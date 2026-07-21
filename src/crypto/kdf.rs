//! Key derivation: Argon2id → HKDF-Extract → HKDF-Expand.
//!
//! All outputs are wrapped in `Zeroizing` (via `SecretBytes`) so they are
//! wiped from memory when dropped. Each `pub(crate) fn` enforces its own
//! preconditions explicitly, and the passphrase-derivation path wipes the
//! Argon2id internal memory blocks (not just the caller's passphrase
//! buffer) before returning — this requires the `zeroize` feature on the
//! `argon2` dependency.

use crate::crypto::constants::*;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Maximum output length of HKDF-Expand for SHA-256 (RFC 5869 §2.3).
/// L ≤ 255 × HashLen = 255 × 32 = 8160 bytes.
pub const HKDF_SHA256_MAX_LEN: usize = 255 * 32;

/// Derive the master key from a passphrase via Argon2id.
///
/// `mem_kib` is the memory cost in KiB. `iters` is the time cost.
/// `par` is the parallelism (lanes).
///
/// Returns a 32-byte master key wrapped in `SecretBytes` (zeroized on drop).
///
/// `mem_kib` is enforced to be at least `KDF_MEM_MIN` (64 MiB) for all
/// production callers. The selftest is the ONLY caller allowed to use a
/// weaker value (1 MiB) — and it does so by calling the argon2 crate
/// directly, bypassing this function. This is acceptable because the
/// selftest's job is to detect a tampered/replaced argon2 crate, not to
/// enforce production KDF parameters.
///
/// All-zero salt is rejected: it indicates a broken RNG or a caller bug
/// and defeats the purpose of salting.
///
/// After Argon2id completes, we wipe the passphrase AND we rely on the
/// argon2 crate's `zeroize` feature to wipe its internal 64-256 MiB of
/// memory blocks. If the feature is missing, this function cannot
/// compensate — keep `argon2/zeroize` enabled in Cargo.toml.
pub(crate) fn argon2id_master(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    iters: u32,
    par: u32,
) -> Result<SecretBytes> {
    // Enforce KDF_MEM_MIN as a hard floor for ALL production callers. A
    // uniform "bad" error is returned for any out-of-range parameter to
    // avoid leaking which constraint was violated: an attacker who plants
    // a crafted .frts file (kdf_mem_kib / iters / par are read from the
    // attacker-controlled slot header) could otherwise probe the bounds
    // by observing parameter-specific error strings, and could
    // distinguish "malformed file" from "wrong passphrase".
    if !(KDF_MEM_MIN..=KDF_MEM_MAX).contains(&mem_kib)
        || !(KDF_ITERS_MIN..=KDF_ITERS_MAX).contains(&iters)
        || !(KDF_PAR_MIN..=KDF_PAR_MAX).contains(&par)
    {
        bail!("bad");
    }

    // Reject all-zero salt. A zero salt would mean two passphrases produce
    // the same master key as a passphrase with no salt, defeating the
    // salt's purpose. This is a defense-in-depth check — `rng::fill`
    // already rejects all-zero output, but a caller bug could pass a zero
    // salt directly. The check uses constant-time OR-accumulation (no
    // early break, no data-dependent branch) so that an observer cannot
    // learn the position of the first non-zero byte via timing.
    let mut salt_acc: u8 = 0;
    for b in salt.iter() {
        salt_acc |= *b;
    }
    if salt_acc == 0 {
        // Uniform error message — do not reveal that the salt was zero
        // (which could leak information to an adversary observing errors).
        bail!("bad");
    }

    let params = Params::new(mem_kib, iters, par, Some(32)).map_err(|_| anyhow::anyhow!("bad"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = SecretBytes::new(32);
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    // The argon2 crate with `zeroize` feature wipes its internal memory
    // blocks (the 64-256 MiB Argon2id scratchpad) when `argon` goes out of
    // scope at the end of this function. We cannot compensate if the
    // feature is missing — it MUST be enabled in Cargo.toml. Do not remove
    // the feature flag without re-auditing this function.
    Ok(out)
}

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
///
/// Returns a 32-byte PRK wrapped in `SecretBytes`.
///
/// `Hkdf::extract` is infallible for SHA-256 because HMAC accepts all
/// input lengths. The output length is asserted to match HashLen (32
/// bytes), catching a future SHA-3 swap that changes the output length.
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<SecretBytes> {
    // The second tuple element of `Hkdf::extract` is `()` (the unit type),
    // not an error marker — `extract` is infallible for SHA-256.
    let (mut prk, _unit) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    // Copy the PRK into a SecretBytes (which is zeroized on drop) BEFORE
    // returning, then wipe the on-stack GenericArray copy. Without this,
    // the 32-byte PRK remains on the stack frame until the caller returns
    // and the stack slot is reused — a stack-scraping adversary could
    // recover it.
    let prk_len = prk.as_slice().len();
    debug_assert_eq!(
        prk_len, 32,
        "HKDF-Extract output length mismatch (expected 32 bytes for SHA-256)"
    );
    if prk_len != 32 {
        prk.as_mut_slice().zeroize();
        bail!("bad");
    }
    let result = SecretBytes::from_slice(prk.as_slice());
    prk.as_mut_slice().zeroize();
    Ok(result)
}

/// HKDF-Expand: derive `length` bytes from PRK with the given `info` label.
///
/// Returns a `SecretBytes` of exactly `length` bytes.
///
/// RFC 5869's hard limit `length ≤ 255 × HashLen` is enforced BEFORE
/// allocating the output buffer. `prk.len() ≥ 32` (HashLen for SHA-256)
/// is checked explicitly. Zero-length expansion is rejected (technically
/// valid per RFC 5869 but indicates a caller bug).
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<SecretBytes> {
    // Reject zero-length expansion. The uniform "bad" error is used to
    // match the codebase's no-oracle policy.
    if length == 0 {
        bail!("bad");
    }
    // Enforce RFC 5869 hard limit.
    if length > HKDF_SHA256_MAX_LEN {
        bail!("bad");
    }
    // Explicit PRK length check.
    if prk.len() < 32 {
        bail!("bad");
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| anyhow::anyhow!("bad"))?;
    // Zeroizing intermediate so it is wiped on drop.
    let mut out: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    let result = SecretBytes::from_slice(&out);
    // Explicit wipe (in addition to Zeroizing's Drop).
    out.iter_mut().for_each(|b| *b = 0);
    Ok(result)
}

/// Derive the per-chunk AEAD key via HKDF-Expand.
///
/// `chunk_index` is bound into the `info` label so each chunk gets a
/// cryptographically independent key.
///
/// The `info` label also includes `chunk_count` in addition to
/// `chunk_index`. This binds each chunk key to the total chunk count, so
/// a chunk key from a 10-chunk file cannot be confused with a chunk key
/// from a 100-chunk file even if the PRK were somehow reused (defense
/// in depth).
pub(crate) fn derive_chunk_key(
    prk: &[u8],
    chunk_index: u32,
    chunk_count: u32,
) -> Result<SecretBytes> {
    let mut info = Vec::with_capacity(HKDF_INFO_CHUNK_PREFIX.len() + 8);
    info.extend_from_slice(HKDF_INFO_CHUNK_PREFIX);
    info.extend_from_slice(&chunk_index.to_be_bytes());
    // Bind chunk_count to the info label (domain separation).
    info.extend_from_slice(&chunk_count.to_be_bytes());
    hkdf_expand(prk, &info, 32)
}

/// Derive the per-chunk AEAD key and return as a fixed `[u8; 32]` for the AEAD API.
///
/// The returned array is wrapped in `Zeroizing` so the caller's stack
/// copy is wiped when it goes out of scope.
pub(crate) fn derive_chunk_key_array(
    prk: &[u8],
    chunk_index: u32,
    chunk_count: u32,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let key = derive_chunk_key(prk, chunk_index, chunk_count)?;
    let mut arr = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&key);
    Ok(arr)
}

/// Derive the commit key via HKDF-Expand.
///
/// The commit key is used to compute the HMAC-SHA256-truncated-128
/// commitment tag that is verified before AEAD decryption.
pub(crate) fn derive_commit_key(prk: &[u8]) -> Result<SecretBytes> {
    hkdf_expand(prk, HKDF_INFO_COMMIT, 32)
}

/// Derive the full slot secret tree:
///   passphrase → Argon2id → master → HKDF-Extract(salt, master) → PRK
///   PRK → HKDF-Expand("commit") → commitKey
///
/// The master key is wiped immediately after HKDF-Extract; only the PRK
/// and commitKey survive, both wrapped in `SecretBytes`.
///
/// The passphrase is consumed (passed by value as `SecretBytes`) and
/// zeroized IMMEDIATELY after Argon2id completes. We also rely on the
/// `argon2` crate's `zeroize` feature to wipe its internal 64-256 MiB
/// scratchpad when the `Argon2` struct drops inside `argon2id_master`. If
/// the feature is ever removed, this function becomes unsafe against
/// memory forensics — see the comment in `argon2id_master`.
pub(crate) fn derive_slot_secrets_from_secret(
    mut passphrase: crate::memory::SecretBytes,
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    iters: u32,
    par: u32,
) -> Result<(SecretBytes, SecretBytes)> {
    // master = Argon2id(passphrase, salt, params)
    let master = argon2id_master(passphrase.as_bytes(), salt, mem_kib, iters, par)?;
    // Wipe the passphrase IMMEDIATELY after Argon2id finishes.
    passphrase.wipe();
    drop(passphrase);
    // PRK = HKDF-Extract(salt, master)
    let prk = hkdf_extract(salt, &master)?;
    // master is no longer needed — drop it (SecretBytes::drop zeroizes)
    drop(master);
    // commitKey = HKDF-Expand(PRK, "fortis-v7/commit", 32)
    let commit_key = derive_commit_key(&prk)?;
    Ok((prk, commit_key))
}
