//! Argon2id then HKDF-Extract then HKDF-Expand. Outputs are `SecretBytes`
//! and wiped on drop. Argon2id internal scratch is wiped via the
//! `zeroize` feature on the argon2 crate.

use crate::crypto::constants::*;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Max HKDF-Expand output for SHA-256: 255 * HashLen = 8160 bytes. RFC 5869 §2.3.
pub const HKDF_SHA256_MAX_LEN: usize = 255 * 32;

/// Argon2id master key from a passphrase. Returns 32 bytes in `SecretBytes`.
/// `mem_kib`, `iters`, `par` are the Argon2 costs. All-zero salt is rejected.
pub(crate) fn argon2id_master(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    iters: u32,
    par: u32,
) -> Result<SecretBytes> {
    // Uniform error; do not reveal which check failed.
    if !(KDF_MEM_MIN..=KDF_MEM_MAX).contains(&mem_kib)
        || !(KDF_ITERS_MIN..=KDF_ITERS_MAX).contains(&iters)
        || !(KDF_PAR_MIN..=KDF_PAR_MAX).contains(&par)
    {
        bail!("bad");
    }

    // Reject all-zero salt.
    let mut salt_acc: u8 = 0;
    for b in salt.iter() {
        salt_acc |= *b;
    }
    if salt_acc == 0 {
        // Uniform error; do not reveal the salt was zero.
        bail!("bad");
    }

    let params = Params::new(mem_kib, iters, par, Some(32)).map_err(|_| anyhow::anyhow!("bad"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = SecretBytes::new(32);
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    Ok(out)
}

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM). Returns 32 bytes in
/// `SecretBytes`.
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<SecretBytes> {
    // extract returns (PRK, ()) for SHA-256; no error path.
    let (mut prk, _unit) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    // Wipe the on-stack PRK before returning.
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

/// HKDF-Expand: derive `length` bytes from PRK with `info`. Enforces the
/// RFC 5869 length limit and `prk.len() >= 32`.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<SecretBytes> {
    if length == 0 {
        bail!("bad");
    }
    if length > HKDF_SHA256_MAX_LEN {
        bail!("bad");
    }
    if prk.len() < 32 {
        bail!("bad");
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| anyhow::anyhow!("bad"))?;
    let mut out: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    let result = SecretBytes::from_slice(&out);
    out.iter_mut().for_each(|b| *b = 0);
    Ok(result)
}

/// Per-chunk AEAD key via HKDF-Expand. `info` binds `chunk_index` and
/// `chunk_count`.
pub(crate) fn derive_chunk_key(
    prk: &[u8],
    chunk_index: u32,
    chunk_count: u32,
) -> Result<SecretBytes> {
    let mut info = Vec::with_capacity(HKDF_INFO_CHUNK_PREFIX.len() + 8);
    info.extend_from_slice(HKDF_INFO_CHUNK_PREFIX);
    info.extend_from_slice(&chunk_index.to_be_bytes());
    info.extend_from_slice(&chunk_count.to_be_bytes());
    hkdf_expand(prk, &info, 32)
}

/// Same as `derive_chunk_key` but returns a fixed `[u8; 32]` for the
/// AES-GCM API, wrapped in `Zeroizing`.
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

/// Commit key for the HMAC-SHA256-truncated-128 tag verified before AEAD
/// decryption.
pub(crate) fn derive_commit_key(prk: &[u8]) -> Result<SecretBytes> {
    hkdf_expand(prk, HKDF_INFO_COMMIT, 32)
}

/// Slot secret tree:
///   passphrase -> Argon2id -> master -> HKDF-Extract(salt, master) -> PRK
///   PRK -> HKDF-Expand("commit") -> commitKey
///
/// Passphrase is wiped right after Argon2id. Master key is wiped after
/// HKDF-Extract. Only PRK and commitKey return, both in `SecretBytes`.
pub(crate) fn derive_slot_secrets_from_secret(
    mut passphrase: crate::memory::SecretBytes,
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    iters: u32,
    par: u32,
) -> Result<(SecretBytes, SecretBytes)> {
    let master = argon2id_master(passphrase.as_bytes(), salt, mem_kib, iters, par)?;
    passphrase.wipe();
    drop(passphrase);
    let prk = hkdf_extract(salt, &master)?;
    drop(master);
    let commit_key = derive_commit_key(&prk)?;
    Ok((prk, commit_key))
}
