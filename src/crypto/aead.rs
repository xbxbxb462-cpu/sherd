//! AES-256-GCM AEAD.
//!
//! Uses the `aes-gcm` crate (pure Rust, audited by NCC Group in 2020).
//! Per-chunk keys are derived via HKDF-Expand (see `kdf::derive_chunk_key`).
//! Per-chunk nonces are counter-based: base_iv XOR (0x00...00 || u32be(chunk_index)),
//! where base_iv is a fresh 96-bit random value per slot (generated via
//! `rng::fill`, which routes through `OsRng` and includes the all-zeros
//! health check).
//!
//! All secret outputs (ciphertext, plaintext) are wrapped in
//! `Zeroizing<Vec<u8>>` so they are wiped from memory on drop. Tag
//! verification happens inside `aes-gcm`'s `decrypt_in_place_detached`
//! BEFORE any plaintext is returned to the caller.

use crate::crypto::constants::*;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
// GenericArray is re-exported by the `aead` crate via `aes_gcm::aead`.
// Used for the GCM tag reference in `decrypt_in_place_detached`.
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// Build the per-chunk 96-bit nonce.
///
/// Nonce uniqueness guarantee:
///   nonce = base_iv XOR (0x00...00 || u32be(chunk_index))
///
/// Where `base_iv` is a fresh 96-bit random value generated per slot via
/// `rng::fill` (which routes through `OsRng` and includes the all-zeros
/// health check). The XOR with a unique counter guarantees that every chunk
/// within a file gets a distinct nonce (XOR with a fixed value is a
/// bijection on the 4-byte space, so distinct counters yield distinct
/// nonces). Cross-file nonce collision requires two slots to share the
/// same `base_iv` (96-bit random collision — probability ~2^-48 after
/// 2^24 files, negligible).
///
/// This satisfies the "counter + random per session" nonce uniqueness
/// requirement: the random component is `base_iv` (per-slot, fresh from
/// OsRng), and the counter component is `chunk_index` (per-chunk within
/// the slot). Nonce reuse within a slot is impossible because chunk_index
/// is unique per chunk; nonce reuse across slots is impossible because
/// base_iv is random per slot.
pub(crate) fn chunk_nonce(base_iv: &[u8; IV_LEN], chunk_index: u32) -> [u8; IV_LEN] {
    // Defense-in-depth: assert chunk_index is within the valid range in
    // release builds too. MAX_CHUNKS=256 and chunk_index is u32, so
    // wraparound is impossible, but a stale or corrupted chunk_index
    // must not silently produce a nonce that could collide with another
    // chunk's nonce (which would be catastrophic for AES-GCM). Using
    // `assert!` (not `debug_assert!`) keeps the check in release builds.
    assert!(
        chunk_index < MAX_CHUNKS,
        "chunk_index {} exceeds MAX_CHUNKS {}",
        chunk_index,
        MAX_CHUNKS
    );
    let mut n = *base_iv; // copy all 12 bytes
                          // XOR the chunk index into the last 4 bytes.
    let idx_bytes = chunk_index.to_be_bytes();
    n[8] ^= idx_bytes[0];
    n[9] ^= idx_bytes[1];
    n[10] ^= idx_bytes[2];
    n[11] ^= idx_bytes[3];
    n
}

/// Encrypt one chunk with AES-256-GCM.
///
/// `key` is the per-chunk key (32 bytes). `iv` is the per-chunk nonce
/// (12 bytes). `aad` is bound as authenticated associated data. `pt` is
/// the plaintext chunk.
///
/// Returns `ct || tag` (plaintext_len + 16 bytes) wrapped in `Zeroizing`
/// so it is wiped when the caller drops it.
pub(crate) fn encrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Runtime zero-key check: a zero key indicates a catastrophic HKDF
    // bug. We bail with the uniform "bad" message — never reveal that the
    // key was zero.
    if is_zero_key(key) {
        bail!("bad");
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        // Uniform error message, no internal detail leak.
        .map_err(|_| anyhow::anyhow!("bad"))?;
    // The cipher drops here; if the `zeroize` feature is enabled on the
    // underlying `aes` crate, the AES key schedule is wiped by Drop.
    drop(cipher);
    Ok(Zeroizing::new(ct))
}

/// Decrypt one chunk with AES-256-GCM. Verifies the GCM tag in constant
/// time (via the `subtle` crate, used internally by `aes-gcm`).
///
/// Returns the plaintext chunk, or an error if authentication failed.
///
/// Tag verification order: `decrypt_in_place_detached` first decrypts the
/// ciphertext in-place, then computes the GHASH tag over AAD + ciphertext,
/// then compares the computed tag with the provided tag using
/// `subtle::ConstantTimeEq`, and returns `Err` if the tags do not match.
/// On `Err`, the buffer contains "decrypted garbage" (AES-CTR keystream
/// XOR attacker ciphertext). Because we use a `Zeroizing<Vec<u8>>` buffer,
/// this garbage is wiped from memory when the function returns `Err`. The
/// caller NEVER receives unverified plaintext — the `?` operator propagates
/// the error before the buffer is returned.
///
/// Using `decrypt_in_place_detached` (instead of `Aead::decrypt`) avoids
/// an internal non-`Zeroizing` allocation inside `aes-gcm` that would
/// briefly leak the AES-CTR keystream on a tag mismatch.
pub(crate) fn decrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Runtime zero-key check (defense against HKDF failure).
    if is_zero_key(key) {
        bail!("bad");
    }
    // Reject inputs shorter than TAG_LEN (16 bytes) early. The aes-gcm
    // crate would return an error anyway, but checking early avoids
    // allocating a Zeroizing buffer for an obviously-invalid input and
    // avoids a potential panic in GenericArray::from_slice (which asserts
    // length == 16).
    if ct.len() < TAG_LEN {
        bail!("bad");
    }
    // Split ciphertext into (body, tag). The body is the encrypted
    // plaintext; the tag is the trailing 16-byte GCM authentication tag.
    let (ct_body, tag_bytes) = ct.split_at(ct.len() - TAG_LEN);
    // Allocate a Zeroizing buffer and copy the ciphertext body into it.
    // `decrypt_in_place_detached` will decrypt in-place. On tag mismatch,
    // the buffer contains "decrypted garbage" but is zeroized on drop
    // (because it is wrapped in Zeroizing).
    let mut pt_buf: Zeroizing<Vec<u8>> = Zeroizing::new(ct_body.to_vec());
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    // GenericArray::from_slice asserts length == 16 at runtime. We have
    // already verified ct.len() >= TAG_LEN (16), and tag_bytes is the
    // last 16 bytes of ct, so its length is exactly 16. No panic.
    let tag = GenericArray::from_slice(tag_bytes);
    // decrypt_in_place_detached verifies the tag (constant-time via
    // subtle::ConstantTimeEq) BEFORE returning Ok. On Err, pt_buf
    // contains "decrypted garbage" but is zeroized when pt_buf drops
    // at the end of this function (or when ? propagates the error).
    cipher
        .decrypt_in_place_detached(nonce, aad, pt_buf.as_mut_slice(), tag)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    // The cipher's Drop impl wipes the AES-256 key schedule (176 bytes)
    // IF the `zeroize` feature is enabled on the `aes-gcm` crate.
    drop(cipher);
    // pt_buf now contains the verified plaintext. Returned to caller
    // wrapped in Zeroizing so it is wiped when the caller drops it.
    Ok(pt_buf)
}

/// Encrypt an empty plaintext and return only the 16-byte GCM tag.
///
/// Used as a building block for constant-time dummy-slot encryption in the
/// plausible-deniability path; currently inlined at call sites but retained
/// as a documented helper for future use.
///
/// Explicitly assert the ciphertext length equals `TAG_LEN` before copying
/// into the fixed-size array. Calling `tag.copy_from_slice(&ct)` would panic
/// in debug (or perform an out-of-bounds write in release) if the `aes-gcm`
/// crate ever returned a malformed ciphertext for the empty-input case.
#[allow(dead_code)]
pub(crate) fn encrypt_empty(key: &[u8; 32], iv: &[u8; IV_LEN]) -> Result<[u8; TAG_LEN]> {
    let ct = encrypt_chunk(key, iv, &[], &[])?;
    // Explicit length check before copy. Use the uniform "bad" error
    // message instead of leaking the unexpected length, which could reveal
    // implementation internals.
    if ct.len() != TAG_LEN {
        bail!("bad");
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ct);
    Ok(tag)
}

/// Check if a 32-byte key is all-zeros. Used by `encrypt_chunk` and
/// `decrypt_chunk` to detect catastrophic HKDF failures.
///
/// Constant-time implementation: OR-accumulates all 32 bytes into a single
/// u8 accumulator with no early break. This prevents timing leakage of the
/// position of the first non-zero byte of the key. While a properly
/// functioning HKDF produces uniformly random keys (so the first byte is
/// non-zero with probability 255/256 ≈ 99.6%, making timing ~constant in
/// practice), the constant-time scan is defense-in-depth against a future
/// HKDF bug that produces biased keys (e.g., keys with leading zero bytes).
fn is_zero_key(key: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for b in key.iter() {
        acc |= *b;
    }
    acc == 0
}
