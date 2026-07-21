//! AES-256-GCM AEAD over the `aes-gcm` crate. Per-chunk keys come from
//! `kdf::derive_chunk_key`. Per-chunk nonce is `base_iv` with the last 4
//! bytes XORed by `chunk_index`; `base_iv` is fresh per slot. Outputs are
//! `Zeroizing`; tag is verified before any plaintext leaves.

use crate::crypto::constants::*;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// Per-chunk 96-bit nonce: `base_iv` XOR `chunk_index` in the low 4 bytes.
/// Distinct chunk_index gives distinct nonce within a slot. Cross-slot
/// collision needs two slots to share `base_iv`, ~2^-48 after 2^24 files.
pub(crate) fn chunk_nonce(base_iv: &[u8; IV_LEN], chunk_index: u32) -> [u8; IV_LEN] {
    // Release-build assert. A stale chunk_index must not silently produce
    // a colliding nonce.
    assert!(
        chunk_index < MAX_CHUNKS,
        "chunk_index {} exceeds MAX_CHUNKS {}",
        chunk_index,
        MAX_CHUNKS
    );
    let mut n = *base_iv;
    // XOR the index into the low 4 bytes.
    let idx_bytes = chunk_index.to_be_bytes();
    n[8] ^= idx_bytes[0];
    n[9] ^= idx_bytes[1];
    n[10] ^= idx_bytes[2];
    n[11] ^= idx_bytes[3];
    n
}

/// Encrypt one chunk. Returns `ct || tag` in `Zeroizing`. `aad` is bound
/// as associated data.
pub(crate) fn encrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Zero key means HKDF broke. Uniform "bad" message; never say why.
    if is_zero_key(key) {
        bail!("bad");
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| anyhow::anyhow!("bad"))?;
    // Wipes the AES key schedule on drop if the `zeroize` feature is on.
    drop(cipher);
    Ok(Zeroizing::new(ct))
}

/// Decrypt one chunk. Tag verified via `subtle::ConstantTimeEq` inside
/// `aes-gcm` before `Ok`. On `Err` the buffer holds AES-CTR garbage but is
/// `Zeroizing` so it is wiped on drop; the caller never sees unverified
/// plaintext. `decrypt_in_place_detached` is used over `Aead::decrypt` to
/// avoid an internal non-`Zeroizing` allocation.
pub(crate) fn decrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if is_zero_key(key) {
        bail!("bad");
    }
    // Reject short input early so GenericArray::from_slice does not panic.
    if ct.len() < TAG_LEN {
        bail!("bad");
    }
    let (ct_body, tag_bytes) = ct.split_at(ct.len() - TAG_LEN);
    let mut pt_buf: Zeroizing<Vec<u8>> = Zeroizing::new(ct_body.to_vec());
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    let tag = GenericArray::from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(nonce, aad, pt_buf.as_mut_slice(), tag)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    // Wipes the AES key schedule on drop if `zeroize` is enabled.
    drop(cipher);
    Ok(pt_buf)
}

/// Encrypt empty plaintext and return the 16-byte GCM tag. Helper for the
/// dummy-slot path; inlined at call sites today but kept for reuse. The
/// length check guards against a malformed `aes-gcm` return.
#[allow(dead_code)]
pub(crate) fn encrypt_empty(key: &[u8; 32], iv: &[u8; IV_LEN]) -> Result<[u8; TAG_LEN]> {
    let ct = encrypt_chunk(key, iv, &[], &[])?;
    if ct.len() != TAG_LEN {
        bail!("bad");
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ct);
    Ok(tag)
}

/// True if all 32 bytes are zero. Used by `encrypt_chunk` and
/// `decrypt_chunk` to catch a broken HKDF. Constant-time OR scan.
fn is_zero_key(key: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for b in key.iter() {
        acc |= *b;
    }
    acc == 0
}
