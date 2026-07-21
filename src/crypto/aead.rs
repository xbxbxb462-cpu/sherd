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
pub(crate) fn chunk_nonce(base_iv: &[u8; IV_LEN], chunk_index: u32) -> [u8; IV_LEN] {
    assert!(
        chunk_index < MAX_CHUNKS,
        "chunk_index {} exceeds MAX_CHUNKS {}",
        chunk_index,
        MAX_CHUNKS
    );
    let mut n = *base_iv;
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
    // Zero key means HKDF broke. Uniform error.
    if is_zero_key(key) {
        bail!("bad");
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| anyhow::anyhow!("bad"))?;
    drop(cipher);
    Ok(Zeroizing::new(ct))
}

/// Decrypt one chunk. Tag verified via `subtle::ConstantTimeEq` before
/// `Ok`. Buffer is `Zeroizing` so failed-decrypt garbage is wiped on drop.
pub(crate) fn decrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if is_zero_key(key) {
        bail!("bad");
    }
    // Reject short input to avoid a panic in GenericArray::from_slice.
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
    drop(cipher);
    Ok(pt_buf)
}

/// Encrypt empty plaintext and return the 16-byte GCM tag.
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

/// True if all 32 bytes are zero.
fn is_zero_key(key: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for b in key.iter() {
        acc |= *b;
    }
    acc == 0
}
