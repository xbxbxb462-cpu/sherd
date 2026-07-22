//! AES-256-GCM AEAD over the `aes-gcm` crate. Per-chunk keys come from
//! `kdf::derive_chunk_key`. Per-chunk nonce is `base_iv` with the low 4
//! bytes XORed by `chunk_index`; `base_iv` is fresh per slot. Outputs are
//! `Zeroizing`; tag is verified before any plaintext leaves.

use crate::crypto::constants::*;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// Per-chunk 96-bit nonce: `base_iv` XOR `chunk_index` in the low 4 bytes.
/// The XOR is a bijection over u32, so distinct chunk indices yield distinct
/// nonces regardless of `MAX_CHUNKS`. The debug assert is a protocol guard;
/// callers must validate `chunk_count` upstream.
pub(crate) fn chunk_nonce(base_iv: &[u8; IV_LEN], chunk_index: u32) -> [u8; IV_LEN] {
    debug_assert!(chunk_index < MAX_CHUNKS, "chunk_index out of range");
    let mut n = *base_iv;
    let idx_bytes = chunk_index.to_be_bytes();
    n[8] ^= idx_bytes[0];
    n[9] ^= idx_bytes[1];
    n[10] ^= idx_bytes[2];
    n[11] ^= idx_bytes[3];
    n
}

/// Encrypt one chunk. Returns `ct || tag` in `Zeroizing`. `aad` is bound as
/// associated data.
pub(crate) fn encrypt_chunk(
    key: &[u8; 32],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if is_zero_key(key) {
        bail!("bad");
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = iv.into();
    let ct = cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| anyhow::anyhow!("bad"))?;
    Ok(Zeroizing::new(ct))
}

/// Decrypt one chunk. Tag verified before `Ok`. Buffer is `Zeroizing` so
/// failed-decrypt garbage is wiped on drop.
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
    Ok(pt_buf)
}

/// True if all 32 bytes are zero. Constant-time: accumulates OR without
/// short-circuit.
fn is_zero_key(key: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for b in key.iter() {
        acc |= *b;
    }
    acc == 0
}
