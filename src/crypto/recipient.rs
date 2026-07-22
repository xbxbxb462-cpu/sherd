//! File-key wrapping for recipient-based encryption.

use crate::crypto::aead;
use crate::crypto::constants::*;
use crate::crypto::keygen::Identity;
use crate::crypto::rng;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::x25519;
use zeroize::Zeroizing;

/// A recipient stanza: ephemeral X25519 public key plus wrapped file key.
#[allow(dead_code)]
pub struct Stanza {
    pub ephemeral_pub: [u8; X25519_PUB_LEN],
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Wrap a file key for a recipient public key. Returns a `Stanza` containing
/// the ephemeral public key and the wrapped file key.
#[allow(dead_code)]
pub fn wrap_file_key(
    file_key: &[u8; FILE_KEY_LEN],
    recipient_pub: &[u8; X25519_PUB_LEN],
) -> Result<Stanza> {
    // ephemeral_priv and shared are Zeroizing so any early return wipes them.
    let mut ephemeral_priv = Zeroizing::new([0u8; 32]);
    rng::fill(&mut *ephemeral_priv);
    let ephemeral_pub = x25519(*ephemeral_priv, x25519_dalek::X25519_BASEPOINT_BYTES);

    let shared = Zeroizing::new(x25519(*ephemeral_priv, *recipient_pub));
    if is_all_zero(&*shared) {
        bail!("bad");
    }

    // Salt binds both public keys into the KDF.
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&ephemeral_pub);
    salt[32..].copy_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &*shared);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_WRAP_KEY, &mut *wrap_key)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    let mut wrap_nonce = [0u8; IV_LEN];
    hk.expand(HKDF_INFO_WRAP_NONCE, &mut wrap_nonce)
        .map_err(|_| anyhow::anyhow!("bad"))?;

    // AAD binds the stanza to this ephemeral key.
    let ct = aead::encrypt_chunk(&wrap_key, &wrap_nonce, &ephemeral_pub, file_key)?;

    let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
    wrapped_key.copy_from_slice(&ct);

    Ok(Stanza {
        ephemeral_pub,
        wrapped_key,
    })
}

/// Try to unwrap a file key using an identity. Returns `Ok(Some(file_key))`
/// if the identity matches the stanza, `Ok(None)` otherwise.
#[allow(dead_code)]
pub fn unwrap_file_key(stanza: &Stanza, identity: &Identity) -> Result<Option<SecretBytes>> {
    let secret_bytes: [u8; 32] = identity
        .secret_bytes()
        .try_into()
        .expect("identity secret is 32 bytes by construction");
    let shared = Zeroizing::new(x25519(secret_bytes, stanza.ephemeral_pub));
    if is_all_zero(&*shared) {
        return Ok(None);
    }

    let recipient_pub = identity.public_key();

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&stanza.ephemeral_pub);
    salt[32..].copy_from_slice(&recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &*shared);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_WRAP_KEY, &mut *wrap_key)
        .map_err(|_| anyhow::anyhow!("bad"))?;
    let mut wrap_nonce = [0u8; IV_LEN];
    hk.expand(HKDF_INFO_WRAP_NONCE, &mut wrap_nonce)
        .map_err(|_| anyhow::anyhow!("bad"))?;

    let result = aead::decrypt_chunk(
        &wrap_key,
        &wrap_nonce,
        &stanza.ephemeral_pub,
        &stanza.wrapped_key,
    );

    match result {
        Ok(pt) => {
            if pt.len() != FILE_KEY_LEN {
                bail!("bad");
            }
            Ok(Some(SecretBytes::from_slice(&pt)))
        }
        Err(_) => Ok(None),
    }
}

/// Generate a random file key via the health-checked OS RNG.
#[allow(dead_code)]
pub fn generate_file_key() -> [u8; FILE_KEY_LEN] {
    let mut key = [0u8; FILE_KEY_LEN];
    rng::fill(&mut key);
    key
}

/// True if all bytes are zero. Constant-time: accumulates OR without
/// short-circuit.
fn is_all_zero(buf: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for b in buf.iter() {
        acc |= *b;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen::Identity;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let id = Identity::generate();
        let pub_bytes = id.public_key();
        let file_key = generate_file_key();
        let stanza = wrap_file_key(&file_key, &pub_bytes).unwrap();
        let recovered = unwrap_file_key(&stanza, &id).unwrap().unwrap();
        assert_eq!(recovered.as_slice(), &file_key);
    }

    #[test]
    fn test_wrong_identity_fails() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let pub_bytes = id1.public_key();
        let file_key = generate_file_key();
        let stanza = wrap_file_key(&file_key, &pub_bytes).unwrap();
        let result = unwrap_file_key(&stanza, &id2).unwrap();
        assert!(result.is_none(), "wrong identity should not unwrap");
    }

    #[test]
    fn test_multiple_recipients() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let id3 = Identity::generate();
        let file_key = generate_file_key();

        let s1 = wrap_file_key(&file_key, &id1.public_key()).unwrap();
        let s2 = wrap_file_key(&file_key, &id2.public_key()).unwrap();
        let s3 = wrap_file_key(&file_key, &id3.public_key()).unwrap();

        assert_eq!(
            unwrap_file_key(&s1, &id1).unwrap().unwrap().as_slice(),
            &file_key
        );
        assert_eq!(
            unwrap_file_key(&s2, &id2).unwrap().unwrap().as_slice(),
            &file_key
        );
        assert_eq!(
            unwrap_file_key(&s3, &id3).unwrap().unwrap().as_slice(),
            &file_key
        );

        assert!(unwrap_file_key(&s1, &id2).unwrap().is_none());
        assert!(unwrap_file_key(&s2, &id3).unwrap().is_none());
    }

    #[test]
    fn test_reject_all_zero_recipient() {
        let file_key = generate_file_key();
        let zero_pub = [0u8; X25519_PUB_LEN];
        assert!(wrap_file_key(&file_key, &zero_pub).is_err());
    }
}
