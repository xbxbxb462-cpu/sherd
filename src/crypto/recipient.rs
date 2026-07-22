//! File-key wrapping for recipient-based encryption.

use crate::crypto::aead;
use crate::crypto::constants::*;
use crate::crypto::keygen::Identity;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::x25519;
use zeroize::Zeroize;

/// A recipient stanza: ephemeral X25519 public key + wrapped file key.
#[allow(dead_code)]
pub struct Stanza {
    pub ephemeral_pub: [u8; X25519_PUB_LEN],
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Wrap a file key for a recipient public key.
/// Returns a Stanza containing the ephemeral public key and the wrapped file key.
#[allow(dead_code)]
pub fn wrap_file_key(
    file_key: &[u8; FILE_KEY_LEN],
    recipient_pub: &[u8; X25519_PUB_LEN],
) -> Stanza {
    // Ephemeral X25519 keypair.
    let mut ephemeral_priv = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_priv);
    let ephemeral_pub = x25519(ephemeral_priv, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Shared secret via X25519.
    let shared = x25519(ephemeral_priv, *recipient_pub);

    // Derive wrap_key (32 bytes) and wrap_nonce (12 bytes) via HKDF.
    // Salt = ephemeral_pub || recipient_pub (domain separation).
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&ephemeral_pub);
    salt[32..].copy_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared);
    let mut wrap_key = [0u8; 32];
    hk.expand(HKDF_INFO_WRAP_KEY, &mut wrap_key).unwrap();
    let mut wrap_nonce = [0u8; IV_LEN];
    hk.expand(HKDF_INFO_WRAP_NONCE, &mut wrap_nonce).unwrap();

    // Wrap file_key with AES-256-GCM.
    // AAD = ephemeral_pub (binds the stanza to this ephemeral key).
    let ct = aead::encrypt_chunk(&wrap_key, &wrap_nonce, &ephemeral_pub, file_key).unwrap();

    // Zeroize ephemeral private key and shared secret.
    ephemeral_priv.zeroize();
    let mut shared = shared;
    shared.zeroize();
    wrap_key.zeroize();

    let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
    wrapped_key.copy_from_slice(&ct);

    Stanza {
        ephemeral_pub,
        wrapped_key,
    }
}

/// Try to unwrap a file key using an identity (private key).
/// Returns Ok(Some(file_key)) if this identity matches the stanza, Ok(None) if not.
#[allow(dead_code)]
pub fn unwrap_file_key(stanza: &Stanza, identity: &Identity) -> Result<Option<SecretBytes>> {
    // Shared secret via X25519(identity_priv, ephemeral_pub).
    let shared = x25519(
        identity.secret_bytes().try_into().unwrap(),
        stanza.ephemeral_pub,
    );

    // Derive wrap_key and wrap_nonce (same as wrap_file_key).
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&stanza.ephemeral_pub);
    // recipient_pub is identity.public_key() — compute it.
    let recipient_pub = identity.public_key();
    salt[32..].copy_from_slice(&recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared);
    let mut wrap_key = [0u8; 32];
    hk.expand(HKDF_INFO_WRAP_KEY, &mut wrap_key).unwrap();
    let mut wrap_nonce = [0u8; IV_LEN];
    hk.expand(HKDF_INFO_WRAP_NONCE, &mut wrap_nonce).unwrap();

    // Try to decrypt. If GCM tag fails, this identity does not match.
    let result = aead::decrypt_chunk(
        &wrap_key,
        &wrap_nonce,
        &stanza.ephemeral_pub,
        &stanza.wrapped_key,
    );

    // Zeroize secrets.
    let mut shared = shared;
    shared.zeroize();
    wrap_key.zeroize();

    match result {
        Ok(mut pt) => {
            if pt.len() != FILE_KEY_LEN {
                pt.zeroize();
                bail!("bad");
            }
            Ok(Some(SecretBytes::from_slice(&pt)))
        }
        Err(_) => Ok(None),
    }
}

/// Generate a random file key.
#[allow(dead_code)]
pub fn generate_file_key() -> [u8; FILE_KEY_LEN] {
    let mut key = [0u8; FILE_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
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
        let stanza = wrap_file_key(&file_key, &pub_bytes);
        let recovered = unwrap_file_key(&stanza, &id).unwrap().unwrap();
        assert_eq!(recovered.as_slice(), &file_key);
    }

    #[test]
    fn test_wrong_identity_fails() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let pub_bytes = id1.public_key();
        let file_key = generate_file_key();
        let stanza = wrap_file_key(&file_key, &pub_bytes);
        let result = unwrap_file_key(&stanza, &id2).unwrap();
        assert!(result.is_none(), "wrong identity should not unwrap");
    }

    #[test]
    fn test_multiple_recipients() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let id3 = Identity::generate();
        let file_key = generate_file_key();

        let s1 = wrap_file_key(&file_key, &id1.public_key());
        let s2 = wrap_file_key(&file_key, &id2.public_key());
        let s3 = wrap_file_key(&file_key, &id3.public_key());

        // Each identity can unwrap.
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

        // Cross-unwrap fails.
        assert!(unwrap_file_key(&s1, &id2).unwrap().is_none());
        assert!(unwrap_file_key(&s2, &id3).unwrap().is_none());
    }
}
