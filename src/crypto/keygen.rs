//! X25519 keypair generation and encoding.

use crate::crypto::constants::{IDENTITY_PREFIX, RECIPIENT_PREFIX, X25519_PUB_LEN};
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// A private X25519 identity key. Wrapped in SecretBytes so it is wiped on drop.
#[allow(dead_code)]
pub struct Identity {
    secret: SecretBytes, // 32 bytes
}

impl Identity {
    /// Generate a new random identity.
    #[allow(dead_code)]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let bytes = secret.to_bytes();
        let sb = SecretBytes::from_slice(&bytes);
        // StaticSecret already zeroes on drop, but we also hold the raw bytes.
        drop(secret);
        Self { secret: sb }
    }

    /// Get the 32-byte private key.
    #[allow(dead_code)]
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Compute the corresponding public key.
    #[allow(dead_code)]
    pub fn public_key(&self) -> [u8; X25519_PUB_LEN] {
        let secret_bytes: [u8; 32] = self.secret.as_slice().try_into().unwrap();
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        public.to_bytes()
    }

    /// Encode as identity file string: "SHERD-SECRET-KEY-1<base64>"
    #[allow(dead_code)]
    pub fn to_identity_string(&self) -> String {
        let b64 = Base64::encode_string(self.secret.as_slice());
        format!("{}{}", IDENTITY_PREFIX, b64)
    }

    /// Encode the public key as recipient string: "sherd1<base64>"
    #[allow(dead_code)]
    pub fn to_recipient_string(&self) -> String {
        let pub_bytes = self.public_key();
        let b64 = Base64::encode_string(&pub_bytes);
        format!("{}{}", RECIPIENT_PREFIX, b64)
    }
}

/// Parse an identity string ("SHERD-SECRET-KEY-1<base64>") into an Identity.
#[allow(dead_code)]
pub fn parse_identity(s: &str) -> Result<Identity> {
    let s = s.trim();
    if !s.starts_with(IDENTITY_PREFIX) {
        bail!("bad");
    }
    let b64 = &s[IDENTITY_PREFIX.len()..];
    let bytes = Base64::decode_vec(b64).map_err(|_| anyhow::anyhow!("bad"))?;
    if bytes.len() != 32 {
        bail!("bad");
    }
    let id = Identity {
        secret: SecretBytes::from_slice(&bytes),
    };
    Ok(id)
}

/// Parse a recipient string ("sherd1<base64>") into a 32-byte public key.
#[allow(dead_code)]
pub fn parse_recipient(s: &str) -> Result<[u8; X25519_PUB_LEN]> {
    let s = s.trim();
    if !s.starts_with(RECIPIENT_PREFIX) {
        bail!("bad");
    }
    let b64 = &s[RECIPIENT_PREFIX.len()..];
    let mut bytes = Base64::decode_vec(b64).map_err(|_| anyhow::anyhow!("bad"))?;
    if bytes.len() != 32 {
        bytes.zeroize();
        bail!("bad");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

/// Parse an identity FILE (multi-line text with comments).
/// Lines starting with '#' are comments. One line is the SHERD-SECRET-KEY-1...
#[allow(dead_code)]
pub fn parse_identity_file(content: &str) -> Result<Vec<Identity>> {
    let mut identities = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(IDENTITY_PREFIX) {
            identities.push(parse_identity(line)?);
        }
    }
    if identities.is_empty() {
        bail!("bad");
    }
    Ok(identities)
}

/// Parse a recipient FILE (multi-line, one recipient per line, # comments).
#[allow(dead_code)]
pub fn parse_recipient_file(content: &str) -> Result<Vec<[u8; X25519_PUB_LEN]>> {
    let mut recipients = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        recipients.push(parse_recipient(line)?);
    }
    if recipients.is_empty() {
        bail!("bad");
    }
    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let id = Identity::generate();
        let id_str = id.to_identity_string();
        let id2 = parse_identity(&id_str).unwrap();
        assert_eq!(id.secret_bytes(), id2.secret_bytes());
    }

    #[test]
    fn test_recipient_roundtrip() {
        let id = Identity::generate();
        let rec = id.to_recipient_string();
        let pub_bytes = parse_recipient(&rec).unwrap();
        assert_eq!(pub_bytes, id.public_key());
    }

    #[test]
    fn test_identity_file_parse() {
        let id = Identity::generate();
        let content = format!(
            "# created: 2026-07-21\n# public key: {}\n{}\n",
            id.to_recipient_string(),
            id.to_identity_string()
        );
        let ids = parse_identity_file(&content).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].secret_bytes(), id.secret_bytes());
    }

    #[test]
    fn test_dh_symmetry() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();
        let alice_dh = x25519_dalek::x25519(alice.secret_bytes().try_into().unwrap(), bob_pub);
        let bob_dh = x25519_dalek::x25519(bob.secret_bytes().try_into().unwrap(), alice_pub);
        assert_eq!(alice_dh, bob_dh);
    }
}
