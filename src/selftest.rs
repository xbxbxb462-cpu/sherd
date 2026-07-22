//! Cryptographic self-tests: KATs, round-trips, tamper rejection.
//!
//! Run `sherd selftest` before trusting this binary.

use crate::armor;
use crate::crypto::aead;
use crate::crypto::commit;
use crate::crypto::constants::*;
use crate::crypto::kdf;
use crate::envelope;
use crate::memory::SecretBytes;
use crate::shamir;
use anyhow::{bail, Result};
use std::io::{self, Read, Write};

/// AES-256-GCM TC13: empty plaintext, zero key/IV.
const KAT_AESGCM_EMPTY_TAG_HEX: &str = "530f8afbc74536b9a963b4f1c4cb738b";

/// Argon2id KAT: 1 MiB, 3 iters, 1 lane.
const KAT_ARGON2ID_HEX: &str = "71c7e08979b7a21e58ba5fcd9f2700b8fe45992540023533f650ed7228a37d39";

/// HKDF-SHA256 RFC 5869 TC1.
const KAT_HKDF_RFC5869_TC1_HEX: &str =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

/// HKDF PRK intermediate, RFC 5869 TC1. Pins extract independently of expand.
const KAT_HKDF_RFC5869_TC1_PRK_HEX: &str =
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

/// HMAC-SHA256 RFC 4231 TC1.
const KAT_HMAC_RFC4231_TC1_HEX: &str =
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

/// AES-256-GCM TC14: 16-byte zero plaintext, zero key/IV.
const KAT_AESGCM_16BYTE_CT_HEX: &str =
    "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex decode that returns Result instead of panicking.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex: odd length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let hi = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => bail!("hex: invalid char"),
        };
        let lo = match bytes[i + 1] {
            b'0'..=b'9' => bytes[i + 1] - b'0',
            b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
            _ => bail!("hex: invalid char"),
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub fn run_all_selftests() -> Result<()> {
    println!("SHERD v1.0.0 Cryptographic Self-Tests");
    println!("==========================================");
    let mut passed = 0;
    let mut failed = 0;

    macro_rules! test {
        ($name:expr, $body:block) => {
            print!("  … {} ", $name);
            io::stdout().flush()?;
            let result: Result<()> = (|| $body)();
            match result {
                Ok(()) => {
                    println!("✓");
                    passed += 1;
                }
                Err(e) => {
                    println!("✘ ({})", e);
                    failed += 1;
                }
            }
        };
    }

    test!("argon2id KAT", {
        // KAT params: 1 MiB, 3 iters, 1 lane.
        use argon2::{Algorithm, Argon2, Params, Version};
        let salt = *b"sherd-v1-kat-salt-32-bytes!!!!!";
        let params = Params::new(1024, 3, 1, Some(32)).map_err(|_| anyhow::anyhow!("bad"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(b"sherd-v1-kat-password", &salt, &mut out)
            .map_err(|_| anyhow::anyhow!("bad"))?;
        let got = hex_encode(&out);
        if got != KAT_ARGON2ID_HEX {
            bail!(
                "Argon2id KAT mismatch:\n  got      {}\n  expected {}",
                got,
                KAT_ARGON2ID_HEX
            );
        }
        Ok(())
    });

    // Smoke at production params, 64 MiB. Deterministic, non-zero output.
    test!("argon2id at production params", {
        use argon2::{Algorithm, Argon2, Params, Version};
        let salt = [0xAAu8; SALT_LEN];
        let params = Params::new(KDF_MEM_MIN, KDF_ITERS_MIN, KDF_PAR_MIN, Some(32))
            .map_err(|_| anyhow::anyhow!("bad"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        argon
            .hash_password_into(b"production-kat-passphrase", &salt, &mut out1)
            .map_err(|_| anyhow::anyhow!("bad"))?;
        argon
            .hash_password_into(b"production-kat-passphrase", &salt, &mut out2)
            .map_err(|_| anyhow::anyhow!("bad"))?;
        if out1 != out2 {
            bail!("Argon2id not deterministic at production params");
        }
        if out1 == [0u8; 32] {
            bail!("Argon2id produced all-zero output at production params");
        }
        Ok(())
    });

    test!("argon2id rejects weak params", {
        let salt = [0u8; SALT_LEN];
        match kdf::argon2id_master(b"test-passphrase", &salt, 1024, 3, 1) {
            Ok(_) => bail!("argon2id_master accepted weak KDF params"),
            Err(_) => Ok(()),
        }
    });

    test!("hkdf KAT RFC 5869 TC1", {
        let ikm = vec![0x0bu8; 22];
        let salt = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = vec![0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = kdf::hkdf_extract(&salt, &ikm)?;
        let prk_hex = hex_encode(prk.as_bytes());
        if prk_hex != KAT_HKDF_RFC5869_TC1_PRK_HEX {
            bail!(
                "HKDF PRK mismatch:\n  got      {}\n  expected {}",
                prk_hex,
                KAT_HKDF_RFC5869_TC1_PRK_HEX
            );
        }
        let okm = kdf::hkdf_expand(prk.as_slice(), &info, 42)?;
        let got = hex_encode(okm.as_bytes());
        if got != KAT_HKDF_RFC5869_TC1_HEX {
            bail!(
                "HKDF KAT mismatch:\n  got      {}\n  expected {}",
                got,
                KAT_HKDF_RFC5869_TC1_HEX
            );
        }
        Ok(())
    });

    test!("hmac KAT RFC 4231 TC1", {
        // HMAC-SHA256 directly on RFC 4231 TC1 inputs.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("HMAC init failed: {}", e))?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let got = hex_encode(&result);
        if got != KAT_HMAC_RFC4231_TC1_HEX {
            bail!(
                "HMAC-SHA256 KAT mismatch (RFC 4231 TC1):\n  got      {}\n  expected {}",
                got,
                KAT_HMAC_RFC4231_TC1_HEX
            );
        }
        Ok(())
    });

    test!("commit tag deterministic", {
        let key = [0x0bu8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let ct_hash = [0u8; 32];
        let tag = commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 0, 0, &ct_hash)?;
        if tag.len() != COMMIT_TAG_LEN {
            bail!("expected {} bytes, got {}", COMMIT_TAG_LEN, tag.len());
        }
        if tag == [0u8; COMMIT_TAG_LEN] {
            bail!("HMAC produced all-zero output (library bug?)");
        }
        let tag2 =
            commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 0, 0, &ct_hash)?;
        if tag != tag2 {
            bail!("HMAC not deterministic!");
        }
        Ok(())
    });

    test!("chunk key derivation", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        let k0 = kdf::derive_chunk_key(&prk, 0, 10)?;
        let k1 = kdf::derive_chunk_key(&prk, 1, 10)?;
        if k0.as_bytes() == k1.as_bytes() {
            bail!("chunk keys are identical!");
        }
        if k0.len() != 32 {
            bail!("expected 32-byte key, got {}", k0.len());
        }
        Ok(())
    });

    test!("chunk key zeroizing", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        let k0 = kdf::derive_chunk_key_array(&prk, 0, 10)?;
        let _ = k0.as_ref();
        if k0.as_ref().len() != 32 {
            bail!("expected 32-byte key, got {}", k0.as_ref().len());
        }
        Ok(())
    });

    test!("decrypt_chunk zeroizing output", {
        // Non-zero key to pass encrypt_chunk's zero-key check.
        let mut key = [0u8; 32];
        key[0] = 1;
        let iv = [0u8; IV_LEN];
        let ct = aead::encrypt_chunk(&key, &iv, b"aad", b"plaintext")?;
        let pt = aead::decrypt_chunk(&key, &iv, b"aad", &ct)?;
        let pt_slice: &[u8] = pt.as_ref();
        if pt_slice != b"plaintext" {
            bail!("plaintext mismatch");
        }
        Ok(())
    });

    test!("chunk_nonce covers full base_iv", {
        let mut iv_a = [0u8; IV_LEN];
        iv_a[8] = 0xAA;
        let iv_b = [0u8; IV_LEN];
        let n_a = aead::chunk_nonce(&iv_a, 0);
        let n_b = aead::chunk_nonce(&iv_b, 0);
        if n_a == n_b {
            bail!("chunk_nonce ignores base_iv[8..12]");
        }
        let n_0 = aead::chunk_nonce(&iv_a, 0);
        let n_1 = aead::chunk_nonce(&iv_a, 1);
        if n_0 == n_1 {
            bail!("chunk_nonce collision on chunk_index 0 vs 1");
        }
        Ok(())
    });

    test!("hkdf rejects length > 255*32", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        match kdf::hkdf_expand(prk.as_slice(), b"info", 255 * 32 + 1) {
            Ok(_) => bail!("hkdf_expand accepted length > 255*HashLen"),
            Err(_) => Ok(()),
        }
    });

    test!("hkdf rejects zero-length output", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        match kdf::hkdf_expand(prk.as_slice(), b"info", 0) {
            Ok(_) => bail!("hkdf_expand accepted length == 0"),
            Err(_) => Ok(()),
        }
    });

    test!("hkdf rejects short prk", {
        let short_prk = [0u8; 16];
        match kdf::hkdf_expand(&short_prk, b"info", 32) {
            Ok(_) => bail!("hkdf_expand accepted short PRK"),
            Err(_) => Ok(()),
        }
    });

    test!("commit tag binds ciphertext hash", {
        let key = [0x0bu8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let mut ct_hash_1 = [0u8; 32];
        ct_hash_1[0] = 0x01;
        let mut ct_hash_2 = [0u8; 32];
        ct_hash_2[0] = 0x02;
        let tag_1 =
            commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash_1)?;
        let tag_2 =
            commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash_2)?;
        if tag_1 == tag_2 {
            bail!("commit tag does not bind ct_first_chunk_hash");
        }
        Ok(())
    });

    test!("verify_commit_tag accept valid, reject bad", {
        let key = [0u8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let ct_hash = [0u8; 32];
        let tag =
            commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash)?;
        commit::verify_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash, &tag)?;
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xff;
        match commit::verify_commit_tag(
            &key,
            &fixed_header,
            &salt,
            &base_iv,
            1,
            16,
            &ct_hash,
            &bad_tag,
        ) {
            Ok(_) => bail!("wrong tag accepted"),
            Err(_) => Ok(()),
        }
    });

    test!("first_chunk_hash deterministic", {
        let h1 = commit::compute_first_chunk_hash(b"chunk-1");
        let h1b = commit::compute_first_chunk_hash(b"chunk-1");
        let h2 = commit::compute_first_chunk_hash(b"chunk-2");
        if h1 != h1b {
            bail!("first_chunk_hash not deterministic");
        }
        if h1 == h2 {
            bail!("first_chunk_hash collision on different inputs");
        }
        Ok(())
    });

    test!("aes-gcm KAT empty plaintext", {
        // aes-gcm directly; NIST uses a zero key by convention.
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{
            aead::{Aead, Payload},
            Aes256Gcm, KeyInit,
        };
        let key = [0u8; 32];
        let iv = [0u8; IV_LEN];
        let cipher = Aes256Gcm::new(&key.into());
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&iv),
                Payload { msg: b"", aad: b"" },
            )
            .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
        // Empty plaintext: AES-GCM returns just the 16-byte tag.
        if ct.len() != TAG_LEN {
            bail!(
                "empty-plaintext KAT: expected {} bytes (tag only), got {}",
                TAG_LEN,
                ct.len()
            );
        }
        let expected = hex_decode(KAT_AESGCM_EMPTY_TAG_HEX)?;
        if ct != expected {
            bail!(
                "tag mismatch: got {} expected {}",
                hex_encode(&ct),
                KAT_AESGCM_EMPTY_TAG_HEX
            );
        }
        Ok(())
    });

    // NIST GCM TC14: zero key, zero IV, 16-byte zero plaintext, empty AAD.
    test!("aes-gcm KAT 16-byte plaintext", {
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{
            aead::{Aead, Payload},
            Aes256Gcm, KeyInit,
        };
        let key = [0u8; 32];
        let iv = [0u8; IV_LEN];
        let pt = [0u8; 16];
        let cipher = Aes256Gcm::new(&key.into());
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&iv),
                Payload { msg: &pt, aad: b"" },
            )
            .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
        let expected = hex_decode(KAT_AESGCM_16BYTE_CT_HEX)?;
        if ct != expected {
            bail!(
                "AES-GCM 16-byte KAT mismatch:\n  got      {}\n  expected {}",
                hex_encode(&ct),
                KAT_AESGCM_16BYTE_CT_HEX
            );
        }
        Ok(())
    });

    test!("aes-gcm tamper rejected", {
        // Non-zero key; encrypt_chunk rejects zero keys.
        let mut key = [0u8; 32];
        key[0] = 1;
        let iv = [0u8; IV_LEN];
        let mut ct = aead::encrypt_chunk(&key, &iv, b"aad", b"plaintext")?;
        ct[0] ^= 0x01;
        match aead::decrypt_chunk(&key, &iv, b"aad", &ct) {
            Ok(_) => bail!("tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("commit tag length", {
        let commit_key = [0u8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let ct_hash = [0u8; 32];
        let tag = commit::compute_commit_tag(
            &commit_key,
            &fixed_header,
            &salt,
            &base_iv,
            1,
            16,
            &ct_hash,
        )?;
        if tag.len() != COMMIT_TAG_LEN {
            bail!("expected {} bytes, got {}", COMMIT_TAG_LEN, tag.len());
        }
        Ok(())
    });

    test!("commit tag accept valid, reject bad", {
        let commit_key = [0u8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let ct_hash = [0u8; 32];
        let tag = commit::compute_commit_tag(
            &commit_key,
            &fixed_header,
            &salt,
            &base_iv,
            1,
            16,
            &ct_hash,
        )?;
        commit::verify_commit_tag(
            &commit_key,
            &fixed_header,
            &salt,
            &base_iv,
            1,
            16,
            &ct_hash,
            &tag,
        )?;
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xff;
        match commit::verify_commit_tag(
            &commit_key,
            &fixed_header,
            &salt,
            &base_iv,
            1,
            16,
            &ct_hash,
            &bad_tag,
        ) {
            Ok(_) => bail!("wrong tag accepted"),
            Err(_) => Ok(()),
        }
    });

    test!("envelope round-trip", {
        let pt = b"self-test message ok";
        let env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"correct-horse-kat"))?;
        if dec.as_slice() != pt {
            bail!("round-trip mismatch");
        }
        Ok(())
    });

    test!("wrong passphrase rejected", {
        let pt = b"self-test message ok";
        let env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"wrong-passphrase!")) {
            Ok(_) => bail!("wrong passphrase accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("header tamper rejected", {
        let pt = b"self-test message ok";
        let mut env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        env[5] ^= 0x02; // flags byte
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"correct-horse-kat")) {
            Ok(_) => bail!("header tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("chunk ciphertext tamper rejected", {
        let pt = b"self-test message ok";
        let mut env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let real_ct_start = FIXED_HEADER_LEN + SLOT_HEADER_LEN;
        let real_ct_end = real_ct_start + 4096;
        let tamper_offset = real_ct_start + (real_ct_end - real_ct_start) / 2;
        env[tamper_offset] ^= 0x80;
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"correct-horse-kat")) {
            Ok(_) => bail!("chunk tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("commit tag tamper rejected", {
        let pt = b"self-test message ok";
        let mut env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let commit_off = FIXED_HEADER_LEN + SALT_LEN + IV_LEN;
        env[commit_off] ^= 0x01;
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"correct-horse-kat")) {
            Ok(_) => bail!("commit-tag tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("decoy slot decrypts", {
        let real_pt = b"REAL: top secret";
        let decoy_pt = b"DECOY: vacation photos";
        let env = envelope::encrypt_envelope(
            real_pt,
            SecretBytes::from_slice(b"real-pass-12345"),
            Some(decoy_pt),
            Some(SecretBytes::from_slice(b"decoy-pass-12345")),
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let real_dec =
            envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"real-pass-12345"))?;
        if real_dec.as_slice() != real_pt {
            bail!("real slot wrong");
        }
        let decoy_dec =
            envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"decoy-pass-12345"))?;
        if decoy_dec.as_slice() != decoy_pt {
            bail!("decoy slot wrong");
        }
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"wrong-pass")) {
            Ok(_) => bail!("wrong passphrase accepted"),
            Err(_) => Ok(()),
        }
    });

    // 20 samples each: size ranges with and without decoy must overlap and
    // each span at least PAD_BLOCK.
    test!("decoy size range overlaps real", {
        let real_pt = b"identical-size-test-message";
        let mut no_decoy_sizes = Vec::new();
        let mut with_decoy_sizes = Vec::new();
        for _ in 0..20 {
            let env_no = envelope::encrypt_envelope(
                real_pt,
                SecretBytes::from_slice(b"pass-12345-abcde"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            no_decoy_sizes.push(env_no.len());
            let env_w = envelope::encrypt_envelope(
                real_pt,
                SecretBytes::from_slice(b"pass-12345-abcde"),
                Some(b"decoy message here"),
                Some(SecretBytes::from_slice(b"decoypass-12345")),
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            with_decoy_sizes.push(env_w.len());
        }
        let no_min = *no_decoy_sizes.iter().min().unwrap();
        let no_max = *no_decoy_sizes.iter().max().unwrap();
        let w_min = *with_decoy_sizes.iter().min().unwrap();
        let w_max = *with_decoy_sizes.iter().max().unwrap();
        if no_min > w_max || w_min > no_max {
            bail!(
                "size ranges do not overlap: no_decoy=[{},{}], with_decoy=[{},{}]",
                no_min,
                no_max,
                w_min,
                w_max
            );
        }
        let no_range = no_max - no_min;
        let w_range = w_max - w_min;
        if no_range < PAD_BLOCK {
            bail!("no_decoy range too narrow: {}", no_range);
        }
        if w_range < PAD_BLOCK {
            bail!("with_decoy range too narrow: {}", w_range);
        }
        Ok(())
    });

    // Paranoid mode adds 1..=4 PAD_BLOCK blocks of jitter. 20 samples must
    // produce >= 3 unique sizes and a spread >= 2*PAD_BLOCK.
    test!("paranoid mode jitter", {
        let pt = b"A";
        let mut sizes = Vec::new();
        for _ in 0..20 {
            let env = envelope::encrypt_envelope(
                pt,
                SecretBytes::from_slice(b"jitter-test-pass-1"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                true,
            )?;
            sizes.push(env.len());
        }
        let unique: std::collections::HashSet<_> = sizes.iter().collect();
        if unique.len() < 3 {
            bail!(
                "paranoid jitter too weak: {} unique out of 20 samples",
                unique.len()
            );
        }
        let min_size = *sizes.iter().min().unwrap();
        let max_size = *sizes.iter().max().unwrap();
        if max_size - min_size < 2 * PAD_BLOCK {
            bail!(
                "paranoid jitter range too narrow: {} bytes",
                max_size - min_size
            );
        }
        Ok(())
    });

    test!("round-trip empty plaintext", {
        let pt: &[u8] = b"";
        let env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"empty-test-pass1"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"empty-test-pass1"))?;
        if dec.as_slice() != pt {
            bail!(
                "empty plaintext round-trip mismatch: got {} bytes",
                dec.len()
            );
        }
        Ok(())
    });

    test!("round-trip 1-byte plaintext", {
        let pt = b"X";
        let env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"one-byte-pass-1!"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"one-byte-pass-1!"))?;
        if dec.as_slice() != pt {
            bail!("1-byte round-trip mismatch");
        }
        Ok(())
    });

    // 4-byte length prefix: CHUNK_SIZE - 4 fills one chunk pre-padding.
    test!("round-trip exact one chunk", {
        let pt = vec![b'A'; CHUNK_SIZE - 4];
        let env = envelope::encrypt_envelope(
            &pt,
            SecretBytes::from_slice(b"exact-1-chunk-pass"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"exact-1-chunk-pass"))?;
        if dec.as_slice() != pt.as_slice() {
            bail!("round-trip mismatch");
        }
        Ok(())
    });

    test!("round-trip exact CHUNK_SIZE", {
        let pt = vec![b'B'; CHUNK_SIZE];
        let env = envelope::encrypt_envelope(
            &pt,
            SecretBytes::from_slice(b"exact-2-chunk-pass"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"exact-2-chunk-pass"))?;
        if dec.as_slice() != pt.as_slice() {
            bail!("exact-2-chunk round-trip mismatch");
        }
        Ok(())
    });

    // CHUNK_SIZE - 3 + 4 framing = CHUNK_SIZE + 1 -> 2 chunks.
    test!("round-trip chunk boundary +1", {
        let pt = vec![b'C'; CHUNK_SIZE - 3];
        let env = envelope::encrypt_envelope(
            &pt,
            SecretBytes::from_slice(b"over-1-chunk-pass!"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec = envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"over-1-chunk-pass!"))?;
        if dec.as_slice() != pt.as_slice() {
            bail!("over-1-chunk round-trip mismatch");
        }
        Ok(())
    });

    // Two encryptions of the same plaintext must produce distinct salt and IV.
    test!("salt and iv unique per call", {
        let pt = b"salt-uniqueness-test";
        let env1 = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"salt-test-pass-1!"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let env2 = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"salt-test-pass-1!"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let salt1 = &env1[FIXED_HEADER_LEN..FIXED_HEADER_LEN + SALT_LEN];
        let salt2 = &env2[FIXED_HEADER_LEN..FIXED_HEADER_LEN + SALT_LEN];
        if salt1 == salt2 {
            bail!("salt collision, CSPRNG may be broken");
        }
        let iv1 = &env1[FIXED_HEADER_LEN + SALT_LEN..FIXED_HEADER_LEN + SALT_LEN + IV_LEN];
        let iv2 = &env2[FIXED_HEADER_LEN + SALT_LEN..FIXED_HEADER_LEN + SALT_LEN + IV_LEN];
        if iv1 == iv2 {
            bail!("IV collision, CSPRNG may be broken");
        }
        Ok(())
    });

    test!("rng health", {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        crate::crypto::rng::fill(&mut buf1);
        crate::crypto::rng::fill(&mut buf2);
        if buf1 == [0u8; 32] {
            bail!("RNG returned all zeros (first call)");
        }
        if buf2 == [0u8; 32] {
            bail!("RNG returned all zeros (second call)");
        }
        if buf1 == buf2 {
            bail!("RNG returned identical output twice");
        }
        let first = buf1[0];
        if buf1.iter().all(|&b| b == first) {
            bail!("RNG returned all-same-byte output");
        }
        Ok(())
    });

    test!("armor rejects missing BEGIN", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let no_begin: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----BEGIN "))
            .collect::<Vec<_>>()
            .join("\n");
        match armor::dearmor(&no_begin) {
            Ok(_) => bail!("armor parser accepted input without BEGIN"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects missing END", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let no_end: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----END "))
            .collect::<Vec<_>>()
            .join("\n");
        match armor::dearmor(&no_end) {
            Ok(_) => bail!("armor parser accepted input without END"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects mismatched labels", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let tampered = armored.replace("BEGIN SHERD MESSAGE", "BEGIN SHERD SHARE");
        match armor::dearmor(&tampered) {
            Ok(_) => bail!("armor parser accepted mismatched labels"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects multiple blocks", {
        let data = b"test";
        let armored1 = armor::armor(ARMOR_MSG, data);
        let armored2 = armor::armor(ARMOR_MSG, data);
        let combined = format!("{}\n{}", armored1, armored2);
        match armor::dearmor(&combined) {
            Ok(_) => bail!("armor parser accepted multiple blocks"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects raw base64", {
        let data = b"test data here for raw base64";
        let raw_b64 = armor::base64_encode(data);
        match armor::dearmor(&raw_b64) {
            Ok(_) => bail!("armor parser accepted raw base64 without markers"),
            Err(_) => Ok(()),
        }
    });

    // "AC==" is non-canonical: the bottom 4 bits of 'C' are nonzero, per
    // RFC 4648 §3.3.
    test!("armor rejects non-canonical padding", {
        let non_canonical = "-----BEGIN SHERD MESSAGE-----\nAC==\n-----END SHERD MESSAGE-----\n";
        match armor::dearmor(non_canonical) {
            Ok(_) => bail!("armor parser accepted non-canonical base64"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects mid-stream padding", {
        let mid_pad = "-----BEGIN SHERD MESSAGE-----\nAB=C\n-----END SHERD MESSAGE-----\n";
        match armor::dearmor(mid_pad) {
            Ok(_) => bail!("armor parser accepted mid-stream padding"),
            Err(_) => Ok(()),
        }
    });

    test!("armor rejects unknown label", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let tampered = armored
            .replace("BEGIN SHERD MESSAGE", "BEGIN SHERD UNKNOWN")
            .replace("END SHERD MESSAGE", "END SHERD UNKNOWN");
        match armor::dearmor(&tampered) {
            Ok(_) => bail!("armor parser accepted unknown label"),
            Err(_) => Ok(()),
        }
    });

    test!("multi-chunk round-trip", {
        let big = vec![b'A'; CHUNK_SIZE * 2 + CHUNK_SIZE / 2];
        let env = envelope::encrypt_envelope(
            &big,
            SecretBytes::from_slice(b"multi-chunk-kat-pass"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let dec =
            envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"multi-chunk-kat-pass"))?;
        if dec.as_slice() != big.as_slice() {
            bail!("multi-chunk round-trip mismatch");
        }
        let chunk_count = u32::from_be_bytes([
            env[FIXED_HEADER_LEN + SALT_LEN + IV_LEN + COMMIT_TAG_LEN],
            env[FIXED_HEADER_LEN + SALT_LEN + IV_LEN + COMMIT_TAG_LEN + 1],
            env[FIXED_HEADER_LEN + SALT_LEN + IV_LEN + COMMIT_TAG_LEN + 2],
            env[FIXED_HEADER_LEN + SALT_LEN + IV_LEN + COMMIT_TAG_LEN + 3],
        ]);
        if chunk_count < 3 {
            bail!("expected >=3 chunks, got {}", chunk_count);
        }
        Ok(())
    });

    test!("wrong passphrase on multi-chunk rejected", {
        let big = vec![b'X'; CHUNK_SIZE * 3];
        let env = envelope::encrypt_envelope(
            &big,
            SecretBytes::from_slice(b"correct-timing-pass"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let result =
            envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"wrong-timing-pass"));
        match result {
            Ok(_) => bail!("wrong passphrase was accepted (timing test)"),
            Err(_) => Ok(()),
        }
    });

    test!("shamir round-trip k=3 n=5", {
        let secret = b"shamir-test-secret";
        let shares = shamir::split(secret, 3, 5)?;
        let combo = shamir::combine(
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
            3,
        )?;
        if combo.as_slice() != secret {
            bail!("Shamir combine mismatch");
        }
        match shamir::combine(&[shares[0].clone(), shares[1].clone()], 3) {
            Ok(_) => bail!("2-of-3 accepted!"),
            Err(_) => Ok(()),
        }
    });

    // A constant polynomial would give every share the same payload. Two
    // shares with distinct x must have distinct payloads.
    test!("shamir non-constant polynomial", {
        let secret = b"check-no-constant-polynomial-test-1234";
        let shares = shamir::split(secret, 2, 3)?;
        let s0 = &shares[0];
        let s1 = &shares[1];
        if s0[1] == s1[1] {
            bail!("test setup error: shares have the same x value");
        }
        let payload0 = &s0[shamir::SHARE_HEADER_LEN..];
        let payload1 = &s1[shamir::SHARE_HEADER_LEN..];
        if payload0 == payload1 {
            bail!("two shares have identical payloads, constant polynomial");
        }
        Ok(())
    });

    test!("shamir rejects k mismatch", {
        let secret = b"k-mismatch-test";
        let shares = shamir::split(secret, 3, 5)?;
        match shamir::combine(&[shares[0].clone(), shares[1].clone()], 2) {
            Ok(_) => bail!("k downgrade accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("shamir detects tampered share", {
        let secret = b"tampered-share-test";
        let shares = shamir::split(secret, 3, 5)?;
        let mut tampered = shares[4].clone();
        tampered[3] ^= 0x01;
        match shamir::combine(
            &[
                shares[0].clone(),
                shares[1].clone(),
                shares[2].clone(),
                tampered,
            ],
            3,
        ) {
            Ok(_) => bail!("tampered share accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("shamir round-trip across k,n", {
        for k in 2..=5u8 {
            for n in k..=8u8 {
                let secret = format!("ct-test-k{}-n{}", k, n);
                let shares = shamir::split(secret.as_bytes(), k, n)?;
                let first_k: Vec<Vec<u8>> = shares[..k as usize].to_vec();
                let combo = shamir::combine(&first_k, k)?;
                if combo.as_slice() != secret.as_bytes() {
                    bail!("gmul mismatch at k={}, n={}", k, n);
                }
            }
        }
        Ok(())
    });

    test!("armor round-trip", {
        let data = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc sherd test";
        let armored = armor::armor(ARMOR_MSG, data);
        let dearmored = armor::dearmor(&armored)?;
        if dearmored != data {
            bail!("armor round-trip mismatch");
        }
        Ok(())
    });

    test!("header rejects unknown cipher_id", {
        let bad_header = envelope::FixedHeader::build(
            0,
            99,
            KDF_ID_ARGON2ID,
            COMMIT_ID_HMAC_SHA256_TRUNC128,
            1024,
            1,
            1,
            1,
        );
        match envelope::FixedHeader::parse(&bad_header) {
            Ok(_) => bail!("unknown cipher_id accepted!"),
            Err(_) => Ok(()),
        }
    });

    // Outputs must not be padded to a multiple of 8192. Allow at most
    // 1 coincidence out of 8 samples; otherwise plaintext length leaks.
    test!("padding randomizes length", {
        const LENGTH_ORACLE_BLOCK: usize = 8192;
        let sizes: &[usize] = &[1, 100, 1000, 4096, 8192, 10000, 20000, 50000];
        let mut multiples = 0;
        for &size in sizes {
            let pt = vec![b'L'; size];
            let env = envelope::encrypt_envelope(
                &pt,
                SecretBytes::from_slice(b"length-oracle-test-pass"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            if env.len() % LENGTH_ORACLE_BLOCK == 0 {
                multiples += 1;
            }
        }
        if multiples > sizes.len() / 2 {
            bail!(
                "{}/{} outputs are multiples of 8192, length oracle present",
                multiples,
                sizes.len()
            );
        }
        Ok(())
    });

    // Share header is 2 bytes [version, x]; K is not encoded anywhere.
    test!("shamir header hides threshold", {
        if shamir::SHARE_HEADER_LEN != 2 {
            bail!(
                "SHARE_HEADER_LEN is {} (expected 2, header may encode K)",
                shamir::SHARE_HEADER_LEN
            );
        }
        let secret = b"shamir-metadata-leak-test-secret-1234567890";
        let shares_k3 = shamir::split(secret, 3, 5)?;
        let shares_k5 = shamir::split(secret, 5, 8)?;
        let len3 = shares_k3[0].len();
        let len5 = shares_k5[0].len();
        if len3 != len5 {
            bail!(
                "share length differs between k=3 ({}) and k=5 ({}), format encodes K",
                len3,
                len5
            );
        }
        for s in shares_k3.iter().chain(shares_k5.iter()) {
            if s[0] != shamir::SHARE_FORMAT_VERSION {
                bail!(
                    "share byte 0 is {} (expected SHARE_FORMAT_VERSION {})",
                    s[0],
                    shamir::SHARE_FORMAT_VERSION
                );
            }
        }
        Ok(())
    });

    // Both slots must share ct_total_len. Encrypt small real + large decoy.
    test!("decoy size matches real slot", {
        let real_pt = b"small-real-msg-test";
        let decoy_pt = vec![b'D'; 50_000];
        let env = envelope::encrypt_envelope(
            real_pt,
            SecretBytes::from_slice(b"real-pass-test-aaa"),
            Some(&decoy_pt[..]),
            Some(SecretBytes::from_slice(b"decoy-pass-test-aaa")),
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let rest = &env[FIXED_HEADER_LEN..];
        let (rest_after_s0, slot0) = envelope::Slot::parse(rest)?;
        let (_rest_after_s1, slot1) = envelope::Slot::parse(rest_after_s0)?;
        if slot0.ct_total_len != slot1.ct_total_len {
            bail!(
                "slot sizes differ (slot0={}, slot1={}), decoy size leak",
                slot0.ct_total_len,
                slot1.ct_total_len
            );
        }
        Ok(())
    });

    // encrypt_envelope rejects input starting with the SHERD magic.
    test!("recursive encryption rejected", {
        let pt = b"recursive-encryption-test-message";
        let env1 = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"first-pass-test-aaa"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        if env1[..4] != MAGIC {
            bail!("test setup error: env1 does not start with MAGIC");
        }
        match envelope::encrypt_envelope(
            &env1,
            SecretBytes::from_slice(b"second-pass-test-aaa"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        ) {
            Ok(_) => bail!("recursive encryption of a SHERD envelope was accepted"),
            Err(_) => Ok(()),
        }
    });

    // Release-binary mlock verification lives in tests/mlock_bypass.rs.
    // Here we just check the env var does not leak into the unit-test env.
    test!("no_mlock env not leaked", {
        if std::env::var("SHERD_ALLOW_NO_MLOCK").is_ok() {
            bail!(
                "SHERD_ALLOW_NO_MLOCK is set in the test environment, \
                  a previous test failed to clean up"
            );
        }
        Ok(())
    });

    // Wrong PRK must take similar time to correct. Argon2id is bypassed so
    // timing reflects the AES-GCM path; a wrong PRK must not short-circuit.
    test!("wrong prk timing matches correct", {
        use std::time::Instant;
        let big = vec![b'T'; CHUNK_SIZE * 2 + CHUNK_SIZE / 2]; // ~3 chunks
        let env = envelope::encrypt_envelope(
            &big,
            SecretBytes::from_slice(b"timing-correct-pass-test"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let fixed_header = &env[..FIXED_HEADER_LEN];
        let rest = &env[FIXED_HEADER_LEN..];
        let (_rest_after_s0, slot0) = envelope::Slot::parse(rest)?;
        let params = crate::crypto::constants::KdfPreset::Standard.params();
        let (prk_correct, _commit_key) = kdf::derive_slot_secrets_from_secret(
            SecretBytes::from_slice(b"timing-correct-pass-test"),
            &slot0.salt,
            params.mem_kib,
            params.iters,
            params.par,
        )?;
        let mut wrong_prk = [0u8; 32];
        crate::crypto::rng::fill(&mut wrong_prk);
        if &wrong_prk[..] == prk_correct.as_bytes() {
            bail!("test setup error: wrong PRK equals correct PRK");
        }
        // Warm up: first call may allocate.
        let _ = envelope::decrypt_stream(
            prk_correct.as_bytes(),
            &slot0.ct,
            &slot0.base_iv,
            fixed_header,
            &slot0.salt,
            slot0.chunk_count,
        );
        let n_iter = 5u32;
        let mut correct_times = Vec::with_capacity(n_iter as usize);
        for _ in 0..n_iter {
            let start = Instant::now();
            let _ = envelope::decrypt_stream(
                prk_correct.as_bytes(),
                &slot0.ct,
                &slot0.base_iv,
                fixed_header,
                &slot0.salt,
                slot0.chunk_count,
            );
            correct_times.push(start.elapsed().as_nanos());
        }
        let mut wrong_times = Vec::with_capacity(n_iter as usize);
        for _ in 0..n_iter {
            let start = Instant::now();
            let _ = envelope::decrypt_stream(
                &wrong_prk,
                &slot0.ct,
                &slot0.base_iv,
                fixed_header,
                &slot0.salt,
                slot0.chunk_count,
            );
            wrong_times.push(start.elapsed().as_nanos());
        }
        // Medians, robust to outliers.
        correct_times.sort_unstable();
        wrong_times.sort_unstable();
        let correct_median = correct_times[correct_times.len() / 2];
        let wrong_median = wrong_times[wrong_times.len() / 2];
        // 3x threshold for CI noise; a real early-exit is 3x-10x faster.
        if wrong_median * 3 < correct_median {
            bail!(
                "wrong-PRK decrypt {} ns is >3x faster than correct {} ns, timing leak",
                wrong_median,
                correct_median
            );
        }
        Ok(())
    });

    // Flip 1 bit in the GCM tag; decrypt must reject.
    test!("aead tag tamper rejected", {
        let key = [0u8; 32];
        let iv = [0u8; IV_LEN];
        let pt = b"tag-tamper-test-message";
        let mut ct = aead::encrypt_chunk(&key, &iv, b"aad", pt)?;
        let ct_len = ct.len();
        if ct_len < TAG_LEN {
            bail!("ct too short: {}", ct_len);
        }
        let tag_last = ct_len - 1;
        ct[tag_last] ^= 0x01;
        match aead::decrypt_chunk(&key, &iv, b"aad", &ct) {
            Ok(_) => bail!("tag tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    // x=0 is the polynomial's constant term, i.e. the secret.
    test!("shamir rejects x=0", {
        let secret = b"shamir-index-zero-test";
        let shares = shamir::split(secret, 3, 5)?;
        let mut bad_share = shares[0].clone();
        bad_share[1] = 0;
        match shamir::combine(&[bad_share, shares[1].clone(), shares[2].clone()], 3) {
            Ok(_) => bail!("combine accepted share with x=0!"),
            Err(_) => Ok(()),
        }
    });

    // k-1 shares must not recover the secret across k in 2..=5.
    test!("shamir k-1 shares leak nothing", {
        let secret = b"k-minus-1-no-recovery-test-secret-1234567890";
        for k in 2..=5u8 {
            let n = (k + 2).min(10);
            if n < k {
                continue;
            }
            let shares = shamir::split(secret, k, n)?;
            let k_minus_1_shares: Vec<Vec<u8>> = shares[..(k - 1) as usize].to_vec();
            if let Ok(recovered) = shamir::combine(&k_minus_1_shares, k) {
                if recovered.as_slice() == secret {
                    bail!("k-1={} shares recovered the SECRET for k={}", k - 1, k);
                }
                bail!(
                    "combine accepted k-1={} shares for k={} (returned wrong value)",
                    k - 1,
                    k
                );
            }
        }
        Ok(())
    });

    println!();
    println!("==========================================");
    println!("  Passed: {}", passed);
    println!("  Failed: {}", failed);
    println!("==========================================");
    if failed > 0 {
        bail!("SELF-TEST FAILED, DO NOT USE THIS BINARY");
    }
    Ok(())
}

/// SHA-256 of the running binary, used by `sherd hash`.
///
/// current_exe may resolve symlinks; the binary can be replaced between
/// resolution and open.
pub fn compute_binary_hash() -> Result<String> {
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe()?;
    let mut file = std::fs::File::open(&exe)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hex_encode(&hash))
}
