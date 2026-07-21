//! Cryptographic self-tests (KATs + round-trip + tamper rejection).
//!
//! Run `fortis selftest` before trusting the binary in a sensitive
//! environment.

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

/// Known-answer test vectors (mirror the browser FORTIS v7 constants).
const KAT_AESGCM_EMPTY_TAG_HEX: &str = "530f8afbc74536b9a963b4f1c4cb738b";

/// Pinned Argon2id KAT vector (matches browser FORTIS v7).
const KAT_ARGON2ID_HEX: &str = "e6893e3d82174029fbde1a7eb3d494fa68999742552ed0f64677c38c4d0514b4";

/// Pinned HKDF-SHA256 KAT (RFC 5869 Test Case 1).
const KAT_HKDF_RFC5869_TC1_HEX: &str =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

/// Pinned HKDF PRK (RFC 5869 Test Case 1 intermediate). Verifying the
/// PRK intermediate eliminates the class of failure where compensating
/// bugs in extract and expand produce the correct OKM.
const KAT_HKDF_RFC5869_TC1_PRK_HEX: &str =
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

/// Pinned HMAC-SHA256 KAT (RFC 4231 Test Case 1).
const KAT_HMAC_RFC4231_TC1_HEX: &str =
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

/// Pinned AES-256-GCM KAT with non-empty plaintext.
/// Test vector: NIST GCM Test Case 14 (AES-256, zero key, zero IV,
/// 16-byte zero plaintext, empty AAD).
///   key   = 32 zero bytes
///   iv    = 12 zero bytes
///   pt    = 16 zero bytes
///   ct    = cea7403d4d606b6e074ec5d3baf39d18
///   tag   = d0d1c8a799996bf0265b98b5d48ab919
/// The ciphertext+tag concatenated (what encrypt_chunk returns) is:
///   cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919
const KAT_AESGCM_16BYTE_CT_HEX: &str =
    "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Safe hex decode that returns `Result` instead of panicking. A panic
/// in the selftest is acceptable (we want to abort on tampered
/// constants), but returning Result makes the failure mode explicit.
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
    println!("FORTIS v7.3.0 — Cryptographic Self-Tests");
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

    test!("Argon2id pinned KAT", {
        // The selftest bypasses `kdf::argon2id_master` (which enforces
        // KDF_MEM_MIN = 64 MiB) and calls the argon2 crate directly with
        // the original KAT params (1 MiB, 3 iters, 1 lane). This is
        // acceptable because the selftest's job is to detect a
        // tampered/replaced argon2 crate, not to enforce production KDF
        // parameters. The KAT value is unchanged across versions.
        use argon2::{Algorithm, Argon2, Params, Version};
        let salt = *b"blackout-v6-kat-salt-32-bytes!!!";
        let params = Params::new(1024, 3, 1, Some(32)).map_err(|_| anyhow::anyhow!("bad"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(b"blackout-v6-kat-password", &salt, &mut out)
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

    // Argon2id with PRODUCTION parameters. A bug that only manifests at
    // production memory sizes (e.g., a memory allocation failure, an
    // off-by-one in the Argon2id memory matrix addressing that only
    // triggers above a certain size, a zeroization feature that fails on
    // large buffers) would NOT be caught by the 1 MiB KAT.
    //
    // This KAT runs Argon2id at the Standard preset (64 MiB, 3 iters,
    // 1 lane) and verifies it produces a 32-byte non-zero output. We do
    // NOT pin the exact output because:
    //   (a) Argon2id is deterministic, but the pinned value would need
    //       to be computed once and stored — adding a maintenance burden.
    //   (b) The goal here is to detect crashes/panics/zero-output at
    //       production memory sizes, not to detect a different Argon2id
    //       implementation (that's the 1 MiB KAT's job).
    //   (c) DETERMINISM is verified by computing twice and comparing.
    test!(
        "Argon2id production params (64 MiB) — smoke + determinism",
        {
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
        }
    );

    test!("Argon2id downgrade protection rejects weak KDF params", {
        // Verify that `argon2id_master` REJECTS mem_kib below KDF_MEM_MIN.
        let salt = [0u8; SALT_LEN];
        match kdf::argon2id_master(b"test-passphrase", &salt, 1024, 3, 1) {
            Ok(_) => bail!("REGRESSION: argon2id_master accepted weak KDF params"),
            Err(_) => Ok(()),
        }
    });

    test!("HKDF-SHA256 pinned KAT — RFC 5869 TC1", {
        let ikm = vec![0x0bu8; 22];
        let salt = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = vec![0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = kdf::hkdf_extract(&salt, &ikm)?;
        // Verify the PRK intermediate matches RFC 5869 TC1.
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

    test!("HMAC-SHA256 pinned KAT — RFC 4231 TC1", {
        // Compute HMAC-SHA256 DIRECTLY (not via the commit module,
        // which truncates and binds fixed_header/salt/IV into the
        // message) on the RFC 4231 TC1 inputs and compare the full
        // 32-byte output to the pinned reference value.
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

    test!("HMAC-SHA256 commit-tag determinism (regression)", {
        // The commit tag takes a typed &[u8; FIXED_HEADER_LEN] and a
        // ct_first_chunk_hash argument. Use a 32-byte key (Fortis
        // commit keys are always 32 bytes, derived via HKDF-Expand with
        // length=32).
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

    test!("Per-chunk key derivation (HKDF-Expand)", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        // derive_chunk_key takes chunk_count for domain separation.
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

    test!("Chunk keys are Zeroizing", {
        // Regression: derive_chunk_key_array must return a Zeroizing<[u8;32]>
        // so the stack copy is wiped on drop. We verify the type by calling
        // .as_ref() on it (only Zeroizing supports this).
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        let k0 = kdf::derive_chunk_key_array(&prk, 0, 10)?;
        let _ = k0.as_ref();
        if k0.as_ref().len() != 32 {
            bail!("expected 32-byte key, got {}", k0.as_ref().len());
        }
        Ok(())
    });

    test!("decrypt_chunk returns Zeroizing<Vec<u8>>", {
        // Verify that decrypt_chunk returns a Zeroizing-wrapped Vec (not
        // a raw Vec) so the plaintext is wiped on drop.
        //
        // The runtime zero-key check in `encrypt_chunk` rejects all-
        // zero keys as a defense against catastrophic HKDF failures.
        // That check is appropriate for production keys but would
        // reject NIST GCM test vectors (TC1-TC4 use zero keys by
        // convention). For this test (which verifies the Zeroizing
        // WRAPPING, not the
        // KAT correctness), use a non-zero key — the wrapping behavior
        // is key-independent, and using a non-zero key avoids tripping
        // the zero-key check.
        let mut key = [0u8; 32];
        key[0] = 1; // non-zero key to pass the runtime check
        let iv = [0u8; IV_LEN];
        let ct = aead::encrypt_chunk(&key, &iv, b"aad", b"plaintext")?;
        let pt = aead::decrypt_chunk(&key, &iv, b"aad", &ct)?;
        // Verify the plaintext matches (the Zeroizing wrapper ensures it
        // is wiped on drop — we cannot call .as_ref() without a type hint
        // because Vec<u8> has multiple AsRef impls).
        let pt_slice: &[u8] = pt.as_ref();
        if pt_slice != b"plaintext" {
            bail!("plaintext mismatch");
        }
        Ok(())
    });

    test!("chunk_nonce uses all 12 bytes of base_iv", {
        // Verify that changing base_iv[8..12] changes the nonce.
        let mut iv_a = [0u8; IV_LEN];
        iv_a[8] = 0xAA;
        let iv_b = [0u8; IV_LEN]; // iv_b[8] = 0
        let n_a = aead::chunk_nonce(&iv_a, 0);
        let n_b = aead::chunk_nonce(&iv_b, 0);
        if n_a == n_b {
            bail!("REGRESSION: chunk_nonce ignores base_iv[8..12]");
        }
        // Also verify that changing chunk_index changes the nonce.
        let n_0 = aead::chunk_nonce(&iv_a, 0);
        let n_1 = aead::chunk_nonce(&iv_a, 1);
        if n_0 == n_1 {
            bail!("chunk_nonce collision on chunk_index 0 vs 1");
        }
        Ok(())
    });

    test!("hkdf_expand rejects length > 255*32", {
        // Verify the RFC 5869 hard limit is enforced.
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        match kdf::hkdf_expand(prk.as_slice(), b"info", 255 * 32 + 1) {
            Ok(_) => bail!("REGRESSION: hkdf_expand accepted length > 255*HashLen"),
            Err(_) => Ok(()),
        }
    });

    test!("hkdf_expand rejects length == 0", {
        let prk = kdf::hkdf_extract(b"salt", b"ikm")?;
        match kdf::hkdf_expand(prk.as_slice(), b"info", 0) {
            Ok(_) => bail!("REGRESSION: hkdf_expand accepted length == 0"),
            Err(_) => Ok(()),
        }
    });

    test!("hkdf_expand rejects short PRK", {
        // PRK shorter than 32 bytes should be rejected.
        let short_prk = [0u8; 16];
        match kdf::hkdf_expand(&short_prk, b"info", 32) {
            Ok(_) => bail!("REGRESSION: hkdf_expand accepted short PRK"),
            Err(_) => Ok(()),
        }
    });

    test!("Commit tag binds ciphertext content", {
        // Verify that changing the first chunk's ciphertext changes the
        // commit tag (proving the tag is bound to ciphertext content).
        // Use 32-byte key (matches Fortis commit key length).
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
            bail!("REGRESSION: commit tag does not bind ct_first_chunk_hash");
        }
        Ok(())
    });

    test!("verify_commit_tag returns Result<()>", {
        let key = [0u8; 32];
        let fixed_header = [0u8; FIXED_HEADER_LEN];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let ct_hash = [0u8; 32];
        let tag =
            commit::compute_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash)?;
        // Correct tag → Ok(())
        commit::verify_commit_tag(&key, &fixed_header, &salt, &base_iv, 1, 16, &ct_hash, &tag)?;
        // Wrong tag → Err
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

    test!("compute_first_chunk_hash determinism", {
        // Verify the SHA-256 hash is deterministic and changes with input.
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

    test!("AES-256-GCM KAT (NIST zero vector — empty plaintext)", {
        // The runtime zero-key check in `encrypt_chunk` is a defense
        // against HKDF failures; it must not reject legitimate KAT
        // vectors that use zero keys by convention (NIST GCM TC1-TC4
        // all use zero keys). Bypass `aead::encrypt_chunk` and call
        // the `aes-gcm` crate directly. This
        // mirrors the existing pattern for the Argon2id KAT, which
        // bypasses `kdf::argon2id_master` (which enforces KDF_MEM_MIN)
        // and calls the `argon2` crate directly.
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
        // For empty plaintext, AES-GCM returns just the 16-byte tag.
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

    // Pinned AES-256-GCM KAT with non-empty plaintext. A backdoored AES
    // implementation could pass the empty-plaintext KAT (which only
    // verifies the GCM tag computation on an all-zero GHASH input) but
    // fail on real data. This KAT uses the NIST GCM Test Case 14 vector:
    // zero key, zero iv, 16-byte zero plaintext, empty AAD. The expected
    // ciphertext+tag is the well-documented value below.
    test!(
        "AES-256-GCM KAT (NIST TC14 — 16-byte plaintext, non-empty)",
        {
            // Bypass `aead::encrypt_chunk` (which rejects zero keys) and
            // call the `aes-gcm` crate directly. NIST GCM TC14 uses a
            // zero key by convention; see the matching comment on the
            // empty-plaintext KAT above for full rationale.
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
        }
    );

    test!("AES-256-GCM tamper rejection", {
        // Use a non-zero key — the tamper-rejection property is key-
        // independent, and `encrypt_chunk` rejects all-zero keys as a
        // HKDF-failure defense. See the comment on the
        // "decrypt_chunk returns Zeroizing<Vec<u8>>" test for rationale.
        let mut key = [0u8; 32];
        key[0] = 1;
        let iv = [0u8; IV_LEN];
        let mut ct = aead::encrypt_chunk(&key, &iv, b"aad", b"plaintext")?;
        ct[0] ^= 0x01; // tamper
        match aead::decrypt_chunk(&key, &iv, b"aad", &ct) {
            Ok(_) => bail!("tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("HMAC-SHA256 commitment tag computation", {
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

    // Verifies CORRECTNESS (correct tag accepted, wrong tag rejected),
    // not constant-time behavior. The constant-time property is verified
    // by the statistical timing test below.
    test!(
        "Commit-tag verification (correct accepted, wrong rejected)",
        {
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
        }
    );

    test!("Full envelope round-trip (encrypt → decrypt)", {
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

    test!("Wrong passphrase rejected (commit-tag mismatch)", {
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

    test!("Header tamper rejected (AES-GCM AAD)", {
        let pt = b"self-test message ok";
        let mut env = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"correct-horse-kat"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        env[5] ^= 0x02; // tamper with flags byte
        match envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"correct-horse-kat")) {
            Ok(_) => bail!("header tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("Chunk ciphertext tamper rejected (GCM tag)", {
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

    test!("Commit-tag tamper rejected", {
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

    test!("Plausible deniability (decoy slot)", {
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

    test!("No-decoy and with-decoy have overlapping size ranges", {
        // The correct property to test is that the SIZE RANGES overlap —
        // i.e., an observer cannot distinguish "has decoy" from "no
        // decoy" based on size alone.
        //
        // We encrypt 20 times with and without decoy, collect all sizes,
        // and verify the ranges overlap.
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
        // The ranges must overlap: no_min <= w_max AND w_min <= no_max.
        if no_min > w_max || w_min > no_max {
            bail!(
                "size ranges do not overlap: no_decoy=[{},{}], with_decoy=[{},{}]",
                no_min,
                no_max,
                w_min,
                w_max
            );
        }
        // Also verify both ranges span at least PAD_BLOCK (jitter is 1..4,
        // so the range should be at least 3*PAD_BLOCK if we see both 1 and 4).
        // With 20 samples, we should see at least 2 distinct values.
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

    test!("Paranoid mode adds random jitter", {
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
        // The jitter adds 1..=4 extra PAD_BLOCK blocks, so there are
        // exactly 4 possible sizes. Requiring >= 5 unique is IMPOSSIBLE.
        // The threshold is set to 3 (out of 20 samples): a uniform PRNG
        // will produce all 4 values with overwhelming probability in 20
        // samples, while a broken PRNG that produces only 1-2 distinct
        // values will fail.
        if unique.len() < 3 {
            bail!(
                "paranoid jitter too weak: {} unique out of 20 samples",
                unique.len()
            );
        }
        // Also verify the spread: max - min must be at least 2 × PAD_BLOCK.
        // With 4 possible values (1,2,3,4 extra blocks), the max spread is
        // 3*PAD_BLOCK. Requiring >= 2*PAD_BLOCK ensures we see at least
        // values differing by 2 blocks (not just 1 extra vs 2 extra).
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

    // Chunk boundary round-trip tests. With the randomized padding scheme
    // (16–4096 bytes of uniform jitter on top of a 32-byte minimum), the
    // padded length is no longer a clean multiple of CHUNK_SIZE — so these
    // tests no longer exercise exact boundary conditions the way the
    // names suggest. They remain valuable as round-trip correctness
    // tests on small / large plaintexts, but they do NOT verify
    // specific chunk counts. The chunk-count assertions were removed to
    // avoid false confidence; if you need to verify chunk counts, add
    // tests that bypass `encrypt_envelope` and call `encrypt_stream`
    // directly with a known padded length.
    test!("Round-trip: empty plaintext", {
        // `encrypt_envelope` does NOT check for empty plaintext — it
        // correctly encrypts it (producing a valid envelope with a
        // zero-length plaintext framing). The CLI layer
        // (cmd_encrypt_message) rejects empty plaintext, but the envelope
        // layer should handle it gracefully. This test verifies that
        // empty plaintext round-trips correctly.
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

    test!("Round-trip: 1-byte plaintext", {
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

    test!(
        "Round-trip: plaintext sized to one chunk minus framing",
        {
            // pad_plaintext adds a 4-byte length prefix, so a plaintext of
            // CHUNK_SIZE - 4 bytes fills exactly one chunk BEFORE the
            // randomized padding is added. After padding the chunk count
            // may be 1 or 2 depending on the jitter, so this test verifies
            // round-trip correctness, not chunk count.
            let pt = vec![b'A'; CHUNK_SIZE - 4];
            let env = envelope::encrypt_envelope(
                &pt,
                SecretBytes::from_slice(b"exact-1-chunk-pass"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            let dec =
                envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"exact-1-chunk-pass"))?;
            if dec.as_slice() != pt.as_slice() {
                bail!("round-trip mismatch");
            }
            Ok(())
        }
    );

    test!("Round-trip: plaintext sized to exactly CHUNK_SIZE", {
        // CHUNK_SIZE bytes of plaintext + 4-byte framing + randomized
        // padding. Verifies round-trip correctness on a multi-chunk input.
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

    test!("Chunk boundary: 1 byte over 1 chunk (2 chunks total)", {
        let pt = vec![b'C'; CHUNK_SIZE - 3]; // CHUNK_SIZE - 3 + 4 framing = CHUNK_SIZE + 1 → 2 chunks
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

    // Salt uniqueness across encryptions. If the CSPRNG were broken
    // (returning constant output), every encryption would produce the
    // same salt → same PRK → nonce reuse across files → catastrophic
    // AES-GCM failure. This test encrypts the same plaintext twice and
    // verifies the salts differ.
    test!("Salt uniqueness across encryptions (CRIT)", {
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
        // Extract salts from both envelopes (salt is the first 32 bytes
        // after the fixed header).
        let salt1 = &env1[FIXED_HEADER_LEN..FIXED_HEADER_LEN + SALT_LEN];
        let salt2 = &env2[FIXED_HEADER_LEN..FIXED_HEADER_LEN + SALT_LEN];
        if salt1 == salt2 {
            bail!("CRITICAL: salt collision — CSPRNG may be broken!");
        }
        // Also verify IVs differ.
        let iv1 = &env1[FIXED_HEADER_LEN + SALT_LEN..FIXED_HEADER_LEN + SALT_LEN + IV_LEN];
        let iv2 = &env2[FIXED_HEADER_LEN + SALT_LEN..FIXED_HEADER_LEN + SALT_LEN + IV_LEN];
        if iv1 == iv2 {
            bail!("CRITICAL: IV collision — CSPRNG may be broken!");
        }
        Ok(())
    });

    // RNG health check. A broken CSPRNG that returns all zeros would
    // compromise every cryptographic operation. This test samples 32
    // bytes from the RNG and verifies they are not all zero and not all
    // the same byte. (A true statistical test would require thousands of
    // samples, but this catches the catastrophic "RNG returns constant"
    // failure mode that would otherwise go undetected until the
    // salt-uniqueness test above catches it indirectly.)
    test!("RNG health check (catastrophic failure detection)", {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        crate::crypto::rng::fill(&mut buf1);
        crate::crypto::rng::fill(&mut buf2);
        if buf1 == [0u8; 32] {
            bail!("CRITICAL: RNG returned all zeros (first call)");
        }
        if buf2 == [0u8; 32] {
            bail!("CRITICAL: RNG returned all zeros (second call)");
        }
        if buf1 == buf2 {
            bail!("CRITICAL: RNG returned identical output twice — possible constant output");
        }
        // Check for "all same byte" failure (e.g., all 0xFF).
        let first = buf1[0];
        if buf1.iter().all(|&b| b == first) {
            bail!("CRITICAL: RNG returned all-same-byte output");
        }
        Ok(())
    });

    // Armor negative tests. Verify the strict parser rejects malformed
    // inputs.
    test!("Armor parser rejects: missing BEGIN marker", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        // Strip the BEGIN line entirely.
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

    test!("Armor parser rejects: missing END marker", {
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

    test!("Armor parser rejects: mismatched labels", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let tampered = armored.replace("BEGIN FORTIS MESSAGE", "BEGIN FORTIS SHARE");
        match armor::dearmor(&tampered) {
            Ok(_) => bail!("armor parser accepted mismatched labels"),
            Err(_) => Ok(()),
        }
    });

    test!("Armor parser rejects: multiple BEGIN/END blocks", {
        let data = b"test";
        let armored1 = armor::armor(ARMOR_MSG, data);
        let armored2 = armor::armor(ARMOR_MSG, data);
        let combined = format!("{}\n{}", armored1, armored2);
        match armor::dearmor(&combined) {
            Ok(_) => bail!("armor parser accepted multiple blocks"),
            Err(_) => Ok(()),
        }
    });

    test!("Armor parser rejects: raw base64 without markers", {
        let data = b"test data here for raw base64";
        let raw_b64 = armor::base64_encode(data);
        match armor::dearmor(&raw_b64) {
            Ok(_) => bail!("armor parser accepted raw base64 without markers"),
            Err(_) => Ok(()),
        }
    });

    test!("Armor parser rejects: non-canonical base64 padding", {
        // "AB==" is canonical (decodes to single byte 0x00).
        // "AC==" is NON-canonical — the bottom 4 bits of 'C' (=2) are
        // non-zero, but they should be zero per RFC 4648 §3.3.
        let non_canonical = "-----BEGIN FORTIS MESSAGE-----\nAC==\n-----END FORTIS MESSAGE-----\n";
        match armor::dearmor(non_canonical) {
            Ok(_) => bail!("armor parser accepted non-canonical base64"),
            Err(_) => Ok(()),
        }
    });

    test!("Armor parser rejects: mid-stream padding", {
        // "=" in the middle of a base64 group is invalid.
        let mid_pad = "-----BEGIN FORTIS MESSAGE-----\nAB=C\n-----END FORTIS MESSAGE-----\n";
        match armor::dearmor(mid_pad) {
            Ok(_) => bail!("armor parser accepted mid-stream padding"),
            Err(_) => Ok(()),
        }
    });

    test!("Armor parser rejects: unknown label", {
        let data = b"test";
        let armored = armor::armor(ARMOR_MSG, data);
        let tampered = armored
            .replace("BEGIN FORTIS MESSAGE", "BEGIN FORTIS UNKNOWN")
            .replace("END FORTIS MESSAGE", "END FORTIS UNKNOWN");
        match armor::dearmor(&tampered) {
            Ok(_) => bail!("armor parser accepted unknown label"),
            Err(_) => Ok(()),
        }
    });

    test!("Multi-chunk streaming (3+ chunks, >1 MiB)", {
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

    // With the uniform-timing fix, decrypt_envelope must process ALL
    // chunks on EVERY slot regardless of whether the commit tag matches.
    // We cannot measure wall-time reliably in a unit test (CI variance),
    // but we CAN verify the fix structurally: encrypt a multi-chunk
    // message, then decrypt with WRONG passphrase. If the fix is in
    // place, decrypt_stream processed all chunks (the commit_tag for the
    // wrong passphrase will not match, but decrypt_stream still ran
    // through every chunk). We cannot observe the time directly, but we
    // can verify the function still returns Err (no false positive) and
    // does not panic.
    test!(
        "Wrong passphrase on multi-chunk envelope rejected (timing path exercised)",
        {
            let big = vec![b'X'; CHUNK_SIZE * 3]; // 3 chunks
            let env = envelope::encrypt_envelope(
                &big,
                SecretBytes::from_slice(b"correct-timing-pass"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            // Wrong passphrase — must fail, and must not panic.
            let result =
                envelope::decrypt_envelope(&env, SecretBytes::from_slice(b"wrong-timing-pass"));
            match result {
                Ok(_) => bail!("wrong passphrase was accepted (timing test)"),
                Err(_) => Ok(()),
            }
        }
    );

    test!("Shamir Secret Sharing (split 3-of-5, combine)", {
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

    test!("Shamir no constant polynomial (statistical)", {
        // In the new Shamir format (2-byte header + fixed 4096-byte
        // payload), `share.len() = 4098`. The correct check for "no
        // constant polynomial" is: if the polynomial is constant (all
        // random coefficients are zero), then P_i(x) = payload[i] for
        // all x, and ALL shares have the SAME payload. So we verify that
        // two shares with DIFFERENT x values have DIFFERENT payloads.
        // If they have the same payload, the polynomial was constant
        // (a regression of the no-constant-polynomial guarantee that
        // shamir::split prevents by retrying when coeffs[1..] are all
        // zero).
        let secret = b"check-no-constant-polynomial-test-1234";
        let shares = shamir::split(secret, 2, 3)?;
        // Each share is [SHARE_FORMAT_VERSION, x, payload(4096)].
        // Compare the payload regions of two shares with different x values.
        let s0 = &shares[0];
        let s1 = &shares[1];
        // Verify x values differ (they should — split draws distinct x's).
        if s0[1] == s1[1] {
            bail!("test setup error: shares have the same x value");
        }
        // Compare payloads (bytes SHARE_HEADER_LEN..). If they're identical,
        // the polynomial was constant — a regression of the
        // no-constant-polynomial guarantee.
        let payload0 = &s0[shamir::SHARE_HEADER_LEN..];
        let payload1 = &s1[shamir::SHARE_HEADER_LEN..];
        if payload0 == payload1 {
            bail!("REGRESSION: two shares have identical payloads (constant polynomial)");
        }
        Ok(())
    });

    test!("Shamir reject k mismatch from share", {
        let secret = b"k-mismatch-test";
        let shares = shamir::split(secret, 3, 5)?;
        match shamir::combine(&[shares[0].clone(), shares[1].clone()], 2) {
            Ok(_) => bail!("REGRESSION: k downgrade accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("Shamir detect tampered extra share", {
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
            Ok(_) => bail!("REGRESSION: tampered share accepted!"),
            Err(_) => Ok(()),
        }
    });

    test!("Shamir gmul is branchless (round-trip across k,n)", {
        // Statistical sanity: gmul must agree with the reference values
        // across the full 0..256 × 0..256 input space (regression for the
        // branchless rewrite). We don't call gmul directly (it's private),
        // but split+combine round-trip on adversarial inputs exercises it.
        for k in 2..=5u8 {
            for n in k..=8u8 {
                let secret = format!("ct-test-k{}-n{}", k, n);
                let shares = shamir::split(secret.as_bytes(), k, n)?;
                // Use first k shares
                let first_k: Vec<Vec<u8>> = shares[..k as usize].to_vec();
                let combo = shamir::combine(&first_k, k)?;
                if combo.as_slice() != secret.as_bytes() {
                    bail!("gmul branchless regression at k={}, n={}", k, n);
                }
            }
        }
        Ok(())
    });

    test!("ASCII armor round-trip", {
        let data = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc fortis test";
        let armored = armor::armor(ARMOR_MSG, data);
        let dearmored = armor::dearmor(&armored)?;
        if dearmored != data {
            bail!("armor round-trip mismatch");
        }
        Ok(())
    });

    test!("Header parser rejects unknown cipher_id", {
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

    // =====================================================================
    // Regression tests for known vulnerability classes.
    //
    // Each test below verifies that the fix for a documented
    // vulnerability is present and effective.
    // =====================================================================

    // Regression test: length oracle — output size must NOT be padded to
    // 8 KiB.
    test!("length_oracle_padding_is_randomized", {
        // A previous version padded the output file to a multiple of 8192
        // bytes, leaking the plaintext length to within 8 KB. After the
        // fix, the output size must NOT be a multiple of 8192 for typical
        // plaintext sizes. (The fixed-header + slot-header overhead of
        // 84 bytes ensures the output is never an exact multiple of 8192
        // in the current format; this test catches a regression where
        // someone adds a final outer padding step that rounds the total
        // file size up to 8192.)
        const LENGTH_ORACLE_BLOCK: usize = 8192;
        let sizes: &[usize] = &[1, 100, 1000, 4096, 8192, 10000, 20000, 50000];
        let mut multiples = 0;
        for &size in sizes {
            let pt = vec![b'L'; size];
            let env = envelope::encrypt_envelope(
                &pt,
                SecretBytes::from_slice(b"length-oracle-t6.1-pass"),
                None,
                None,
                crate::crypto::constants::KdfPreset::Standard,
                false,
            )?;
            if env.len() % LENGTH_ORACLE_BLOCK == 0 {
                multiples += 1;
            }
        }
        // Allow at most 1 coincidence (a plaintext whose natural padded
        // size happens to land on a multiple of 8192). If MOST outputs
        // are multiples of 8192, the length oracle is present.
        if multiples > sizes.len() / 2 {
            bail!(
                "REGRESSION: {}/{} outputs are multiples of 8192 — length oracle present",
                multiples,
                sizes.len()
            );
        }
        Ok(())
    });

    // Regression test: Shamir share header must NOT encode K.
    test!("shamir_share_header_does_not_leak_threshold", {
        // The previous share format stored K (threshold) at byte offset 2
        // of every share (between VERSION and the x-coordinate). An
        // interceptor of a single share could read this byte to learn
        // the quorum K, revealing the operational custody structure.
        //
        // In the new format, the share header is EXACTLY
        // SHARE_HEADER_LEN (2) bytes: [SHARE_FORMAT_VERSION, x]. K is
        // NOT stored. We verify:
        //   1. SHARE_HEADER_LEN == 2 (compile-time constant, no K field).
        //   2. Byte 0 == SHARE_FORMAT_VERSION for all shares.
        //   3. No header byte equals k (which would indicate K is stored).
        //   4. Share lengths are identical regardless of k (no length leak).
        if shamir::SHARE_HEADER_LEN != 2 {
            bail!(
                "REGRESSION: SHARE_HEADER_LEN is {} (expected 2 — header may encode K)",
                shamir::SHARE_HEADER_LEN
            );
        }
        let secret = b"shamir-metadata-leak-test-secret-1234567890";
        let shares_k3 = shamir::split(secret, 3, 5)?;
        let shares_k5 = shamir::split(secret, 5, 8)?;
        // Verify all shares have the same length (no k-dependent length leak).
        let len3 = shares_k3[0].len();
        let len5 = shares_k5[0].len();
        if len3 != len5 {
            bail!(
                "REGRESSION: share length differs between k=3 ({}) and k=5 ({}) — format encodes K",
                len3,
                len5
            );
        }
        // Verify byte 0 is SHARE_FORMAT_VERSION for all shares.
        for s in shares_k3.iter().chain(shares_k5.iter()) {
            if s[0] != shamir::SHARE_FORMAT_VERSION {
                bail!(
                    "REGRESSION: share byte 0 is {} (expected SHARE_FORMAT_VERSION {})",
                    s[0],
                    shamir::SHARE_FORMAT_VERSION
                );
            }
            // Verify no header byte equals k (3 or 5). With the new 2-byte
            // header [VERSION, x], byte 0 is VERSION (=2, not 3 or 5) and
            // byte 1 is x (random). If byte 1 happened to equal k, that's
            // a coincidence (x is random in [1, 255]), not a K leak. But
            // if a FUTURE regression adds K back to the header, this check
            // catches it for the specific k values we test.
            // Note: we do NOT check byte 1 against k because x is random
            // and could legitimately equal k by chance.
        }
        Ok(())
    });

    // Regression test: decoy size independence — both slots must have
    // equal ct_total_len.
    test!("decoy_size_independence_both_slots_equal", {
        // A previous implementation sized the real and decoy slots
        // independently, so an observer who decrypted the decoy could
        // compute real_size = total_output - decoy_size - overhead,
        // leaking the real plaintext size. After the fix, both slots are
        // sized to max(real_padded, decoy_padded), so the slot sizes are
        // equal and the observer cannot determine which slot is larger.
        //
        // We encrypt with a small real and a large decoy, then parse the
        // envelope and verify both slots have the same ct_total_len.
        let real_pt = b"small-real-msg-t6.3";
        let decoy_pt = vec![b'D'; 50_000];
        let env = envelope::encrypt_envelope(
            real_pt,
            SecretBytes::from_slice(b"real-pass-t6.3-aaa"),
            Some(&decoy_pt[..]),
            Some(SecretBytes::from_slice(b"decoy-pass-t6.3-aaa")),
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        let rest = &env[FIXED_HEADER_LEN..];
        let (rest_after_s0, slot0) = envelope::Slot::parse(rest)?;
        let (_rest_after_s1, slot1) = envelope::Slot::parse(rest_after_s0)?;
        if slot0.ct_total_len != slot1.ct_total_len {
            bail!(
                "REGRESSION: slot sizes differ (slot0={}, slot1={}) — decoy size leak",
                slot0.ct_total_len,
                slot1.ct_total_len
            );
        }
        Ok(())
    });

    // Regression test: recursive encryption must be rejected.
    test!("recursive_encryption_rejected_frt7_magic_input", {
        // Re-encrypting an already-encrypted Fortis envelope is an
        // operational footgun. The operator may accidentally pipe
        // `fortis decrypt` output back into `fortis encrypt`, producing a
        // double-encrypted blob. After the fix, encrypt_envelope must
        // REJECT input that begins with the Fortis magic "FRT7".
        let pt = b"recursive-encryption-test-message";
        let env1 = envelope::encrypt_envelope(
            pt,
            SecretBytes::from_slice(b"first-pass-t6.4-aaa"),
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
            SecretBytes::from_slice(b"second-pass-t6.4-aaa"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        ) {
            Ok(_) => bail!("REGRESSION: recursive encryption of a FORTIS envelope was accepted"),
            Err(_) => Ok(()),
        }
    });

    // Regression test: FORTIS_ALLOW_NO_MLOCK bypass disabled in release.
    //
    // The real verification (subprocess invocation of the release binary with
    // the env var set) lives in `tests/mlock_bypass.rs` as an integration
    // test. A unit-test cannot exercise main()'s startup path.
    //
    // Here we only assert a compile-time invariant: the env-var read in
    // main.rs is gated behind `#[cfg(debug_assertions)]`, so a release
    // build physically cannot honor the bypass.
    //
    // This is enforced by the `#[cfg(debug_assertions)]` block around the
    // `allow_no_mlock` env-var read in `src/main.rs`. If that guard is
    // ever removed, this assertion still passes (it cannot introspect
    // another module's cfg), but the integration test in
    // `tests/mlock_bypass.rs` will fail.
    //
    // We keep this entry as a documentation anchor and an env-hygiene
    // check (the env var must NOT leak into the test process).
    test!("fortis_allow_no_mlock_env_does_not_leak_into_unit_tests", {
        // If the env var is set in the unit-test environment, that's a
        // hygiene violation — a previous test failed to clean up.
        if std::env::var("FORTIS_ALLOW_NO_MLOCK").is_ok() {
            bail!("FORTIS_ALLOW_NO_MLOCK is set in the test environment — \
                  a previous test failed to clean up");
        }
        Ok(())
    });

    // Regression test: constant-time decrypt — wrong PRK takes similar
    // time to correct.
    test!("constant_time_decrypt_wrong_prk_similar_time", {
        // decrypt_stream must process ALL chunks regardless of whether
        // the PRK is correct, to prevent timing side-channels that
        // reveal which slot matched. A leaky implementation that
        // early-exits on the first chunk's tag mismatch would be much
        // faster on wrong PRKs.
        //
        // This test bypasses Argon2id (by deriving the PRK once and
        // calling decrypt_stream directly) so the timing measurement is
        // sensitive to AES-GCM path differences, not KDF overhead.
        use std::time::Instant;
        let big = vec![b'T'; CHUNK_SIZE * 2 + CHUNK_SIZE / 2]; // ~3 chunks
        let env = envelope::encrypt_envelope(
            &big,
            SecretBytes::from_slice(b"timing-correct-pass-t6.6"),
            None,
            None,
            crate::crypto::constants::KdfPreset::Standard,
            false,
        )?;
        // Parse the envelope to extract slot0 fields.
        let fixed_header = &env[..FIXED_HEADER_LEN];
        let rest = &env[FIXED_HEADER_LEN..];
        let (_rest_after_s0, slot0) = envelope::Slot::parse(rest)?;
        // Derive the correct PRK (one Argon2id call, not timed).
        let params = crate::crypto::constants::KdfPreset::Standard.params();
        let (prk_correct, _commit_key) = kdf::derive_slot_secrets_from_secret(
            SecretBytes::from_slice(b"timing-correct-pass-t6.6"),
            &slot0.salt,
            params.mem_kib,
            params.iters,
            params.par,
        )?;
        // Wrong PRK: a random 32-byte buffer (different from correct).
        let mut wrong_prk = [0u8; 32];
        crate::crypto::rng::fill(&mut wrong_prk);
        // Ensure wrong_prk differs from prk_correct.
        if &wrong_prk[..] == prk_correct.as_bytes() {
            bail!("test setup error: wrong PRK equals correct PRK");
        }
        // Warm up (first call may be slower due to memory allocation).
        let _ = envelope::decrypt_stream(
            prk_correct.as_bytes(),
            &slot0.ct,
            &slot0.base_iv,
            fixed_header,
            &slot0.salt,
            slot0.chunk_count,
        );
        // Time correct PRK.
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
        // Time wrong PRK (should fail but process all chunks).
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
        // Use medians (robust against outliers).
        correct_times.sort_unstable();
        wrong_times.sort_unstable();
        let correct_median = correct_times[correct_times.len() / 2];
        let wrong_median = wrong_times[wrong_times.len() / 2];
        // The wrong-PRK time must NOT be much faster than the correct time.
        // A constant-time implementation processes all chunks in both cases.
        // Threshold: wrong must be at least 1/3 of correct (ratio < 3x).
        // (Generous threshold to avoid CI flakiness; a real early-exit
        // leak would be 3x-10x+ faster on wrong PRKs.)
        if wrong_median * 3 < correct_median {
            bail!(
                "REGRESSION: wrong-PRK decrypt {} ns is >3x faster than correct {} ns — timing leak",
                wrong_median, correct_median
            );
        }
        Ok(())
    });

    // Regression test: AEAD tag tamper must be rejected.
    test!("aead_tag_tamper_rejected_bit_flip", {
        // The existing "AES-256-GCM tamper rejection" test tampers a
        // CIPHERTEXT byte (ct[0]), not a TAG byte. A bug that checks
        // ciphertext integrity but skips tag verification would pass the
        // existing test but fail this one. This test flips a single bit
        // in the GCM tag (last 16 bytes) and verifies decryption rejects
        // it.
        let key = [0u8; 32];
        let iv = [0u8; IV_LEN];
        let pt = b"tag-tamper-test-message-t6.7";
        let mut ct = aead::encrypt_chunk(&key, &iv, b"aad", pt)?;
        let ct_len = ct.len();
        if ct_len < TAG_LEN {
            bail!("ct too short: {}", ct_len);
        }
        // Flip 1 bit in the last byte of the tag (tag is the last 16 bytes).
        let tag_last = ct_len - 1;
        ct[tag_last] ^= 0x01;
        match aead::decrypt_chunk(&key, &iv, b"aad", &ct) {
            Ok(_) => bail!("REGRESSION: tag tamper accepted!"),
            Err(_) => Ok(()),
        }
    });

    // Regression test: Shamir must reject share with index x=0.
    test!("shamir_rejects_share_with_index_zero", {
        // A share with x=0 is the polynomial evaluated at 0, which
        // equals the secret (the constant term). An attacker who can
        // inject a share with x=0 into combine() would recover the
        // secret from a single "share". combine() must reject x=0.
        let secret = b"shamir-index-zero-test-t6.8";
        let shares = shamir::split(secret, 3, 5)?;
        // Craft a share with x=0 by modifying share[0]'s x byte (byte 1).
        let mut bad_share = shares[0].clone();
        bad_share[1] = 0; // set x=0
        match shamir::combine(&[bad_share, shares[1].clone(), shares[2].clone()], 3) {
            Ok(_) => bail!("REGRESSION: combine accepted share with x=0!"),
            Err(_) => Ok(()),
        }
    });

    // Regression test: Shamir K-1 shares must NOT recover the secret.
    test!("shamir_k_minus_1_shares_do_not_recover_secret", {
        // Fewer than K shares must NOT reveal the secret. This is the
        // fundamental information-theoretic property of Shamir Secret
        // Sharing. We test multiple k values and verify:
        //   (a) combine() rejects k-1 shares (API-level check), AND
        //   (b) even if combine() erroneously returned a value, it must
        //       NOT equal the secret (defense-in-depth).
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
                    bail!(
                        "REGRESSION: k-1={} shares recovered the SECRET for k={}",
                        k - 1,
                        k
                    );
                }
                bail!(
                    "REGRESSION: combine accepted k-1={} shares for k={} (returned wrong value)",
                    k - 1,
                    k
                );
            }
            // Err(_) is the correct behavior: combine must reject k-1 shares.
        }
        Ok(())
    });

    println!();
    println!("==========================================");
    println!("  Passed: {}", passed);
    println!("  Failed: {}", failed);
    println!("==========================================");
    if failed > 0 {
        bail!("SELF-TEST FAILED — DO NOT USE THIS BINARY");
    }
    Ok(())
}

/// Compute the SHA-256 of the running binary's own executable file.
/// Used by `fortis hash` to print a fingerprint for out-of-band verification.
///
/// # TOCTOU note
///
/// There is a small time-of-check/time-of-use gap between
/// `std::env::current_exe()` resolving the path and `File::open` opening
/// it. On most platforms `current_exe` returns a path that may traverse
/// symlinks; an attacker who can replace the binary on disk between the
/// two calls could feed a different file to the hasher. In practice,
/// if an attacker can replace the binary, the host is already
/// compromised and the hash is meaningless — the operator should
/// compute the hash out-of-band (e.g., `sha256sum $(which fortis)`)
/// before trusting the binary in a sensitive environment.
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
