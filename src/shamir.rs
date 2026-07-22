//! Shamir Secret Sharing over GF(256), constant-time.
//!
//! Share format: `[VERSION(1) | x(1) | secret_len(2 BE) | secret(L)
//! | zero_pad(P) | sha256(...)(32)]`. The digest covers everything
//! except itself. K and N are not stored; K is supplied to `combine()`.

use crate::crypto::rng;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Share format version. v2 = 2-byte header + fixed 4096-byte payload.
pub const SHARE_FORMAT_VERSION: u8 = 2;

/// Share header length: `[SHARE_FORMAT_VERSION, x]`.
pub const SHARE_HEADER_LEN: usize = 2;

/// SHA-256 digest length.
const HASH_LEN: usize = 32;

/// Length of the `secret_len` field: u16 big-endian, 2 bytes.
const LEN_FIELD_LEN: usize = 2;

/// Fixed payload size for every share.
pub const SHARE_PAYLOAD_BYTES: usize = 4096;

/// Maximum secret length. Larger secrets must be encrypted first and
/// the key shared via Shamir.
pub const MAX_SECRET_LEN: usize = SHARE_PAYLOAD_BYTES - LEN_FIELD_LEN - HASH_LEN; // 4062

/// Offset where the SHA-256 digest begins within the payload.
const HASH_OFFSET: usize = SHARE_PAYLOAD_BYTES - HASH_LEN; // 4064

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic: branchless, constant-time
// ---------------------------------------------------------------------------

/// Branchless GF(2^8) multiply with the AES polynomial 0x11b.
fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut b = b as u16;
    let mut p: u16 = 0;
    for _ in 0..8 {
        // mask = -(b & 1): all-ones if bit set, all-zeros otherwise.
        let mask = (0u16).wrapping_sub(b & 1);
        p ^= a & mask;
        let hi_bit = (a >> 7) & 1;
        a <<= 1;
        let mask = (0u16).wrapping_sub(hi_bit);
        a ^= 0x11b & mask;
        b >>= 1;
    }
    p as u8
}

/// GF(2^8) inverse via a^254 = a^(-1). 254 = 0b11111110, so every
/// iteration multiplies into r with no data-dependent branch.
fn ginv_checked(a: u8) -> Result<u8> {
    if a == 0 {
        // den is a product of distinct x's, nonzero in GF(256).
        bail!("bad");
    }
    let mut r: u8 = 1;
    let mut base: u8 = a;
    // base goes a^2, a^4, ..., a^128; r accumulates the product.
    for _ in 0..7 {
        base = gmul(base, base);
        r = gmul(r, base);
    }
    Ok(r)
}

/// 1 if x == 0, else 0. Used for constant-time duplicate-x detection.
#[inline]
fn is_zero_u8(x: u8) -> u8 {
    let nonzero = (x | x.wrapping_neg()) >> 7;
    1 - nonzero
}

/// Constant-time equality for two equal-length u8 slices. Returns 1 iff
/// all bytes match. Length is the caller's responsibility.
#[inline]
#[allow(dead_code)]
fn ct_eq_u8(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    is_zero_u8(diff)
}

// ---------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
///
/// Each share is `[SHARE_FORMAT_VERSION, x]` followed by
/// `SHARE_PAYLOAD_BYTES` of payload: 2-byte length, secret, zero padding,
/// SHA-256 digest.
///
/// Requires `secret.len() <= MAX_SECRET_LEN` and `2 <= k <= n <= 10`.
/// Returns `Err("bad")` on any invalid input; no oracle.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>> {
    if !(2..=10).contains(&k) || !(k..=10).contains(&n) {
        bail!("bad");
    }
    if secret.len() > MAX_SECRET_LEN {
        bail!("bad");
    }

    // Payload layout: secret_len u16 BE, secret, zero pad, SHA-256.
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; SHARE_PAYLOAD_BYTES]);
    let slen = secret.len() as u16;
    payload[0] = (slen >> 8) as u8;
    payload[1] = slen as u8;
    payload[2..2 + secret.len()].copy_from_slice(secret);

    // finalize_reset wipes the Sha256 state, which has seen the secret.
    let mut hasher = Sha256::new();
    hasher.update(&payload[..HASH_OFFSET]);
    let digest = hasher.finalize_reset();
    payload[HASH_OFFSET..SHARE_PAYLOAD_BYTES].copy_from_slice(&digest);

    // Generate n distinct random x in [1, 255]. x=0 is the constant
    // term and would leak the secret byte. Batched RNG to cut syscalls.
    let mut xs: Vec<u8> = Vec::with_capacity(n as usize);
    let mut seen = [false; 256];
    let mut rng_batch = [0u8; 32];
    let mut batch_pos = rng_batch.len(); // forces a fill on first use
    let mut attempts = 0u32;
    while xs.len() < n as usize {
        if batch_pos >= rng_batch.len() {
            rng::fill(&mut rng_batch);
            batch_pos = 0;
        }
        let x = rng_batch[batch_pos];
        batch_pos += 1;
        // x is public, so the indexed access into `seen` is not a side channel.
        if x == 0 || seen[x as usize] {
            attempts += 1;
            if attempts > 10000 {
                bail!("bad");
            }
            continue;
        }
        seen[x as usize] = true;
        xs.push(x);
    }
    // Wipe unused RNG candidates from the batch buffer.
    use zeroize::Zeroize;
    rng_batch.zeroize();

    // Build shares: one Vec per share, byte position at a time. Each
    // byte uses a fresh polynomial with that payload byte as the constant.
    let mut shares: Vec<Vec<u8>> = (0..n)
        .map(|_| Vec::with_capacity(SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES))
        .collect();

    // Coefficients, constant term = payload byte. Zeroizing because
    // coefficients include the secret.
    let mut coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; k as usize]);

    for &sb in payload.iter() {
        coeffs[0] = sb;
        // Reject all-zero random coeffs: a constant polynomial would
        // let any single share reveal that byte.
        let mut att = 0u32;
        loop {
            rng::fill(&mut coeffs[1..]);
            let mut coef_acc: u8 = 0;
            for &c in coeffs[1..].iter() {
                coef_acc |= c;
            }
            if coef_acc != 0 {
                break;
            }
            att += 1;
            if att > 100 {
                bail!("bad");
            }
        }
        // Hörner form: y = c_{k-1}; y = y*x ^ c_{k-2}; ... ; y = y*x ^ c_0.
        for (idx, &x) in xs.iter().enumerate() {
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gmul(y, x) ^ c;
            }
            shares[idx].push(y);
        }
    }

    // Prepend 2-byte header. K and N are not stored in the share.
    for (idx, share) in shares.iter_mut().enumerate() {
        let mut full = Vec::with_capacity(SHARE_HEADER_LEN + share.len());
        full.push(SHARE_FORMAT_VERSION);
        full.push(xs[idx]);
        full.extend_from_slice(share);
        use zeroize::Zeroize;
        share.zeroize();
        *share = full;
    }

    Ok(shares)
}

// ---------------------------------------------------------------------------
// Combine
// ---------------------------------------------------------------------------

/// Reconstruct the secret from `shares` via Lagrange interpolation in
/// GF(256). Requires at least `k_expected` shares; K is supplied by the
/// caller; the share header does not carry it.
///
/// Returns `Err("bad")` on any failure: malformed shares, duplicate x,
/// wrong K, or tampering. Tampering is caught by the SHA-256 digest when
/// exactly K shares are given, or by the consistency check otherwise.
/// The returned secret is wrapped in `Zeroizing<Vec<u8>>`.
pub fn combine(shares: &[Vec<u8>], k_expected: u8) -> Result<Zeroizing<Vec<u8>>> {
    if shares.is_empty() {
        bail!("bad");
    }
    if !(2..=10).contains(&k_expected) {
        bail!("bad");
    }
    let expected_len = SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES;

    // Parse and validate each share.
    let parsed: Vec<(u8, &[u8])> = shares
        .iter()
        .map(|s| {
            if s.len() != expected_len {
                bail!("bad");
            }
            if s[0] != SHARE_FORMAT_VERSION {
                bail!("bad");
            }
            let x = s[1];
            // x=0 is the polynomial's constant term, i.e. the secret.
            if x == 0 {
                bail!("bad");
            }
            Ok((x, &s[SHARE_HEADER_LEN..]))
        })
        .collect::<Result<Vec<_>>>()?;

    let k = k_expected as usize;
    if parsed.len() < k {
        bail!("bad");
    }

    // Constant-time duplicate-x detection: O(k^2) branchless pairwise
    // compare. No early exit, so an observer learns only that a duplicate
    // exists, not which pair.
    let n = parsed.len();
    let mut duplicate = 0u8;
    for i in 0..n {
        for j in (i + 1)..n {
            let diff = parsed[i].0 ^ parsed[j].0;
            duplicate |= is_zero_u8(diff);
        }
    }
    if duplicate != 0 {
        bail!("bad");
    }

    // Use the first k shares for reconstruction.
    let use_shares = &parsed[..k];

    // Pre-compute Lagrange coefficients.
    let mut lagrange_coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(k));
    for a in 0..k {
        let mut num = 1u8;
        let mut den = 1u8;
        for b in 0..k {
            if a == b {
                continue;
            }
            num = gmul(num, use_shares[b].0);
            den = gmul(den, use_shares[b].0 ^ use_shares[a].0);
        }
        // den is nonzero: distinct x's => x_a ^ x_b != 0 for a != b.
        let den_inv = ginv_checked(den)?;
        lagrange_coeffs.push(gmul(num, den_inv));
    }

    // Reconstruct the full padded payload.
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; SHARE_PAYLOAD_BYTES]);
    for i in 0..SHARE_PAYLOAD_BYTES {
        let mut acc = 0u8;
        for a in 0..k {
            acc ^= gmul(use_shares[a].1[i], lagrange_coeffs[a]);
        }
        payload[i] = acc;
    }

    // Consistency check: if MORE than k shares were provided, verify
    // each extra share against the reconstructed polynomial.
    if parsed.len() > k {
        for extra in &parsed[k..] {
            let mut eval_coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(k));
            for a in 0..k {
                let mut num = 1u8;
                let mut den = 1u8;
                for b in 0..k {
                    if a == b {
                        continue;
                    }
                    num = gmul(num, extra.0 ^ use_shares[b].0);
                    den = gmul(den, use_shares[a].0 ^ use_shares[b].0);
                }
                let den_inv = ginv_checked(den)?;
                eval_coeffs.push(gmul(num, den_inv));
            }
            // Branchless mismatch accumulation across all bytes; bail after.
            let mut mismatch = 0u8;
            for i in 0..SHARE_PAYLOAD_BYTES {
                let mut acc = 0u8;
                for a in 0..k {
                    acc ^= gmul(use_shares[a].1[i], eval_coeffs[a]);
                }
                mismatch |= acc ^ extra.1[i];
            }
            if mismatch != 0 {
                bail!("bad");
            }
        }
    }

    // Digest check catches tampering when exactly K shares are provided.
    // finalize_reset wipes the Sha256 state, which has seen the secret.
    let mut hasher = Sha256::new();
    hasher.update(&payload[..HASH_OFFSET]);
    let computed_hash = hasher.finalize_reset();
    let stored_hash = &payload[HASH_OFFSET..SHARE_PAYLOAD_BYTES];

    if !bool::from(computed_hash.as_slice().ct_eq(stored_hash)) {
        bail!("bad");
    }

    // secret_len is authenticated by the digest.
    let secret_len = ((payload[0] as u16) << 8) | (payload[1] as u16);
    let secret_len = secret_len as usize;
    if secret_len > MAX_SECRET_LEN {
        bail!("bad");
    }
    let secret_end = LEN_FIELD_LEN + secret_len;
    if secret_end > HASH_OFFSET {
        bail!("bad");
    }
    let secret_bytes = &payload[LEN_FIELD_LEN..secret_end];

    let mut secret: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; secret_len]);
    secret.copy_from_slice(secret_bytes);
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_roundtrip() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        let combo = combine(
            &[shares[0].clone(), shares[2].clone(), shares[4].clone()],
            3,
        )
        .unwrap();
        assert_eq!(combo.as_slice(), secret);
        let combo2 = combine(
            &[shares[1].clone(), shares[3].clone(), shares[0].clone()],
            3,
        )
        .unwrap();
        assert_eq!(combo2.as_slice(), secret);
    }

    #[test]
    fn test_shamir_insufficient_shares() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        assert!(combine(&[shares[0].clone(), shares[1].clone()], 3).is_err());
    }

    #[test]
    fn test_shamir_consistency_check() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        let mut tampered = shares[4].clone();
        // Flip the first payload byte; consistency check runs because 4 > k=3.
        tampered[2] ^= 0x01;
        assert!(combine(
            &[
                shares[0].clone(),
                shares[1].clone(),
                shares[2].clone(),
                tampered
            ],
            3,
        )
        .is_err());
    }

    // Exactly K shares: only the SHA-256 digest guards against tampering.
    #[test]
    fn test_shamir_tampering_detected_with_exact_k() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();

        // Padding byte.
        let mut tampered_pad = shares[0].clone();
        tampered_pad[100] ^= 0x01;
        assert!(combine(&[tampered_pad, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // Secret byte.
        let mut tampered_sec = shares[0].clone();
        tampered_sec[4] ^= 0x01;
        assert!(combine(&[tampered_sec, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // secret_len field.
        let mut tampered_len = shares[0].clone();
        tampered_len[2] ^= 0x01;
        assert!(combine(&[tampered_len, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // Digest region itself.
        let mut tampered_hash = shares[0].clone();
        let last = tampered_hash.len() - 1;
        tampered_hash[last] ^= 0x01;
        assert!(combine(&[tampered_hash, shares[1].clone(), shares[2].clone()], 3,).is_err());
    }

    // No metadata leak from a single share.
    #[test]
    fn test_shamir_no_metadata_leak() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();

        // Fixed-size shares.
        for s in shares.iter() {
            assert_eq!(s.len(), SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES);
        }

        // Header is 2 bytes [SHARE_FORMAT_VERSION, x]. No K, no N.
        for s in shares.iter() {
            assert_eq!(s[0], SHARE_FORMAT_VERSION);
            assert_ne!(s[1], 0, "x must be in [1, 255]");
        }

        // x values must be distinct.
        let mut xs: Vec<u8> = shares.iter().map(|s| s[1]).collect();
        xs.sort();
        for i in 1..xs.len() {
            assert_ne!(xs[i], xs[i - 1], "duplicate x value");
        }
    }

    // A single share from a k=3 split is byte-identical in structure to
    // one from a k=5 split.
    #[test]
    fn test_shamir_share_indistinguishable_across_k() {
        let secret = b"top-secret-message";

        let shares_k3 = split(secret, 3, 5).unwrap();
        let shares_k5 = split(secret, 5, 7).unwrap();

        assert_eq!(shares_k3[0].len(), shares_k5[0].len());

        for s in shares_k3.iter().chain(shares_k5.iter()) {
            assert_eq!(s[0], SHARE_FORMAT_VERSION);
            // x is a u8 in [1, 255]. x=0 is the polynomial's constant term,
            // which is the secret itself.
            assert!(s[1] >= 1);
        }

        // 3 shares from a k=3 split must not combine under k_expected=5.
        let combo_wrong_k = combine(
            &[
                shares_k3[0].clone(),
                shares_k3[1].clone(),
                shares_k3[2].clone(),
            ],
            5, // wrong K; bails on the < k share count first
        );
        assert!(combo_wrong_k.is_err());
    }

    // Share size does not depend on secret length.
    #[test]
    fn test_shamir_length_hiding() {
        let secret_short = b"abc";
        let secret_long = b"this is a much longer secret, but still under 4062 bytes";
        let shares_short = split(secret_short, 2, 2).unwrap();
        let shares_long = split(secret_long, 2, 2).unwrap();
        assert_eq!(shares_short[0].len(), shares_long[0].len());
    }

    // Secret too long is rejected.
    #[test]
    fn test_shamir_secret_too_long() {
        let secret = vec![0u8; MAX_SECRET_LEN + 1];
        assert!(split(&secret, 2, 2).is_err());
    }

    // Secret at max length round-trips correctly.
    #[test]
    fn test_shamir_max_secret_length() {
        let secret = vec![0xABu8; MAX_SECRET_LEN];
        let shares = split(&secret, 2, 3).unwrap();
        let combo = combine(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        assert_eq!(combo.as_slice(), secret.as_slice());
    }

    // Empty secret round-trips correctly.
    #[test]
    fn test_shamir_empty_secret() {
        let secret: &[u8] = b"";
        let shares = split(secret, 2, 3).unwrap();
        let combo = combine(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        assert_eq!(combo.as_slice(), secret);
    }

    // Combine with wrong K fails: Lagrange produces a bad payload, digest
    // check catches it.
    #[test]
    fn test_shamir_wrong_k() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        assert!(combine(&[shares[0].clone(), shares[1].clone()], 2).is_err());
    }

    // Duplicate x values are rejected.
    #[test]
    fn test_shamir_duplicate_x_rejected() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        // Replace shares[1]'s x with shares[0]'s x.
        let mut dup = shares[1].clone();
        dup[1] = shares[0][1];
        assert!(combine(&[shares[0].clone(), dup, shares[2].clone()], 3,).is_err());
    }

    // Malformed share lengths are rejected.
    #[test]
    fn test_shamir_malformed_length() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        // Too short.
        let mut short = shares[0].clone();
        short.truncate(10);
        assert!(combine(&[short, shares[1].clone(), shares[2].clone()], 3).is_err());
        // Too long; trailing bytes appended.
        let mut long = shares[0].clone();
        long.push(0xFF);
        assert!(combine(&[long, shares[1].clone(), shares[2].clone()], 3).is_err());
    }

    // Wrong share format version is rejected.
    #[test]
    fn test_shamir_wrong_version() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        let mut bad_ver = shares[0].clone();
        bad_ver[0] = 0x01; // not SHARE_FORMAT_VERSION
        assert!(combine(&[bad_ver, shares[1].clone(), shares[2].clone()], 3).is_err());
    }

    // x=0 is rejected.
    #[test]
    fn test_shamir_x_zero_rejected() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        let mut bad_x = shares[0].clone();
        bad_x[1] = 0;
        assert!(combine(&[bad_x, shares[1].clone(), shares[2].clone()], 3).is_err());
    }

    // With k_expected > actual_k but enough shares, Lagrange still
    // reproduces f(x). Not a leak: the caller already has >= K shares.
    #[test]
    fn test_shamir_wrong_k_with_enough_shares() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        // 5 shares available, caller claims k=5 when actual k=3.
        let all5: Vec<Vec<u8>> = shares.to_vec();
        let result = combine(&all5, 5);
        assert!(
            result.is_ok(),
            "combine with k=5 on k=3 shares should succeed (interpolation uniqueness), got: {:?}",
            result.err()
        );
        let recovered = result.unwrap();
        assert_eq!(
            recovered.as_slice(),
            secret,
            "combine with k=5 on k=3 shares should recover the original secret"
        );
    }

    #[test]
    fn test_gmul_basic() {
        assert_eq!(gmul(0, 0), 0);
        assert_eq!(gmul(1, 1), 1);
        assert_eq!(gmul(2, 3), 6);
        assert_eq!(gmul(0x53, 0xca), 0x01); // 0x53 is the AES inverse of 0xca
    }

    // gmul against log/exp tables, all 256*256 inputs.
    #[test]
    fn test_gmul_exhaustive() {
        let mut exp_table = [0u8; 256];
        let mut log_table = [0u8; 256];
        let mut x: u16 = 1;
        for (i, exp_slot) in exp_table.iter_mut().enumerate().take(255) {
            *exp_slot = x as u8;
            log_table[x as usize] = i as u8;
            let mut new_x = (x << 1) ^ x;
            if new_x & 0x100 != 0 {
                new_x ^= 0x11b;
            }
            x = new_x & 0xff;
        }
        exp_table[255] = exp_table[0];
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let expected = if a == 0 || b == 0 {
                    0u8
                } else {
                    let log_sum =
                        ((log_table[a as usize] as u16) + log_table[b as usize] as u16) % 255;
                    exp_table[log_sum as usize]
                };
                assert_eq!(gmul(a, b), expected, "gmul({}, {})", a, b);
            }
        }
    }

    // ginv inverts every nonzero input.
    #[test]
    fn test_ginv_correctness() {
        for a in 1..=255u8 {
            let inv = ginv_checked(a).unwrap();
            assert_eq!(gmul(a, inv), 1, "ginv({})", a);
        }
        assert!(ginv_checked(0).is_err());
    }

    #[test]
    fn test_is_zero_u8() {
        assert_eq!(is_zero_u8(0), 1);
        for a in 1..=255u8 {
            assert_eq!(is_zero_u8(a), 0, "is_zero_u8({})", a);
        }
    }

    // ct_eq_u8 on equal-length inputs.
    #[test]
    fn test_ct_eq_u8() {
        assert_eq!(ct_eq_u8(&[], &[]), 1);
        assert_eq!(ct_eq_u8(&[1, 2, 3], &[1, 2, 3]), 1);
        assert_eq!(ct_eq_u8(&[1, 2, 3], &[1, 2, 4]), 0);
        assert_eq!(ct_eq_u8(&[1, 2, 3], &[0, 2, 3]), 0);
        assert_eq!(ct_eq_u8(&[0xFF; 32], &[0xFF; 32]), 1);
        assert_eq!(ct_eq_u8(&[0xFF; 32], &[0xFE; 32]), 0);
    }
}
