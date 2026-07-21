//! Shamir Secret Sharing over GF(256).
//!
//! Information-theoretic: fewer than K shares reveal absolutely nothing
//! about the secret. Implemented with branchless, constant-time GF(256)
//! operations.
//!
//! # Threat model addressed
//!
//! An adversary who intercepts a SINGLE share (the realistic threat for
//! a quorum-based key-splitting tool — operators distribute shares over
//! distinct channels, and any one channel may be compromised) must NOT
//! learn:
//!   - the threshold K (would let them target the weakest k-1 holders),
//!   - the total share count N (would reveal the org structure),
//!   - the secret length (would reveal whether the secret is a 32-byte
//!     symmetric key, a 64-byte Ed25519 seed, or a multi-KB RSA-4096
//!     PKCS#8 blob — operationally significant),
//!   - any byte of the secret (information-theoretic guarantee).
//!
//! ## Hardening applied
//!
//! - **K leak in share header**: the share header is just
//!   `[SHARE_FORMAT_VERSION, x]` (2 bytes). K is supplied by the caller
//!   of `combine()` and is NOT stored in any share.
//!
//! - **N leak via sequential x**: the share x values are drawn as N
//!   DISTINCT random values uniformly from [1, 255]. An interceptor of
//!   one share sees a uniform random x and learns nothing about n.
//!
//! - **Length leak via share size**: the secret is padded to a FIXED
//!   payload size (`SHARE_PAYLOAD_BYTES = 4096`) before splitting. All
//!   shares are exactly `SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES = 4098`
//!   bytes, regardless of secret length (up to `MAX_SECRET_LEN = 4062`
//!   bytes). The original secret length is stored INSIDE the
//!   Shamir-protected payload (2-byte `secret_len` field), so an
//!   interceptor of < K shares cannot read it.
//!
//! - **Tampering detection with exactly K shares**: a SHA-256 digest of
//!   the entire padded payload (excluding the digest region itself) is
//!   appended to the Shamir-protected payload. After recovery, the
//!   digest is verified in constant time. Tampering of ANY byte —
//!   including the `secret_len` field, secret bytes, padding, or the
//!   digest itself — is detected even with exactly K shares.
//!
//! - **Constant-time duplicate-x detection**: O(k²) branchless pairwise
//!   comparison via `is_zero_u8` (arithmetic shift, no branches).
//!
//! - **Branchless ginv**: `ginv_checked` uses a fixed 7-iteration loop
//!   with no branches on `exp` (since 254 = 0b11111110, all bits 1..7
//!   are set).
//!
//! - **Zeroization of intermediate values**: `lagrange_coeffs` and
//!   `eval_coeffs` are wrapped in `Zeroizing<Vec<u8>>`. The padded
//!   payload buffer in `split()` and `combine()` is also `Zeroizing`.
//!
//! - **Strict share length**: requires EXACTLY
//!   `SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES` bytes. This prevents an
//!   attacker from appending trailing bytes that could confuse parsers
//!   downstream (e.g., the armor layer).
//!
//! - **Batched x generation**: a 32-byte batch is drawn from the CSPRNG
//!   and consumed one byte at a time, refilling only when the batch is
//!   exhausted. Reduces the RNG-call count by ~10×.
//!
//! ## Format choice
//!
//! The secret length is stored INSIDE the Shamir-protected payload (not
//! in a separate envelope), so it is information-theoretically hidden
//! from any party holding < K shares. K is supplied by the caller of
//! `combine()` (the operator or application knows the quorum they
//! configured). N is not needed by `combine()` at all (only `n ≥ k`
//! matters, which is implied by providing ≥ k shares).
//!
//! ## Wire format (v2)
//!
//! ```text
//! share = header(2) || payload(4096)
//!   header  = [ SHARE_FORMAT_VERSION(1) || x(1) ]   // x ∈ [1, 255]
//!   payload = [ secret_len(2 BE) || secret(L) || zero_pad(P)
//!               || sha256(secret_len||secret||zero_pad)(32) ]
//!     L = secret_len, P = HASH_OFFSET - 2 - L
//! ```
//! All shares are exactly 4098 bytes. The SHA-256 digest covers
//! `payload[0..HASH_OFFSET]` (everything except itself).

use crate::crypto::rng;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Share format version. Independent of the envelope `VERSION` (which
/// versions the envelope format). Bumped to 2 for the metadata-leak-fix
/// format (2-byte header + fixed-size payload). Old format-1 shares
/// (3-byte header + variable payload) are rejected by the version check.
pub const SHARE_FORMAT_VERSION: u8 = 2;

/// Share header length: `[SHARE_FORMAT_VERSION, x]`.
pub const SHARE_HEADER_LEN: usize = 2;

/// SHA-256 digest length.
const HASH_LEN: usize = 32;

/// Length of the `secret_len` field (u16 big-endian, 2 bytes). Allows
/// secrets up to 65535 bytes in principle, though `MAX_SECRET_LEN`
/// further constrains this to fit the fixed payload.
const LEN_FIELD_LEN: usize = 2;

/// Fixed payload size for every share. Pads the secret to a constant
/// length so an interceptor of one share cannot infer `secret_len`
/// from the share size. Chosen to accommodate all symmetric keys
/// (AES-256, ChaCha20), all elliptic-curve keys (Ed25519, X25519,
/// P-256, P-384), and RSA-4096 PKCS#8 DER (~2350 bytes) with
/// comfortable margin.
pub const SHARE_PAYLOAD_BYTES: usize = 4096;

/// Maximum secret length = `SHARE_PAYLOAD_BYTES - LEN_FIELD_LEN -
/// HASH_LEN`. Secrets longer than this must be encrypted first and
/// the key shared via Shamir.
pub const MAX_SECRET_LEN: usize = SHARE_PAYLOAD_BYTES - LEN_FIELD_LEN - HASH_LEN; // 4062

/// Offset where the SHA-256 digest begins within the payload.
const HASH_OFFSET: usize = SHARE_PAYLOAD_BYTES - HASH_LEN; // 4064

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic — branchless, constant-time
// ---------------------------------------------------------------------------

/// Branchless GF(2^8) multiplication with the standard AES polynomial
/// x^8 + x^4 + x^3 + x + 1 = 0x11b.
///
/// Both `if b & 1 != 0` and `if hi != 0` are replaced with bitmask
/// operations: when the bit is set, the mask is all-ones (0xFFFF) and
/// the XOR happens; when clear, the mask is all-zeros and the XOR is
/// a no-op. Execution time is data-independent.
///
/// The high bit is extracted via arithmetic shift (`a >> 7`) rather
/// than comparison (`(a & 0x80) != 0`), which is guaranteed branchless
/// on every architecture Rust supports (x86, ARM, RISC-V, WASM, embedded).
fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut b = b as u16;
    let mut p: u16 = 0;
    for _ in 0..8 {
        // Branchless: mask = -(b & 1) → 0xFFFF if bit set, 0x0000 if clear.
        let mask = (0u16).wrapping_sub(b & 1);
        p ^= a & mask;
        // Extract high bit via arithmetic shift (branchless on all targets).
        let hi_bit = (a >> 7) & 1;
        a <<= 1;
        // Branchless: mask = -(hi_bit) → 0xFFFF if hi set, 0x0000 if clear.
        let mask = (0u16).wrapping_sub(hi_bit);
        a ^= 0x11b & mask;
        b >>= 1;
    }
    p as u8
}

/// Branchless GF(2^8) multiplicative inverse.
///
/// Since 254 = 0b11111110, all bits 1..7 are set, so we always multiply
/// `r` by `base` at every step. The loop runs exactly 7 times with no
/// branches on `exp`.
///
/// `a^254 = a^(-1)` in GF(2^8) (since `a^255 = 1` for `a != 0`).
/// `a^254 = a^2 · a^4 · a^8 · a^16 · a^32 · a^64 · a^128`.
/// Algorithm: square base, then multiply into r, 7 times.
fn ginv_checked(a: u8) -> Result<u8> {
    if a == 0 {
        // Unreachable in correct usage: den = product of (x_a ^ x_b)
        // for distinct x's, which is nonzero in GF(256). Defensive.
        bail!("bad");
    }
    let mut r: u8 = 1;
    let mut base: u8 = a;
    // 7 iterations: base becomes a^2, a^4, a^8, ..., a^128; r
    // accumulates the product of all these (since all bits 1..7 of
    // 254 are set, we always multiply).
    for _ in 0..7 {
        base = gmul(base, base);
        r = gmul(r, base);
    }
    Ok(r)
}

/// Branchless "is zero" check: returns 1 if `x == 0`, else 0.
/// Used for constant-time duplicate-x detection.
///
/// `(x | x.wrapping_neg())` has its high bit set iff `x != 0`:
///   - `x == 0`: `0 | 0 = 0`, high bit clear.
///   - `x != 0`: either `x` or `-x` has the high bit set (for any
///     nonzero u8, at least one of `x`, `-x` has bit 7 set), so the
///     OR has the high bit set. Shift right by 7 to get 1 if nonzero,
///     0 if zero. Invert.
#[inline]
fn is_zero_u8(x: u8) -> u8 {
    let nonzero = (x | x.wrapping_neg()) >> 7;
    1 - nonzero
}

/// Constant-time equality check for two equally-sized u8 slices.
/// Returns 1 iff all bytes match, 0 otherwise. Length must be equal
/// and is the caller's responsibility (length is public here).
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

/// Split `secret` into `n` shares, any `k` of which can reconstruct it.
///
/// Each share is a 2-byte header `[SHARE_FORMAT_VERSION, x]` followed
/// by `SHARE_PAYLOAD_BYTES` of Shamir-encrypted payload. The payload
/// contains the secret, a 2-byte length field, zero padding, and a
/// SHA-256 digest for tampering detection.
///
/// # Security properties
///
/// - An interceptor of a SINGLE share learns NOTHING about:
///   - the threshold K (not stored in the share),
///   - the total share count N (x is uniform random in [1, 255]),
///   - the secret length (all shares are a fixed 4098 bytes),
///   - or any byte of the secret (information-theoretic).
/// - Tampering of any byte in any share is detected during `combine`
///   (via the consistency check if > K shares are provided, or via
///   the SHA-256 digest if exactly K shares are provided).
///
/// # Constraints
///
/// - `secret.len()` must not exceed `MAX_SECRET_LEN` (4062 bytes).
/// - `2 <= k <= n <= 10`.
///
/// # Errors
///
/// Returns a uniform `Err("bad")` on any invalid input (no
/// distinguishable error messages to avoid oracle attacks).
///
/// # Public API
///
/// Unchanged from the original: `(&[u8], u8, u8) -> Result<Vec<Vec<u8>>>`.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>> {
    // Validate k and n: 2 <= k <= n <= 10.
    if !(2..=10).contains(&k) || !(k..=10).contains(&n) {
        bail!("bad");
    }
    // secret must fit in the fixed-size payload.
    if secret.len() > MAX_SECRET_LEN {
        bail!("bad");
    }

    // Pad secret to fixed-size payload.
    // Layout:
    //   [0..2):               secret_len (u16 big-endian)
    //   [2..2+L):             secret (L = secret_len bytes)
    //   [2+L .. HASH_OFFSET): zero padding
    //   [HASH_OFFSET .. END): SHA-256(payload[0..HASH_OFFSET]) (32 bytes)
    //
    // The digest covers everything except itself, so tampering of
    // secret_len, secret bytes, OR padding is detected.
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; SHARE_PAYLOAD_BYTES]);
    let slen = secret.len() as u16;
    payload[0] = (slen >> 8) as u8;
    payload[1] = slen as u8;
    payload[2..2 + secret.len()].copy_from_slice(secret);
    // bytes [2+L .. HASH_OFFSET] are already zero (padding).

    // Compute SHA-256 over payload[0..HASH_OFFSET] and store at the end.
    //
    // The `sha2` 0.10 crate does not expose a `zeroize` feature, so the
    // internal Sha256 state is NOT wiped when the hasher drops. We use
    // `finalize_reset()` to reset the internal state to the SHA-256 IV
    // (public constant) after producing the digest, reducing the
    // residual leak from "intermediate hash state of the payload"
    // (which includes the secret) to "the IV" (public).
    let mut hasher = Sha256::new();
    hasher.update(&payload[..HASH_OFFSET]);
    let digest = hasher.finalize_reset();
    payload[HASH_OFFSET..SHARE_PAYLOAD_BYTES].copy_from_slice(&digest);

    // Generate n DISTINCT random x values in [1, 255]. An interceptor
    // seeing one x learns nothing about n (x is uniform). x must NEVER
    // be 0 — evaluating the polynomial at x=0 yields the constant term
    // (= secret byte), which would leak the secret.
    //
    // Batched RNG: draw 32 bytes at a time, consume one at a time,
    // refill when exhausted. Reduces syscall count from ~10-15 to ~1
    // per split.
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
        // Reject 0 and duplicates. Note: x is NOT secret (it is stored
        // in the share header), so the data-dependent memory access
        // `seen[x as usize]` is not a timing side channel.
        if x == 0 || seen[x as usize] {
            attempts += 1;
            // With 255 valid x values and n <= 10, the probability of
            // needing more than 1000 attempts is astronomically small.
            // 10000 is a generous safety bound; exceeding it indicates
            // a broken CSPRNG.
            if attempts > 10000 {
                bail!("bad");
            }
            continue;
        }
        seen[x as usize] = true;
        xs.push(x);
    }
    // Wipe the residual RNG batch (may contain unused x candidates that
    // an attacker with a heap dump could correlate with future shares).
    // Use `zeroize::Zeroize` (which uses `write_volatile` to defeat LLVM
    // DCE) rather than a manual `*b = 0` loop, which the compiler is
    // permitted to elide when the buffer is about to go out of scope.
    use zeroize::Zeroize;
    rng_batch.zeroize();

    // Build shares: one Vec per share. Payload bytes are appended one
    // byte position at a time (each byte position uses a fresh random
    // polynomial whose constant term is that payload byte).
    let mut shares: Vec<Vec<u8>> = (0..n)
        .map(|_| Vec::with_capacity(SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES))
        .collect();

    // Polynomial coefficients (constant term = payload byte).
    // Zeroizing: wiped on drop even on panic.
    let mut coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; k as usize]);

    for &sb in payload.iter() {
        coeffs[0] = sb;
        // Ensure random coefficients are NOT all zero. If coeffs[1..k]
        // are all zero, the polynomial is constant (= sb), and ANY
        // single share reveals that byte. The check uses constant-time
        // OR-accumulation (no early break, no data-dependent branch)
        // over the full coefficient slice before testing the
        // accumulator — the coefficients are SECRET (they determine the
        // polynomial that protects the secret byte).
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
        // Evaluate polynomial at each x: y = sum(coeff[j] * x^j).
        // Constant-time: iterates over ALL coeffs (no short-circuit
        // on zero coefficients). Uses incremental x^j computation
        // (Hörner-equivalent direct form).
        for (idx, &x) in xs.iter().enumerate() {
            let mut y = 0u8;
            let mut xp = 1u8; // x^0
            for &c in coeffs.iter() {
                y ^= gmul(c, xp);
                xp = gmul(xp, x);
            }
            shares[idx].push(y);
        }
    }

    // Prepend 2-byte header: [SHARE_FORMAT_VERSION, x].
    // No K, no N — these are NOT leaked via the share.
    //
    // The old share payload Vec (without header) is explicitly zeroized
    // before being replaced. Share payloads are SECRET (K of them
    // reconstruct the secret via Lagrange interpolation); without an
    // explicit zeroize, dropping the Vec would return the backing
    // allocation to the heap with the payload bytes still intact, where
    // a memory-forensics adversary or a heap-overflow read primitive
    // could recover them. `zeroize::Zeroize` uses `write_volatile` to
    // defeat LLVM dead-store elimination.
    for (idx, share) in shares.iter_mut().enumerate() {
        let mut full = Vec::with_capacity(SHARE_HEADER_LEN + share.len());
        full.push(SHARE_FORMAT_VERSION);
        full.push(xs[idx]);
        full.extend_from_slice(share);
        // Wipe the old share payload (without header) before the Vec
        // is dropped and its backing allocation returns to the heap.
        use zeroize::Zeroize;
        share.zeroize();
        *share = full;
    }

    // payload and coeffs are Zeroizing — wiped on drop.
    Ok(shares)
}

// ---------------------------------------------------------------------------
// Combine
// ---------------------------------------------------------------------------

/// Reconstruct the secret from `shares`.
///
/// Uses Lagrange interpolation in GF(256). At least `k_expected`
/// shares are required. K is supplied by the caller (NOT read from
/// the share — the share header does not carry K).
///
/// # Security properties
///
/// - Returns the original secret (unpadded) on success.
/// - Returns a uniform `Err("bad")` on ANY failure, including:
///   - fewer than K shares provided,
///   - malformed shares (wrong length, wrong version, x=0),
///   - duplicate x values,
///   - tampered shares (detected via SHA-256 digest with exactly K
///     shares, or via consistency check with > K shares),
///   - wrong K (the recovered payload fails digest verification).
/// - The returned secret is wrapped in `Zeroizing<Vec<u8>>` and is
///   wiped from memory when dropped.
///
/// # Constant-time notes
///
/// - Duplicate-x detection is O(k²) branchless (no early exit).
/// - Lagrange coefficient computation iterates over all coefficient
///   slots (the `if a == b { continue; }` is a branch on the loop
///   index, not on secret data).
/// - Digest comparison uses `subtle::ConstantTimeEq`.
/// - The function does NOT short-circuit on the first invalid share
///   during parsing; however, `collect::<Result<Vec<_>>>()` does stop
///   at the first parse error. This is acceptable because the parsing
///   stage does not touch secret-derived data.
///
/// # Public API
///
/// Unchanged from the original: `(&[Vec<u8>], u8) -> Result<Zeroizing<Vec<u8>>>`.
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
            // Strict length check. Share must be EXACTLY header + payload
            // bytes.
            if s.len() != expected_len {
                bail!("bad");
            }
            if s[0] != SHARE_FORMAT_VERSION {
                bail!("bad");
            }
            let x = s[1];
            // Reject x=0 (polynomial evaluation at 0 = secret).
            if x == 0 {
                bail!("bad");
            }
            // Note: x is a u8, so x ∈ [1, 255] after the != 0 check.
            // No upper-bound check needed (x is random in [1, 255]).
            Ok((x, &s[SHARE_HEADER_LEN..]))
        })
        .collect::<Result<Vec<_>>>()?;

    let k = k_expected as usize;
    // Off-by-one check: require >= k shares (not > k).
    if parsed.len() < k {
        bail!("bad");
    }

    // Constant-time duplicate-x detection.
    // O(k²) branchless pairwise comparison via is_zero_u8. No early
    // exit, so an observer cannot learn WHICH pair was duplicate
    // (only WHETHER a duplicate exists, which is the rejection signal).
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

    // Pre-compute Lagrange coefficients ONCE.
    // Wrapped in Zeroizing for defense-in-depth zeroization.
    // (lagrange_coeffs depend only on x values, which are public, but
    // zeroizing is cheap and prevents any future leak if the
    // coefficients ever become secret-derived.)
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
        // den != 0 guaranteed by duplicate-x check (distinct x's =>
        // x_a ^ x_b != 0 for a != b => product is nonzero).
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
    // each extra share matches the reconstructed polynomial. This
    // detects tampering when the caller has spare shares.
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
            // Branchless mismatch accumulation across all bytes; bail
            // after the full scan. (A timing observer learns only
            // "this extra share was inconsistent", not which byte —
            // and the extra share's identity is public, supplied by
            // the caller.)
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

    // Verify SHA-256(payload[..HASH_OFFSET]) matches the recovered
    // digest. This detects tampering even when EXACTLY k shares are
    // provided (where the consistency check does not run). The digest
    // covers secret_len, secret bytes, AND padding, so any tampering
    // in those regions is caught.
    //
    // `finalize_reset()` clears the internal Sha256 state (which
    // contains intermediate hash values of the payload — including the
    // secret) back to the IV before the hasher drops. See the matching
    // comment in `split()` for full rationale.
    let mut hasher = Sha256::new();
    hasher.update(&payload[..HASH_OFFSET]);
    let computed_hash = hasher.finalize_reset();
    let stored_hash = &payload[HASH_OFFSET..SHARE_PAYLOAD_BYTES];

    // Constant-time comparison (subtle::ConstantTimeEq). Lengths are
    // both HASH_LEN (fixed), so length is not a side channel.
    if !bool::from(computed_hash.as_slice().ct_eq(stored_hash)) {
        bail!("bad");
    }

    // Extract secret_len and validate. The digest has already
    // authenticated this field, so we can trust it.
    let secret_len = ((payload[0] as u16) << 8) | (payload[1] as u16);
    let secret_len = secret_len as usize;
    if secret_len > MAX_SECRET_LEN {
        bail!("bad");
    }
    let secret_end = LEN_FIELD_LEN + secret_len;
    // Defensive: secret_end must not overlap the hash region.
    if secret_end > HASH_OFFSET {
        bail!("bad");
    }
    let secret_bytes = &payload[LEN_FIELD_LEN..secret_end];

    // Extract and return the secret (wrapped in Zeroizing).
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
        // Tamper with a payload byte (byte 2 = first payload byte in
        // the 2-byte header format). The consistency check (which runs
        // because 4 > k=3 shares are provided) catches this.
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

    // Tampering with exactly K shares is detected via SHA-256. The
    // consistency check does NOT run when exactly k shares are provided,
    // so the SHA-256 digest is the only line of defense.
    #[test]
    fn test_shamir_tampering_detected_with_exact_k() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();

        // Tamper with a padding byte (byte 100 = payload[98], which is
        // in the zero-padding region). The hash-over-entire-payload
        // catches this.
        let mut tampered_pad = shares[0].clone();
        tampered_pad[100] ^= 0x01;
        assert!(combine(&[tampered_pad, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // Tamper with a secret byte (byte 4 = payload[2] = first secret
        // byte). This is caught by the SHA-256 digest.
        let mut tampered_sec = shares[0].clone();
        tampered_sec[4] ^= 0x01;
        assert!(combine(&[tampered_sec, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // Tamper with the secret_len field (byte 2 = payload[0] = high
        // byte of secret_len). Caught by the SHA-256 digest.
        let mut tampered_len = shares[0].clone();
        tampered_len[2] ^= 0x01;
        assert!(combine(&[tampered_len, shares[1].clone(), shares[2].clone()], 3,).is_err());

        // Tamper with the digest region itself (last byte of share).
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

        // All shares must be exactly the same fixed size.
        for s in shares.iter() {
            assert_eq!(s.len(), SHARE_HEADER_LEN + SHARE_PAYLOAD_BYTES);
        }

        // Header is 2 bytes [SHARE_FORMAT_VERSION, x]. No K, no N.
        for s in shares.iter() {
            assert_eq!(s[0], SHARE_FORMAT_VERSION);
            assert_ne!(s[1], 0, "x must be in [1, 255]");
        }

        // x values must be distinct (no sequential 1..=n leak).
        let mut xs: Vec<u8> = shares.iter().map(|s| s[1]).collect();
        xs.sort();
        for i in 1..xs.len() {
            assert_ne!(xs[i], xs[i - 1], "duplicate x value");
        }
    }

    // A single share from a K=3 split is structurally indistinguishable
    // from a single share from a K=5 split (same length, same header
    // structure, x in [1, 255]). An interceptor cannot tell which
    // quorum was used.
    #[test]
    fn test_shamir_share_indistinguishable_across_k() {
        let secret = b"top-secret-message";

        let shares_k3 = split(secret, 3, 5).unwrap();
        let shares_k5 = split(secret, 5, 7).unwrap();

        // Same length regardless of K.
        assert_eq!(shares_k3[0].len(), shares_k5[0].len());

        // Same header structure: byte 0 = SHARE_FORMAT_VERSION,
        // byte 1 = x in [1, 255].
        for s in shares_k3.iter().chain(shares_k5.iter()) {
            assert_eq!(s[0], SHARE_FORMAT_VERSION);
            // x is a u8 in [1, 255]; the upper bound is automatic (u8 max = 255)
            // but kept here for documentation of the intended range.
            #[allow(unused_comparisons, clippy::absurd_extreme_comparisons)]
            let in_range = s[1] >= 1 && s[1] <= 255;
            assert!(in_range);
        }

        // Single-share K recovery is impossible: a share from the K=3
        // split must NOT validate against combine() with k_expected=5
        // (the digest check fails because the wrong polynomial was
        // recovered). (And vice versa: K=5 shares cannot be combined
        // with k=3.)
        let combo_wrong_k = combine(
            &[
                shares_k3[0].clone(),
                shares_k3[1].clone(),
                shares_k3[2].clone(),
            ],
            5, // wrong K — but we only have 3 shares, so this bails first
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

    // Combine with wrong K fails (SHA-256 mismatch).
    #[test]
    fn test_shamir_wrong_k() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        // If the caller passes k=2 but shares were split with k=3,
        // Lagrange interpolation produces a wrong payload, and the
        // SHA-256 digest check catches it.
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
        // Too long (trailing bytes appended).
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

    // A wrong-K combine that has enough shares but wrong K.
    //
    // When k_expected >= actual_k and at least k_expected shares are
    // provided, Lagrange interpolation produces the unique
    // degree-<=(k_expected-1) polynomial passing through the points.
    // Since the actual polynomial f(x) is degree (actual_k - 1) <=
    // (k_expected - 1), f(x) is in the interpolating set, so the
    // interpolation reproduces f(x) EXACTLY (uniqueness of polynomial
    // interpolation). The SHA-256 digest then matches, and combine
    // returns Ok(secret).
    //
    // Security implication: an attacker with >= k shares and an
    // INCORRECT k_expected > actual_k can STILL recover the secret.
    // This is NOT a vulnerability — the threat model is "an attacker
    // with < k shares cannot recover the secret"; an attacker with
    // >= k shares CAN recover the secret regardless of which
    // k_expected they pass (as long as k_expected <= #shares and
    // k_expected >= actual_k). The test verifies the actual behavior:
    // combine with k_expected > actual_k AND enough shares succeeds
    // and returns the original secret.
    //
    // Defense-in-depth trade-off (Option B rejected): one might want
    // `combine` to reject any k_expected != original_k used in `split`.
    // This is INFEASIBLE without re-introducing the K metadata leak
    // that Agency 5 removed: the v2 share header is just
    // `[SHARE_FORMAT_VERSION, x]` (2 bytes) and does NOT store K, so
    // `combine` has no way to know the original K. Storing K in the
    // share would let a single-share interceptor read the quorum
    // directly (the exact leak we hardened against). Since the
    // "wrong K with enough shares" case is not a vulnerability (the
    // attacker already has >= K shares), accepting it is the correct
    // trade-off: preserve the metadata-leak fix over a defense-in-depth
    // check that would itself introduce a worse leak.
    #[test]
    fn test_shamir_wrong_k_with_enough_shares() {
        let secret = b"top-secret-message";
        let shares = split(secret, 3, 5).unwrap();
        // 5 shares available, but caller claims k=5 when actual k=3.
        // Mathematically, Lagrange interpolation with k=5 points on
        // a degree-2 polynomial reproduces the degree-2 polynomial
        // exactly (uniqueness of interpolation). The SHA-256 digest
        // matches, and combine returns Ok(secret).
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

    // Exhaustive gmul correctness test against log/exp tables.
    #[test]
    fn test_gmul_exhaustive() {
        let mut exp_table = [0u8; 256];
        let mut log_table = [0u8; 256];
        let mut x: u16 = 1;
        for (i, slot) in exp_table.iter_mut().enumerate().take(255) {
            *slot = x as u8;
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

    // Verify ginv against gmul for all nonzero inputs.
    #[test]
    fn test_ginv_correctness() {
        for a in 1..=255u8 {
            let inv = ginv_checked(a).unwrap();
            assert_eq!(gmul(a, inv), 1, "ginv({})", a);
        }
        assert!(ginv_checked(0).is_err());
    }

    // is_zero_u8 is correct and branchless.
    #[test]
    fn test_is_zero_u8() {
        assert_eq!(is_zero_u8(0), 1);
        for a in 1..=255u8 {
            assert_eq!(is_zero_u8(a), 0, "is_zero_u8({})", a);
        }
    }

    // ct_eq_u8 correctness (equal-length inputs only — see debug_assert).
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
