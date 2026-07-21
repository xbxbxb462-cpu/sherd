//! Key commitment (HMAC-SHA256-truncated).
//!
//! commit_tag = HMAC-SHA256(commitKey, "FORTIS-v7-commit-tag\x00"
//!                          || fixed_header || salt || base_iv
//!                          || chunk_count || ct_total_len
//!                          || ct_first_chunk_hash)[0..15]
//!
//! The commit tag is verified before any plaintext is released. For
//! uniform-timing reasons `decrypt_stream` always runs regardless of
//! commit_ok, but the commit tag is what determines whether the result
//! is ACCEPTED.

use crate::crypto::constants::*;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation prefix for the commit tag HMAC.
///
/// This prevents the commit tag from being confused with any other HMAC
/// usage in the codebase (HKDF-Extract, HKDF-Expand both use HMAC-SHA256
/// internally with different keys, but explicit domain separation is
/// defense in depth).
const COMMIT_TAG_DOMAIN_SEP: &[u8] = b"FORTIS-v7-commit-tag\x00";

/// Compute the 16-byte commitment tag.
///
/// Inputs:
///   - `commit_key`: the per-slot commit key derived via HKDF-Expand
///   - `fixed_header`: the 16-byte fixed header (magic + version + flags + ...)
///   - `salt`: the per-slot 32-byte salt
///   - `base_iv`: the per-slot 12-byte base IV
///   - `chunk_count`: number of chunks in the ciphertext
///   - `ct_total_len`: total ciphertext length (sum of all chunk ct lengths)
///   - `ct_first_chunk_hash`: SHA-256 hash of the first chunk's ciphertext
///     (32 bytes). For empty ciphertexts, pass a zero-filled array.
///
/// The tag now covers `ct_first_chunk_hash`, a SHA-256 hash of the first
/// chunk's ciphertext. This binds the tag to actual ciphertext content
/// (not just metadata), preventing the "invisible salamander" attack
/// where an attacker swaps ciphertexts between two files with the same
/// metadata. We hash only the first chunk (not all chunks) for
/// performance — the first chunk is the most position-sensitive
/// (chunk_index=0 has the file's metadata prefix), and any tampering
/// with later chunks will be caught by the AES-GCM tag verification
/// during decrypt_stream.
///
/// The full 32-byte HMAC output is held in a `Zeroizing` wrapper so the
/// second 16 bytes (which are computed but discarded) are wiped from the
/// stack before return.
pub(crate) fn compute_commit_tag(
    commit_key: &[u8],
    fixed_header: &[u8; FIXED_HEADER_LEN],
    salt: &[u8; SALT_LEN],
    base_iv: &[u8; IV_LEN],
    chunk_count: u32,
    ct_total_len: u32,
    ct_first_chunk_hash: &[u8; 32],
) -> Result<[u8; COMMIT_TAG_LEN]> {
    // Enforce commit_key length at runtime. The commit_key is always
    // 32 bytes (derived via HKDF-Expand with length=32); a key of a
    // different length indicates a bug in the KDF layer.
    if commit_key.len() != 32 {
        bail!("bad");
    }
    let mut mac = HmacSha256::new_from_slice(commit_key).map_err(|_| anyhow::anyhow!("bad"))?;
    // Domain-separation prefix.
    mac.update(COMMIT_TAG_DOMAIN_SEP);
    mac.update(fixed_header);
    mac.update(salt);
    mac.update(base_iv);
    mac.update(&chunk_count.to_be_bytes());
    mac.update(&ct_total_len.to_be_bytes());
    // Bind the tag to actual ciphertext content.
    mac.update(ct_first_chunk_hash);
    // Hold the full 32-byte HMAC output in a Zeroizing-wrapped fixed-size
    // array (not a Vec). Copying the GenericArray into a heap Vec would
    // leave the stack copy un-wiped; using a `Zeroizing<[u8; 32]>` keeps
    // the data on the stack AND wipes it on drop.
    //
    // The intermediate `full_bytes` (a GenericArray<u8, U32> on the
    // stack) is explicitly zeroized after the copy, so the second 16
    // bytes of the HMAC output (computed but discarded) do not linger
    // on the stack until the function returns. We zeroize via
    // `as_mut_slice()`, which returns a `&mut [u8]`; the zeroize crate
    // implements `Zeroize for [u8]` via volatile writes. GenericArray
    // itself does not implement Zeroize directly (sha2 v0.10 has no
    // `zeroize` feature and the zeroize crate's blanket impl requires
    // the `alloc` feature on generic-array, which is not in our
    // dependency tree).
    let mut full_bytes = mac.finalize().into_bytes();
    let mut full: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    full.copy_from_slice(&full_bytes);
    // Explicitly zeroize the intermediate GenericArray. GenericArray<u8, U32>
    // does not implement Zeroize directly (sha2 v0.10 has no `zeroize`
    // feature and the zeroize crate's blanket impl requires the `alloc`
    // feature on generic-array, which is not in our dependency tree).
    // However, `as_mut_slice()` returns `&mut [u8]`, and `&mut [u8]` has
    // `Zeroize` via `impl<Z> Zeroize for [Z]` (volatile writes). This
    // wipes the GenericArray's backing storage.
    use zeroize::Zeroize;
    full_bytes.as_mut_slice().zeroize();
    let mut tag = [0u8; COMMIT_TAG_LEN];
    tag.copy_from_slice(&full[..COMMIT_TAG_LEN]);
    // `full` is Zeroizing<[u8; 32]> — wiped on drop (both halves of the
    // HMAC output). `full_bytes` was explicitly zeroized above.
    Ok(tag)
}

/// Compute the SHA-256 hash of the first chunk's ciphertext for use in
/// the commit tag. Returns a 32-byte array.
///
/// The hash is computed over the raw ciphertext bytes (including the GCM
/// tag of the first chunk), so any modification to either the ciphertext
/// OR the GCM tag is detected by the commit tag verification.
///
/// The hash is an UNKEYED SHA-256 with a domain-separation prefix. It
/// does not use the commit_key — the security comes from the commit_tag
/// HMAC binding the hash into the authenticated data.
pub(crate) fn compute_first_chunk_hash(first_chunk_ct: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"FORTIS-v7-first-chunk-hash\x00"); // domain separation
    hasher.update(first_chunk_ct);
    // The `sha2` 0.10 crate does not expose a `zeroize` feature, so the
    // internal Sha256 state (8 × u32 working state + 64-byte block buffer
    // + counter) is NOT wiped when the hasher drops. The state contains
    // intermediate hash values derived from the (attacker-controlled)
    // ciphertext, not from any secret — so the leak is a defense-in-depth
    // gap, not a direct secret compromise. We use `finalize_reset()`
    // instead of `finalize()` to reset the internal state to the SHA-256
    // IV (public constant) after producing the digest, reducing the
    // residual leak from "intermediate hash state" to "the IV". This is
    // not a substitute for true zeroization, but it is a meaningful
    // improvement over dropping the hasher with full intermediate state
    // intact.
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize_reset());
    out
}

/// Verify a commitment tag in constant time.
///
/// Returns `Ok(())` if the computed tag matches the expected tag, or
/// `Err` with a uniform "bad" message otherwise.
///
/// The return type is `Result<()>` rather than `Result<bool>`: any
/// failure (HMAC init error, tag mismatch) is treated as a uniform
/// `Err("bad")`, so callers cannot accidentally distinguish "tag
/// mismatch" from "HMAC init failed".
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_commit_tag(
    commit_key: &[u8],
    fixed_header: &[u8; FIXED_HEADER_LEN],
    salt: &[u8; SALT_LEN],
    base_iv: &[u8; IV_LEN],
    chunk_count: u32,
    ct_total_len: u32,
    ct_first_chunk_hash: &[u8; 32],
    expected_tag: &[u8; COMMIT_TAG_LEN],
) -> Result<()> {
    let computed = compute_commit_tag(
        commit_key,
        fixed_header,
        salt,
        base_iv,
        chunk_count,
        ct_total_len,
        ct_first_chunk_hash,
    )?;
    // Constant-time comparison. If mismatch, return uniform "bad" error.
    if !bool::from(computed.ct_eq(expected_tag)) {
        return Err(anyhow::anyhow!("bad"));
    }
    Ok(())
}
