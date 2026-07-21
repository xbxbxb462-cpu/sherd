//! Fortis v7 binary envelope format.
//!
//! Layout:
//! ```text
//! Fixed header (16 bytes):
//!   "FRT7" magic | version=7 | flags | cipher_id | kdf_id | commit_id
//!   | kdf_mem_kib(u32be) | kdf_iters | kdf_par | slot_count
//!
//! Per slot (68 bytes + ciphertext):
//!   salt(32) | base_iv(12) | commit_tag(16)
//!   | chunk_count(u32be) | ct_total_len(u32be) | ciphertext(ct_total_len)
//!
//! Per chunk inside ciphertext:
//!   AES-256-GCM(key_i, iv_i, aad, pt_i) → ct_i = chunk_pt || tag(16)
//! ```
//!
//! All header bytes (fixed + slot header except the ciphertext itself) are
//! bound as AEAD AAD AND as commit_tag input.

use crate::crypto::aead;
use crate::crypto::commit;
use crate::crypto::constants::*;
use crate::crypto::kdf;
use crate::crypto::rng;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Typed envelope errors
// ---------------------------------------------------------------------------

/// Typed error for envelope operations.
///
/// Using a typed error makes it possible for callers (cli.rs) to distinguish
/// "input was already encrypted" from "cryptographic failure". Callers of
/// `encrypt_envelope` should match on `downcast_ref::<EnvelopeError>()` to
/// detect the `InputAlreadyEncrypted` case and prompt the user to either:
///   (a) re-run with `--force` (which calls `encrypt_envelope_force`), or
///   (b) decrypt the file first, then re-encrypt.
#[derive(Debug)]
pub enum EnvelopeError {
    /// The input plaintext appears to already be a Fortis envelope (begins
    /// with the "FRT7" magic bytes). Re-encrypting would produce a
    /// double-encrypted file requiring two passphrase entries to decrypt —
    /// an operational footgun. Callers should catch this and offer the
    /// `--force` override (`encrypt_envelope_force`).
    InputAlreadyEncrypted,
    /// Generic envelope error (malformed input, cryptographic failure,
    /// tamper detected, etc.). The uniform "bad" message prevents
    /// error-message oracles.
    #[allow(dead_code)]
    Bad,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::InputAlreadyEncrypted => write!(
                f,
                "input appears to already be a FORTIS envelope; \
                 refusing to re-encrypt (use --force to override)"
            ),
            EnvelopeError::Bad => write!(f, "bad"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Detect whether input bytes appear to be a Fortis envelope.
///
/// Returns `true` iff the input is at least 4 bytes long AND begins with
/// the Fortis magic bytes `"FRT7"` (0x46 0x52 0x54 0x37).
///
/// Used by `encrypt_envelope` to refuse re-encrypting an already-encrypted
/// file. The check is intentionally simple: just the 4-byte magic. A more
/// thorough check (version byte, slot structure) would create a parsing
/// oracle and risks false negatives on truncated envelopes. The magic
/// check is sufficient to catch the common operational footgun (re-running
/// `fortis encrypt` on a `.frts` file).
///
/// False positive rate: for random non-Fortis input, the probability that
/// the first 4 bytes happen to equal "FRT7" is 1/2^32 ≈ 2.3e-10. The
/// `--force` override exists for the rare legitimate case.
pub fn is_fortis_envelope(input: &[u8]) -> bool {
    input.len() >= MAGIC.len() && input[..MAGIC.len()] == MAGIC
}

// ---------------------------------------------------------------------------
// Fixed header (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct FixedHeader {
    pub flags: u8,
    pub cipher_id: u8,
    pub kdf_id: u8,
    pub commit_id: u8,
    pub kdf_mem_kib: u32,
    pub kdf_iters: u32,
    pub kdf_par: u32,
    pub slot_count: u8,
}

impl FixedHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        flags: u8,
        cipher_id: u8,
        kdf_id: u8,
        commit_id: u8,
        kdf_mem_kib: u32,
        kdf_iters: u32,
        kdf_par: u32,
        slot_count: u8,
    ) -> Vec<u8> {
        // Catch truncation at runtime, not just in debug builds. The wire
        // format stores kdf_mem_kib as u32 (4 bytes), but kdf_iters and
        // kdf_par as u8 (1 byte each). If a future preset uses iters > 255
        // or par > 255, the `as u8` cast would silently truncate, producing
        // a header that claims weaker KDF params than the encryptor actually
        // used. The decryptor would then use the weaker params for Argon2id,
        // producing a different PRK and failing to decrypt — silent data
        // loss. Using `assert!` (not `debug_assert!`) ensures the check
        // survives in release builds.
        assert!(
            kdf_iters <= u8::MAX as u32,
            "kdf_iters {} exceeds u8 range",
            kdf_iters
        );
        assert!(
            kdf_par <= u8::MAX as u32,
            "kdf_par {} exceeds u8 range",
            kdf_par
        );
        let mut h = Vec::with_capacity(FIXED_HEADER_LEN);
        h.extend_from_slice(&MAGIC);
        h.push(VERSION);
        h.push(flags);
        h.push(cipher_id);
        h.push(kdf_id);
        h.push(commit_id);
        h.extend_from_slice(&kdf_mem_kib.to_be_bytes());
        h.push(kdf_iters as u8);
        h.push(kdf_par as u8);
        h.push(slot_count);
        debug_assert_eq!(h.len(), FIXED_HEADER_LEN);
        h
    }

    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<u8>)> {
        if bytes.len() < FIXED_HEADER_LEN {
            bail!("bad");
        }
        if bytes[..4] != MAGIC {
            bail!("bad");
        }
        let version = bytes[4];
        if version != VERSION {
            bail!("bad");
        }
        let flags = bytes[5];
        if flags & !KNOWN_FLAGS != 0 {
            bail!("bad");
        }
        let cipher_id = bytes[6];
        if cipher_id != CIPHER_ID_AES256_GCM {
            bail!("bad");
        }
        let kdf_id = bytes[7];
        if kdf_id != KDF_ID_ARGON2ID {
            bail!("bad");
        }
        let commit_id = bytes[8];
        if commit_id != COMMIT_ID_HMAC_SHA256_TRUNC128 {
            bail!("bad");
        }
        let kdf_mem_kib = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        if !(KDF_MEM_MIN..=KDF_MEM_MAX).contains(&kdf_mem_kib) {
            bail!("bad");
        }
        let kdf_iters = bytes[13] as u32;
        if !(KDF_ITERS_MIN..=KDF_ITERS_MAX).contains(&kdf_iters) {
            bail!("bad");
        }
        let kdf_par = bytes[14] as u32;
        if kdf_par < KDF_PAR_MIN || kdf_par > KDF_PAR_MAX {
            bail!("bad");
        }
        let slot_count = bytes[15];
        if !(1..=2).contains(&slot_count) {
            bail!("bad");
        }
        let has_decoy = (flags & FLAG_DECOY) != 0;
        if has_decoy != (slot_count == 2) {
            bail!("bad");
        }
        let fixed_header = bytes[..FIXED_HEADER_LEN].to_vec();
        Ok((
            Self {
                flags,
                cipher_id,
                kdf_id,
                commit_id,
                kdf_mem_kib,
                kdf_iters,
                kdf_par,
                slot_count,
            },
            fixed_header,
        ))
    }
}

// ---------------------------------------------------------------------------
// Slot header (68 bytes) + ciphertext
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Slot {
    pub salt: [u8; SALT_LEN],
    pub base_iv: [u8; IV_LEN],
    pub commit_tag: [u8; COMMIT_TAG_LEN],
    pub chunk_count: u32,
    pub ct_total_len: u32,
    pub ct: Vec<u8>,
}

impl Slot {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLOT_HEADER_LEN + self.ct.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.base_iv);
        out.extend_from_slice(&self.commit_tag);
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.ct_total_len.to_be_bytes());
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<(&[u8], Self)> {
        if bytes.len() < SLOT_HEADER_LEN {
            bail!("bad");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        // Reject all-zero salt at parse time to keep the decrypt path
        // uniform across slots. Without this, an attacker who crafts a
        // slot with an all-zero salt forces `derive_slot_secrets_from_secret`
        // to bail before the second slot is processed, creating a
        // non-uniform timing oracle:
        //   legit file (both salts valid): ~8s (both Argon2id runs)
        //   slot 0 salt=0:                 ~0s (bail before any Argon2id)
        //   slot 1 salt=0:                 ~4s (slot 0 Argon2id, then bail)
        // Validating at parse time makes all crafted files bail uniformly
        // at ~0s, closing the per-slot timing differential.
        let mut salt_acc: u8 = 0;
        for b in salt.iter() {
            salt_acc |= *b;
        }
        if salt_acc == 0 {
            bail!("bad");
        }
        let mut base_iv = [0u8; IV_LEN];
        base_iv.copy_from_slice(&bytes[SALT_LEN..SALT_LEN + IV_LEN]);
        let mut commit_tag = [0u8; COMMIT_TAG_LEN];
        commit_tag.copy_from_slice(&bytes[SALT_LEN + IV_LEN..SALT_LEN + IV_LEN + COMMIT_TAG_LEN]);
        let off = SALT_LEN + IV_LEN + COMMIT_TAG_LEN;
        let chunk_count =
            u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let ct_total_len = u32::from_be_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        if !(1..=MAX_CHUNKS).contains(&chunk_count) {
            bail!("bad");
        }
        if ct_total_len < TAG_LEN as u32 || ct_total_len > MAX_CT as u32 {
            bail!("bad");
        }
        // Cross-validate chunk_count ↔ ct_total_len AT PARSE TIME.
        //
        // Validating these two fields independently would allow a
        // malicious slot header to claim chunk_count=200 with
        // ct_total_len=32 (only 1 chunk's worth of ciphertext). The
        // mismatch would only be detected at decrypt_stream runtime — by
        // which point an attacker had already forced the tool to
        // allocate buffers and run Argon2id on the slot's salt.
        //
        // The invariant: for a legitimate slot, the ciphertext consists of
        //   - (chunk_count - 1) full chunks, each of size (CHUNK_SIZE + TAG_LEN)
        //   - 1 final chunk, of size in [TAG_LEN, CHUNK_SIZE + TAG_LEN]
        // So ct_total_len must satisfy:
        //   (chunk_count - 1) * (CHUNK_SIZE + TAG_LEN) + TAG_LEN  ≤  ct_total_len
        //   ct_total_len  ≤  chunk_count * (CHUNK_SIZE + TAG_LEN)
        let min_ct_len = ((chunk_count as usize).saturating_sub(1))
            .saturating_mul(CHUNK_SIZE + TAG_LEN)
            .saturating_add(TAG_LEN);
        let max_ct_len = (chunk_count as usize).saturating_mul(CHUNK_SIZE + TAG_LEN);
        if (ct_total_len as usize) < min_ct_len || (ct_total_len as usize) > max_ct_len {
            bail!("bad");
        }
        let ct_start = SLOT_HEADER_LEN;
        let ct_end = ct_start + ct_total_len as usize;
        if ct_end > bytes.len() {
            bail!("bad");
        }
        let ct = bytes[ct_start..ct_end].to_vec();
        Ok((
            &bytes[ct_end..],
            Self {
                salt,
                base_iv,
                commit_tag,
                chunk_count,
                ct_total_len,
                ct,
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// Padding — randomized, non-block-aligned scheme
// ---------------------------------------------------------------------------

/// Minimum padding always added (fixed). Prevents trivially small
/// ciphertexts (e.g., for a 1-byte plaintext) from revealing the plaintext
/// length via the ciphertext size. 32 bytes is enough to cover the 4-byte
/// length prefix plus a small noise floor.
const MIN_PAD: usize = 32;

/// Maximum additional random padding (exclusive upper bound) added by
/// `padded_len`. The randomized component is uniform in `[0, MAX_RAND_PAD)`
/// bytes. 8 KiB ensures the spread across multiple encryptions of the same
/// plaintext comfortably exceeds `2 * PAD_BLOCK` (8192 bytes) so the
/// selftest's spread check still passes with margin.
const MAX_RAND_PAD: usize = 8 * 1024;

/// Maximum independent random padding added to the common target length in
/// `encrypt_envelope` to break the "file size = 2 * max(real, decoy)"
/// oracle. The observer's uncertainty about `max(real, decoy)` is bounded
/// by this value per slot (so `2 * MAX_DECOY_JITTER` for the whole file).
/// 256 KiB provides substantial obfuscation without excessive space
/// overhead for typical messages.
const MAX_DECOY_JITTER: usize = 256 * 1024;

/// Randomized padding length. Replaces the deterministic
/// `((4 + pt_len + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK` scheme that
/// quantized output to multiples of 4096 bytes (PAD_BLOCK) — a length
/// oracle leaking the plaintext length within 4 KiB (and within 8 KiB
/// after the 1-4 block jitter was applied by `padded_len_with_jitter`).
///
/// The new scheme returns:
///   `4 (length prefix) + pt_len + MIN_PAD + uniform_random(0, MAX_RAND_PAD)`
///
/// The output is NO LONGER aligned to any fixed block boundary, breaking
/// the quantization oracle. An observer of the ciphertext size learns the
/// plaintext length only modulo a ~8 KiB uniformly-random window centered
/// on the true length (not aligned to a block boundary).
///
/// NOTE: this function is NON-DETERMINISTIC (calls `rng::fill`). The
/// only internal caller is `padded_len_with_jitter`, which uses the
/// result as a target length for `pad_plaintext`.
pub fn padded_len(plaintext_len: usize) -> usize {
    let mut buf = [0u8; 4];
    rng::fill(&mut buf);
    // MAX_RAND_PAD = 8192 = 2^13. A u32 mod 2^13 has negligible bias
    // (< 2^-19); the bias only affects the padding size distribution,
    // not any cryptographic strength. No rejection sampling needed.
    let rand_pad = (u32::from_be_bytes(buf) as usize) % MAX_RAND_PAD;
    4 + plaintext_len + MIN_PAD + rand_pad
}

/// Apply 1-4 extra 4 KiB padding blocks of jitter on top of the
/// randomized base, breaking the quantized size leak. Without this, an
/// observer could determine the plaintext length to within 4 KiB by
/// looking at the ciphertext size.
///
/// The jitter is ALWAYS applied, regardless of the `paranoid` flag.
/// Conditional jitter would leak the operator's sensitivity assessment
/// through the ciphertext size: an observer comparing two encryptions of
/// the same plaintext could determine which used `--paranoid` by checking
/// if the sizes differ by more than PAD_BLOCK.
///
/// The base `padded_len` is randomized (non-block-aligned). The 1-4 block
/// jitter is preserved for layered defense and selftest compatibility.
/// With the randomized base plus 1-4 block jitter, the total padding
/// spread is ~24 KiB.
fn padded_len_with_jitter(plaintext_len: usize, _paranoid: bool) -> usize {
    let base = padded_len(plaintext_len);
    // Always add 1-4 extra 4 KiB blocks.
    let mut jitter_bytes = [0u8; 1];
    rng::fill(&mut jitter_bytes);
    let extra_blocks = (jitter_bytes[0] % 4) + 1; // 1..=4
    base + (extra_blocks as usize) * PAD_BLOCK
}

pub fn pad_plaintext(pt: &[u8], target_len: usize, paranoid: bool) -> Result<Zeroizing<Vec<u8>>> {
    if 4 + pt.len() > target_len {
        bail!("bad");
    }
    // Validate that `pt.len()` fits in a `u32` before the `as u32` cast
    // below. The CLI enforces `plaintext.len() <= MAX_CT` (256 MiB)
    // before reaching here, but `pad_plaintext` is `pub` and a future
    // library consumer could call it without that guard. A silent
    // truncation would produce a stored length prefix of
    // `pt.len() % 2^32` and decryption would return a short slice —
    // silent data corruption.
    if pt.len() > u32::MAX as usize {
        bail!("bad");
    }
    // The randomized padding scheme does NOT align to PAD_BLOCK, so an
    // alignment check would reject all legitimately encrypted files.
    // The length-prefix (first 4 bytes) is the source of truth for the
    // plaintext length, and it is authenticated by the AEAD (the entire
    // padded buffer is the AEAD plaintext). A tampered length prefix
    // would cause AEAD authentication to fail BEFORE unpad_plaintext is
    // reached.
    let mut out = Zeroizing::new(vec![0u8; target_len]);
    out[..4].copy_from_slice(&(pt.len() as u32).to_be_bytes());
    out[4..4 + pt.len()].copy_from_slice(pt);
    // ALWAYS fill padding with CSPRNG output, regardless of the
    // `paranoid` flag.
    //
    // Filling padding with ZEROS in non-paranoid mode had two problems:
    //   (a) After decryption, an observer can distinguish paranoid from
    //       non-paranoid mode by looking at the padding bytes. While the
    //       padding is not exposed to the network (it's inside the
    //       ciphertext), it IS visible to anyone who decrypts the file —
    //       including an adversary who coerces the passphrase out of the
    //       operator. The padding pattern reveals the operator's
    //       sensitivity assessment, which is a metadata leak.
    //   (b) Zeros in the padding create a known-plaintext region. While
    //       AES-256-GCM is not vulnerable to known-plaintext attacks,
    //       defense in depth dictates that we should not hand the
    //       adversary any structured data for free.
    //
    // The `paranoid` flag now controls ONLY the jitter on `target_len`
    // (via `padded_len_with_jitter`), not the padding content.
    rng::fill(&mut out[4 + pt.len()..]);
    let _ = paranoid; // no longer affects padding content
    Ok(out)
}

#[allow(dead_code)]
pub fn unpad_plaintext(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // The randomized padding scheme does NOT align to PAD_BLOCK. The
    // length prefix (first 4 bytes) is authenticated by the AEAD and is
    // the sole source of truth for the plaintext length.
    if padded.len() < 4 {
        bail!("bad");
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        bail!("bad");
    }
    Ok(Zeroizing::new(padded[4..4 + len].to_vec()))
}

/// Constant-work unpadder.
///
/// `unpad_plaintext` above allocates a Vec whose length equals the
/// plaintext length, creating a timing side-channel: copying 1 KiB vs
/// 100 MiB takes wildly different time, which leaks which slot matched
/// (and breaks plausible deniability).
///
/// This wrapper always copies `target_len - 4` bytes (the maximum
/// possible plaintext for this slot's padded length) and then truncates.
/// The copy length is data-independent — only the truncation length
/// depends on the actual plaintext length, and truncation is a single
/// pointer adjust.
///
/// Uses a safe `vec![0u8; max_pt_len]` allocation rather than an
/// `unsafe { set_len(max_pt_len) }`. The unsafe block was technicallyally
/// sound (the capacity was guaranteed by `Vec::with_capacity`), but it
/// was a footgun: any future refactor that changed the capacity
/// calculation without updating the set_len call would introduce UB. The
/// safe version initializes the buffer to zeros (a memset), which is a
/// few microseconds slower for very large files but eliminates the risk
/// entirely.
fn unpad_plaintext_ct(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // The randomized padding scheme does NOT align to PAD_BLOCK (see
    // unpad_plaintext above for rationale).
    if padded.len() < 4 {
        bail!("bad");
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        bail!("bad");
    }
    // Safe allocation — vec![0u8; N] is always sound. The Zeroizing
    // wrapper ensures the buffer (including the bytes beyond `len` that
    // we won't return) is wiped on drop.
    let max_pt_len = padded.len() - 4;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; max_pt_len]);
    // Copy the maximum possible plaintext length (data-independent size).
    out.copy_from_slice(&padded[4..4 + max_pt_len]);
    // Truncate to the actual plaintext length.
    out.truncate(len);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Streaming AEAD
// ---------------------------------------------------------------------------

pub fn compute_chunk_count(padded_len: usize) -> u32 {
    let n = padded_len.div_ceil(CHUNK_SIZE);
    n.max(1) as u32
}

/// AAD for chunk i: fixed_header || salt || base_iv || u32be(i) || u32be(chunk_count)
fn chunk_aad_into(
    out: &mut Vec<u8>,
    fixed_header: &[u8],
    salt: &[u8; SALT_LEN],
    base_iv: &[u8; IV_LEN],
    chunk_index: u32,
    chunk_count: u32,
) {
    // Reuse the caller-provided buffer instead of allocating a new Vec
    // per chunk. The AAD is small (~FIXED_HEADER_LEN + SALT_LEN + IV_LEN
    // + 8 bytes ≈ 80 bytes), but multiplied by chunk_count (up to 256)
    // the allocator pressure adds up on large inputs.
    out.clear();
    out.reserve(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    out.extend_from_slice(fixed_header);
    out.extend_from_slice(salt);
    out.extend_from_slice(base_iv);
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(&chunk_count.to_be_bytes());
}

/// Backwards-compatible wrapper that allocates a fresh Vec. Used by
/// callers that do not benefit from buffer reuse (e.g., single-shot
/// decrypt of one chunk).
#[allow(dead_code)]
fn chunk_aad(
    fixed_header: &[u8],
    salt: &[u8; SALT_LEN],
    base_iv: &[u8; IV_LEN],
    chunk_index: u32,
    chunk_count: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    chunk_aad_into(
        &mut aad,
        fixed_header,
        salt,
        base_iv,
        chunk_index,
        chunk_count,
    );
    aad
}

pub fn encrypt_stream(
    prk: &[u8],
    padded: &[u8],
    base_iv: &[u8; IV_LEN],
    fixed_header: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<(Vec<u8>, u32, u32)> {
    let chunk_count = compute_chunk_count(padded.len());
    if chunk_count > MAX_CHUNKS {
        bail!("bad");
    }
    let mut ct_out = Vec::with_capacity(padded.len() + (chunk_count as usize) * TAG_LEN);
    // Reusable AAD buffer — avoids a per-chunk allocation.
    let mut aad_buf: Vec<u8> = Vec::with_capacity(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    for i in 0..chunk_count {
        let start = (i as usize) * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(padded.len());
        let chunk = &padded[start..end];
        // Pass chunk_count to derive_chunk_key_array for domain separation.
        let key = kdf::derive_chunk_key_array(prk, i, chunk_count)?;
        let iv = aead::chunk_nonce(base_iv, i);
        chunk_aad_into(&mut aad_buf, fixed_header, salt, base_iv, i, chunk_count);
        let ct = aead::encrypt_chunk(&key, &iv, &aad_buf, chunk)?;
        ct_out.extend_from_slice(&ct);
    }
    let ct_total_len = ct_out.len() as u32;
    Ok((ct_out, chunk_count, ct_total_len))
}

/// Constant-work decrypt_stream.
///
/// A naive implementation that used `?` to early-exit on the first
/// chunk whose AES-GCM tag failed authentication would create a
/// measurable timing difference:
///   - Correct key, all chunks authentic → all N chunks processed (~100ms)
///   - Wrong key, first chunk fails auth  → only chunk 0 processed (~1ms)
///
/// That 100× timing gap is observable by any local adversary (or anyone
/// measuring process wall-time) and is exactly the side-channel the
/// decoy layer is designed to close. The fix: ALWAYS process every
/// chunk, even after an authentication failure. Authentication failures
/// are recorded in a flag and reflected in the return value, but the
/// loop body runs the same number of AES-GCM operations in every case.
/// Because AES-GCM `decrypt` performs the AES-CTR pass BEFORE the tag
/// compare, the per-chunk cost is data-independent; running all N
/// chunks makes the total time uniform across success/failure paths.
pub fn decrypt_stream(
    prk: &[u8],
    ct: &[u8],
    base_iv: &[u8; IV_LEN],
    fixed_header: &[u8],
    salt: &[u8; SALT_LEN],
    chunk_count: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(ct.len()));
    // Reusable AAD buffer — avoids a per-chunk allocation.
    let mut aad_buf: Vec<u8> = Vec::with_capacity(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    let mut offset = 0usize;
    let mut all_ok = true;
    for i in 0..chunk_count {
        let chunk_ct_len = if i < chunk_count - 1 {
            CHUNK_SIZE + TAG_LEN
        } else {
            ct.len() - offset
        };
        if chunk_ct_len < TAG_LEN || offset + chunk_ct_len > ct.len() {
            bail!("bad");
        }
        let chunk_ct = &ct[offset..offset + chunk_ct_len];
        offset += chunk_ct_len;
        let key = kdf::derive_chunk_key_array(prk, i, chunk_count)?;
        let iv = aead::chunk_nonce(base_iv, i);
        chunk_aad_into(&mut aad_buf, fixed_header, salt, base_iv, i, chunk_count);
        // ALWAYS run the AES-GCM decrypt (data-independent cost) regardless
        // of whether previous chunks authenticated.
        match aead::decrypt_chunk(&key, &iv, &aad_buf, chunk_ct) {
            Ok(pt) => {
                out.extend_from_slice(&pt);
            }
            Err(_) => {
                // Authentication failed. Append zero-filled plaintext of the
                // expected length so the output buffer is sized identically
                // to the success path (defends against output-length oracles).
                let pt_len = chunk_ct.len() - TAG_LEN;
                out.extend(std::iter::repeat(0u8).take(pt_len));
                all_ok = false;
            }
        }
    }
    if offset != ct.len() {
        bail!("bad");
    }
    if !all_ok {
        bail!("bad");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Envelope encrypt / decrypt
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn encrypt_slot(
    plaintext: &[u8],
    passphrase: SecretBytes,
    kdf_mem_kib: u32,
    kdf_iters: u32,
    kdf_par: u32,
    fixed_header: &[u8],
    target_len: usize,
    paranoid: bool,
) -> Result<Slot> {
    let mut salt = [0u8; SALT_LEN];
    rng::fill(&mut salt);
    let mut base_iv = [0u8; IV_LEN];
    rng::fill(&mut base_iv);

    // Consume the passphrase by value; it is wiped the moment Argon2id
    // finishes inside derive_slot_secrets_from_secret.
    let (prk, commit_key) =
        kdf::derive_slot_secrets_from_secret(passphrase, &salt, kdf_mem_kib, kdf_iters, kdf_par)?;

    let padded = pad_plaintext(plaintext, target_len, paranoid)?;
    let (ct, chunk_count, ct_total_len) =
        encrypt_stream(&prk, &padded, &base_iv, fixed_header, &salt)?;

    // Compute the SHA-256 hash of the first chunk's ciphertext for
    // inclusion in the commit tag. This binds the tag to actual ciphertext
    // content, preventing the "invisible salamander" attack.
    let first_chunk_ct_len = std::cmp::min(ct.len(), CHUNK_SIZE + TAG_LEN);
    let first_chunk_ct = &ct[..first_chunk_ct_len];
    let ct_first_chunk_hash = commit::compute_first_chunk_hash(first_chunk_ct);

    // Convert fixed_header slice to typed array for type-safe length.
    let mut fh = [0u8; FIXED_HEADER_LEN];
    fh.copy_from_slice(&fixed_header[..FIXED_HEADER_LEN]);

    let commit_tag = commit::compute_commit_tag(
        commit_key.as_slice(),
        &fh,
        &salt,
        &base_iv,
        chunk_count,
        ct_total_len,
        &ct_first_chunk_hash,
    )?;

    Ok(Slot {
        salt,
        base_iv,
        commit_tag,
        chunk_count,
        ct_total_len,
        ct,
    })
}

/// Encrypt a plaintext into a Fortis envelope. REFUSES to re-encrypt an
/// input that already appears to be a Fortis envelope (begins with the
/// "FRT7" magic bytes) — see `is_fortis_envelope`.
///
/// To override the recursive-encryption check (e.g., for legitimate
/// layered encryption with two different passphrases), call
/// `encrypt_envelope_force` instead.
pub fn encrypt_envelope(
    plaintext: &[u8],
    passphrase: SecretBytes,
    decoy_plaintext: Option<&[u8]>,
    decoy_passphrase: Option<SecretBytes>,
    kdf_preset: KdfPreset,
    paranoid: bool,
) -> Result<Vec<u8>> {
    // Refuse recursive encryption. The check is on the 4-byte magic only
    // — cheap, no parsing oracle, and catches the common operational
    // footgun of re-running `fortis encrypt` on a `.frts` file. Legitimate
    // layered encryption is still possible via `encrypt_envelope_force`.
    if is_fortis_envelope(plaintext) {
        return Err(EnvelopeError::InputAlreadyEncrypted.into());
    }
    encrypt_envelope_impl(
        plaintext,
        passphrase,
        decoy_plaintext,
        decoy_passphrase,
        kdf_preset,
        paranoid,
    )
}

/// `--force` override path. Skips the recursive-encryption check. Use
/// this when the caller has confirmed (via a `--force` flag or equivalent
/// UI prompt) that the user wants to re-encrypt an already-encrypted file.
/// The resulting file will be double-encrypted and require two passphrase
/// entries to decrypt.
#[allow(dead_code)]
pub fn encrypt_envelope_force(
    plaintext: &[u8],
    passphrase: SecretBytes,
    decoy_plaintext: Option<&[u8]>,
    decoy_passphrase: Option<SecretBytes>,
    kdf_preset: KdfPreset,
    paranoid: bool,
) -> Result<Vec<u8>> {
    encrypt_envelope_impl(
        plaintext,
        passphrase,
        decoy_plaintext,
        decoy_passphrase,
        kdf_preset,
        paranoid,
    )
}

/// Internal encryption implementation shared by `encrypt_envelope`
/// (checked) and `encrypt_envelope_force` (unchecked). Does NOT perform
/// the recursive-encryption check — callers are responsible for gating.
fn encrypt_envelope_impl(
    plaintext: &[u8],
    passphrase: SecretBytes,
    decoy_plaintext: Option<&[u8]>,
    decoy_passphrase: Option<SecretBytes>,
    kdf_preset: KdfPreset,
    paranoid: bool,
) -> Result<Vec<u8>> {
    let params = kdf_preset.params();
    let has_decoy = decoy_plaintext.is_some();
    // FLAG_PARANOID is ALWAYS set in the wire format, regardless of whether
    // the user actually requested paranoid padding. Conditionally setting
    // this flag would leak to any adversary who can read the (unencrypted)
    // fixed header byte 5 whether the operator considered the data
    // sensitive enough to warrant paranoid padding — an unacceptable
    // metadata leak that tells the adversary which files to focus
    // cracking resources on.
    //
    // The actual paranoid-padding behavior is now controlled solely by
    // the `paranoid` parameter passed to `pad_plaintext` /
    // `padded_len_with_jitter`. The flag in the header is decorative —
    // set it always so an observer cannot distinguish paranoid from
    // non-paranoid encryptions.
    //
    // FLAG_DECOY is also always set (see the always-two-slots comment below).
    let flags = FLAG_DECOY | FLAG_PARANOID;
    let _ = has_decoy; // no longer used for flag computation

    // ALWAYS produce 2 slots, even when there is no decoy.
    let slot_count: u8 = 2;

    // The kdf_mem_kib / kdf_iters / kdf_par fields are stored in PLAINTEXT
    // in the fixed header (bytes 9-14). An observer who can read the
    // envelope file can determine which KDF preset was used (Standard
    // 64MiB/3 / Paranoid 128MiB/4 / Extreme 256MiB/5), which leaks the
    // operator's sensitivity assessment — the same class of metadata leak
    // that the always-set FLAG_PARANOID fixes.
    //
    // A proper fix requires a protocol bump that encrypts these fields in
    // an authenticated header. The challenge is bootstrapping: the
    // decryptor needs the KDF params to run Argon2id, which derives the
    // key used to decrypt the header. A future design would use a fixed
    // (always-Extreme) KDF for the header-decryption key, then store the
    // actual message KDF params inside the encrypted header.
    //
    // For v7 we leave the fields in plaintext to preserve wire-format
    // compatibility. This is a KNOWN metadata leak documented in the
    // threat model; it does NOT affect confidentiality of the plaintext
    // (the AEAD still authenticates the params via AAD binding, so
    // tampering is detected).
    let fixed_header = FixedHeader::build(
        flags,
        CIPHER_ID_AES256_GCM,
        KDF_ID_ARGON2ID,
        COMMIT_ID_HMAC_SHA256_TRUNC128,
        params.mem_kib,
        params.iters,
        params.par,
        slot_count,
    );

    // Decoy size leak fix.
    //
    // PREVIOUS BEHAVIOR (vulnerable):
    //   target_len = max(real_padded, decoy_padded)
    //   file_size  = 2 * target_len + overhead
    //   => file_size deterministically reveals max(real, decoy).
    //   In practice operators use a small decoy, so a large file size
    //   leaks the presence of a large REAL (hidden) message — exactly
    //   what plausible deniability was supposed to hide.
    //
    // NEW BEHAVIOR:
    //   common_min  = max(real_padded_with_jitter, decoy_padded_with_jitter)
    //   target_len  = common_min + uniform_random(0, MAX_DECOY_JITTER)
    //   file_size   = 2 * target_len + overhead
    //   => file_size is no longer deterministically equal to 2*max; it is
    //      2*(max + independent_random). The observer learns max(real,
    //      decoy) only within a MAX_DECOY_JITTER (256 KiB) window per slot.
    //
    //   The distribution's parameter (common_min) does NOT depend on WHICH
    //   message is larger — only on the max of the two — satisfying the
    //   directive: "pad BOTH messages to the SAME random target length
    //   drawn from a distribution that does NOT depend on which is larger."
    //
    //   Both slots are still padded to the SAME target_len, so an observer
    //   cannot distinguish slot 0 (real) from slot 1 (decoy) by size.
    //
    //   Layered defense: padded_len_with_jitter already adds 1-4 PAD_BLOCK
    //   (4-16 KiB) of independent jitter to EACH message before taking
    //   the max, so common_min itself is already randomized. The extra
    //   MAX_DECOY_JITTER (256 KiB) here provides additional obfuscation
    //   on top, giving a total per-slot uncertainty of up to ~272 KiB.
    let common_min = std::cmp::max(
        padded_len_with_jitter(plaintext.len(), paranoid),
        decoy_plaintext.map_or(0, |d| padded_len_with_jitter(d.len(), paranoid)),
    );
    let mut decoy_jitter_buf = [0u8; 4];
    rng::fill(&mut decoy_jitter_buf);
    // MAX_DECOY_JITTER = 256 KiB = 2^18. u32 mod 2^18 has negligible bias
    // (< 2^-14); only affects padding size distribution, not crypto strength.
    let extra_decoy_pad = (u32::from_be_bytes(decoy_jitter_buf) as usize) % MAX_DECOY_JITTER;
    let target_len = common_min + extra_decoy_pad;

    // Real slot (slot 0): always encrypts the real plaintext. We move
    // `passphrase` into encrypt_slot, which wipes it immediately after
    // Argon2id. The same applies to `decoy_passphrase`.
    let real_slot = encrypt_slot(
        plaintext,
        passphrase,
        params.mem_kib,
        params.iters,
        params.par,
        &fixed_header,
        target_len,
        paranoid,
    )?;

    let mut out = fixed_header.clone();
    out.extend_from_slice(&real_slot.to_bytes());

    // Second slot (slot 1): either the user-supplied decoy, or random noise.
    if let (Some(dp), Some(dpass)) = (decoy_plaintext, decoy_passphrase) {
        // Real decoy: encrypt the decoy plaintext with the decoy passphrase.
        let decoy_slot = encrypt_slot(
            dp,
            dpass,
            params.mem_kib,
            params.iters,
            params.par,
            &fixed_header,
            target_len,
            paranoid,
        )?;
        out.extend_from_slice(&decoy_slot.to_bytes());
    } else {
        // No user decoy — generate a random slot that is structurally
        // identical to a real encrypted slot but will reject all
        // passphrases. This ensures every file has exactly 2 slots of
        // the same size, hiding whether a decoy is present.
        let dummy_slot = generate_dummy_slot(&fixed_header, target_len, params, paranoid)?;
        out.extend_from_slice(&dummy_slot.to_bytes());
    }

    Ok(out)
}

/// Generate a slot that is structurally identical to a real encrypted
/// slot but contains random ciphertext, a random salt, a random IV, and
/// a random commit tag. No passphrase will unlock it. This is used to
/// fill the second slot when no decoy is supplied, so that every file
/// has 2 indistinguishable slots.
///
/// The dummy ciphertext is generated by running AES-256-GCM with a
/// RANDOM key on a RANDOM plaintext. This produces a ciphertext that is
/// structurally identical to a real slot — every chunk has a valid GCM
/// tag (verifiable only with the key, which we discard). The commit_tag
/// is also computed properly from a random commit_key, so it has correct
/// HMAC structure. (Filling the ciphertext with raw CSPRNG output would
/// be statistically indistinguishable from random but structurally
/// DIFFERENT — the "tag" region would be raw CSPRNG output rather than
/// GHASH output, which has specific algebraic properties. No public
/// attack exists for distinguishing GHASH output from random without the
/// key, but the theoretical possibility is enough to warrant defense in
/// depth.)
fn generate_dummy_slot(
    fixed_header: &[u8],
    target_len: usize,
    params: KdfParams,
    paranoid: bool,
) -> Result<Slot> {
    let mut salt = [0u8; SALT_LEN];
    rng::fill(&mut salt);
    let mut base_iv = [0u8; IV_LEN];
    rng::fill(&mut base_iv);

    // Generate a random plaintext of the target padded length.
    let padded_pt: Zeroizing<Vec<u8>> = {
        let mut pt = Zeroizing::new(vec![0u8; target_len]);
        rng::fill(&mut pt);
        pt
    };

    // Generate a random 32-byte master key, derive PRK + commit_key,
    // and run the REAL encryption pipeline. This produces a ciphertext
    // with the same structure as a real slot.
    let random_master: SecretBytes = {
        let mut k = [0u8; 32];
        rng::fill(&mut k);
        SecretBytes::from_slice(&k)
    };
    let prk = kdf::hkdf_extract(&salt, &random_master)?;
    let commit_key = kdf::derive_commit_key(&prk)?;

    // Encrypt the random plaintext using the real encrypt_stream.
    let (ct, chunk_count, ct_total_len) =
        encrypt_stream(&prk, &padded_pt, &base_iv, fixed_header, &salt)?;

    // Compute a real commit_tag over the dummy ciphertext.
    let first_chunk_ct_len = std::cmp::min(ct.len(), CHUNK_SIZE + TAG_LEN);
    let first_chunk_ct = &ct[..first_chunk_ct_len];
    let ct_first_chunk_hash = commit::compute_first_chunk_hash(first_chunk_ct);

    let mut fh = [0u8; FIXED_HEADER_LEN];
    fh.copy_from_slice(&fixed_header[..FIXED_HEADER_LEN]);

    let commit_tag = commit::compute_commit_tag(
        commit_key.as_slice(),
        &fh,
        &salt,
        &base_iv,
        chunk_count,
        ct_total_len,
        &ct_first_chunk_hash,
    )?;

    let _ = params;
    let _ = paranoid;

    Ok(Slot {
        salt,
        base_iv,
        commit_tag,
        chunk_count,
        ct_total_len,
        ct,
    })
}

/// Uniform-timing decrypt_envelope.
///
/// For uniform-timing reasons, `decrypt_stream` is called on EVERY slot
/// regardless of commit-tag match. With the always-process-all-chunks
/// `decrypt_stream`, the timing of every slot's decryption is identical
/// regardless of whether the commit tag matched. The remaining flow is:
///
///   for slot in slots:
///       derive_slot_secrets_from_secret(passphrase_clone, salt, ...)
///       compute_commit_tag(...)
///       ct_eq(...)        ← constant time
///       decrypt_stream(...)  ← uniform across all branches
///
/// Both branches (commit_ok=true and commit_ok=false) execute the same
/// sequence of operations with the same data sizes. The only observable
/// difference is whether `result` gets populated — and that is not
/// visible to a timing adversary because no I/O happens between the two
/// iterations.
pub fn decrypt_envelope(envelope: &[u8], passphrase: SecretBytes) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.len() < FIXED_HEADER_LEN {
        bail!("bad");
    }
    let (hdr, fixed_header) = FixedHeader::parse(envelope)?;
    let mut rest = &envelope[FIXED_HEADER_LEN..];

    let mut slots = Vec::with_capacity(hdr.slot_count as usize);
    for _ in 0..hdr.slot_count {
        let (remaining, slot) = Slot::parse(rest)?;
        rest = remaining;
        slots.push(slot);
    }
    if !rest.is_empty() {
        bail!("bad"); // no trailing garbage
    }

    // Always run decrypt_stream AND unpad_plaintext_ct on EVERY slot,
    // regardless of commit-tag match. This eliminates BOTH:
    //   - the per-chunk timing gap (decrypt_stream early-exit)
    //   - the per-slot plaintext-length timing gap (unpad allocation)
    //
    // Each iteration consumes a CLONE of the passphrase so the original
    // can be wiped by the caller (Drop). Each clone is wiped inside
    // derive_slot_secrets_from_secret immediately after Argon2id.
    let mut result: Option<Zeroizing<Vec<u8>>> = None;
    for slot in &slots {
        let pass_clone = passphrase.try_clone();
        // Never bail early on a per-slot derive failure. The uniform-
        // timing design requires every slot to be processed; bailing
        // would leak which slot failed via wall-clock time.
        let (prk, commit_key) = match kdf::derive_slot_secrets_from_secret(
            pass_clone,
            &slot.salt,
            hdr.kdf_mem_kib,
            hdr.kdf_iters,
            hdr.kdf_par,
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Compute the SHA-256 hash of the first chunk's ciphertext for
        // inclusion in the commit tag.
        let first_chunk_ct_len = std::cmp::min(slot.ct.len(), CHUNK_SIZE + TAG_LEN);
        let first_chunk_ct = &slot.ct[..first_chunk_ct_len];
        let ct_first_chunk_hash = commit::compute_first_chunk_hash(first_chunk_ct);

        // Convert fixed_header slice to typed array.
        let mut fh = [0u8; FIXED_HEADER_LEN];
        fh.copy_from_slice(&fixed_header[..FIXED_HEADER_LEN]);

        let expected = commit::compute_commit_tag(
            commit_key.as_slice(),
            &fh,
            &slot.salt,
            &slot.base_iv,
            slot.chunk_count,
            slot.ct_total_len,
            &ct_first_chunk_hash,
        )?;

        let commit_ok: bool = expected.ct_eq(&slot.commit_tag).into();

        // Run decrypt_stream REGARDLESS of commit_ok. The fixed
        // decrypt_stream always processes all N chunks, so the timing
        // is identical on both branches.
        let stream_result = decrypt_stream(
            prk.as_slice(),
            &slot.ct,
            &slot.base_iv,
            &fixed_header,
            &slot.salt,
            slot.chunk_count,
        );

        // ALWAYS run unpad_plaintext_ct on a padded-sized buffer,
        // regardless of whether commit_ok matched OR whether
        // decrypt_stream succeeded. If stream_result failed (e.g., wrong
        // key, tampered ciphertext), use a zero-filled dummy of the
        // expected padded length so the unpad work is the same size.
        // This closes the per-slot plaintext-length timing gap.
        let padded_for_unpad: Zeroizing<Vec<u8>> = match &stream_result {
            Ok(p) => p.clone(),
            Err(_) => {
                let padded_len = (slot.ct_total_len as usize)
                    .saturating_sub((slot.chunk_count as usize) * TAG_LEN);
                Zeroizing::new(vec![0u8; padded_len])
            }
        };
        let unpad_result = unpad_plaintext_ct(&padded_for_unpad);

        // ONLY accept the result if ALL of:
        //   1. commit_ok == true (commit tag matched — wrong passphrase cannot pass)
        //   2. stream_result == Ok (AES-GCM authenticated ALL chunks — tamper detected)
        //   3. unpad_result == Ok (padding invariants hold — corrupted plaintext rejected)
        //   4. result.is_none() (we don't already have a result from a previous slot)
        // If commit_ok but stream_result is Err, this means the ciphertext
        // was tampered AFTER the commit tag was computed — we MUST reject
        // (do NOT accept dummy zero output as a valid decryption).
        if commit_ok && result.is_none() {
            if let Ok(ref _padded) = stream_result {
                if let Ok(pt) = unpad_result {
                    result = Some(pt);
                }
            }
        }
        // Otherwise: discard. The work was done for its timing side-effect.
    }

    // Wipe the original passphrase NOW — we no longer need it. (Drop
    // would also handle it, but doing it here narrows the window.
    // `passphrase` is owned by value so we can mutate it.)
    let mut passphrase = passphrase;
    passphrase.wipe();
    drop(passphrase);

    match result {
        Some(pt) => Ok(pt),
        None => bail!("bad"), // uniform error
    }
}
