//! Sherd v1 binary envelope format.
//!
//! 16-byte header followed by N slots. Each slot carries salt, IV, commit
//! tag, chunk count, total ciphertext length, and a stream of AES-256-GCM
//! chunks. Header bytes feed the AEAD AAD and the commit tag.
#![allow(clippy::doc_lazy_continuation)]

use crate::crypto::aead;
use crate::crypto::commit;
use crate::crypto::constants::*;
use crate::crypto::kdf;
use crate::crypto::keygen;
use crate::crypto::recipient;
use crate::crypto::rng;
use crate::memory::SecretBytes;
use anyhow::{bail, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Typed envelope errors
// ---------------------------------------------------------------------------

/// Typed envelope error: "already encrypted" vs generic failure.
#[derive(Debug)]
pub enum EnvelopeError {
    /// Input already looks like a Sherd envelope. Caller can pass --force.
    InputAlreadyEncrypted,
    /// Generic envelope error. Uniform "bad" message.
    #[allow(dead_code)]
    Bad,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::InputAlreadyEncrypted => write!(
                f,
                "input appears to already be a SHERD envelope; \
                 refusing to re-encrypt (use --force to override)"
            ),
            EnvelopeError::Bad => write!(f, "bad"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// True if input begins with the `"SHR1"` magic. Blocks re-encrypting an
/// existing envelope.
pub fn is_sherd_envelope(input: &[u8]) -> bool {
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
        // iters and par are stored as u8 on the wire. Catch truncation here.
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
        // Reject all-zero salt up front to keep per-slot timing uniform.
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
        // Cross-validate chunk_count and ct_total_len: chunk_count-1 full
        // chunks plus one final chunk of [TAG_LEN, CHUNK_SIZE + TAG_LEN].
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
// Padding: randomized, non-block-aligned
// ---------------------------------------------------------------------------

/// Minimum padding added to every ciphertext. Hides plaintext length for
/// short inputs.
const MIN_PAD: usize = 32;

/// Upper bound on the random padding added by `padded_len`.
const MAX_RAND_PAD: usize = 8 * 1024;

/// Extra random padding layered on top of the common target length in
/// `encrypt_envelope` to blunt the file-size oracle.
const MAX_DECOY_JITTER: usize = 256 * 1024;

/// Randomized target padded length: 4-byte length prefix + plaintext + MIN_PAD
/// plus a uniform random pad in `[0, MAX_RAND_PAD)`.
pub fn padded_len(plaintext_len: usize) -> usize {
    let mut buf = [0u8; 4];
    rng::fill(&mut buf);
    // u32 mod 2^13 has negligible bias; rejection sampling not worth it.
    let rand_pad = (u32::from_be_bytes(buf) as usize) % MAX_RAND_PAD;
    4 + plaintext_len + MIN_PAD + rand_pad
}

/// Adds 1-4 extra 4 KiB blocks on top of `padded_len`. Applied regardless of
/// `paranoid` to avoid leaking the flag via ciphertext size.
fn padded_len_with_jitter(plaintext_len: usize, _paranoid: bool) -> usize {
    let base = padded_len(plaintext_len);
    let mut jitter_bytes = [0u8; 1];
    rng::fill(&mut jitter_bytes);
    let extra_blocks = (jitter_bytes[0] % 4) + 1; // 1..=4
    base + (extra_blocks as usize) * PAD_BLOCK
}

pub fn pad_plaintext(pt: &[u8], target_len: usize, paranoid: bool) -> Result<Zeroizing<Vec<u8>>> {
    if 4 + pt.len() > target_len {
        bail!("bad");
    }
    // `pt.len()` is stored as u32 on the wire; reject inputs that truncate.
    if pt.len() > u32::MAX as usize {
        bail!("bad");
    }
    // Length prefix is AEAD-authenticated; no block alignment required.
    let mut out = Zeroizing::new(vec![0u8; target_len]);
    out[..4].copy_from_slice(&(pt.len() as u32).to_be_bytes());
    out[4..4 + pt.len()].copy_from_slice(pt);
    // Always fill padding with CSPRNG output. Zero padding leaks the paranoid
    // flag after decrypt.
    rng::fill(&mut out[4 + pt.len()..]);
    let _ = paranoid; // unused here
    Ok(out)
}

#[allow(dead_code)]
pub fn unpad_plaintext(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Length prefix is the sole source of truth for plaintext length.
    if padded.len() < 4 {
        bail!("bad");
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        bail!("bad");
    }
    Ok(Zeroizing::new(padded[4..4 + len].to_vec()))
}

/// Constant-work unpadder. Copies the maximum plaintext length, then truncates.
fn unpad_plaintext_ct(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if padded.len() < 4 {
        bail!("bad");
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > padded.len() - 4 {
        bail!("bad");
    }
    // Safe init; Zeroizing wipes the buffer including truncated tail on drop.
    let max_pt_len = padded.len() - 4;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; max_pt_len]);
    // Copy the maximum possible plaintext length. Size is data-independent.
    out.copy_from_slice(&padded[4..4 + max_pt_len]);
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
    // Reuse the caller's buffer; one AAD per chunk adds up on large inputs.
    out.clear();
    out.reserve(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    out.extend_from_slice(fixed_header);
    out.extend_from_slice(salt);
    out.extend_from_slice(base_iv);
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(&chunk_count.to_be_bytes());
}

/// Allocating wrapper around `chunk_aad_into` for one-shot callers.
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
    // Reusable AAD buffer; one alloc instead of one per chunk.
    let mut aad_buf: Vec<u8> = Vec::with_capacity(fixed_header.len() + SALT_LEN + IV_LEN + 4 + 4);
    for i in 0..chunk_count {
        let start = (i as usize) * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(padded.len());
        let chunk = &padded[start..end];
        let key = kdf::derive_chunk_key_array(prk, i, chunk_count)?;
        let iv = aead::chunk_nonce(base_iv, i);
        chunk_aad_into(&mut aad_buf, fixed_header, salt, base_iv, i, chunk_count);
        let ct = aead::encrypt_chunk(&key, &iv, &aad_buf, chunk)?;
        ct_out.extend_from_slice(&ct);
    }
    let ct_total_len = ct_out.len() as u32;
    Ok((ct_out, chunk_count, ct_total_len))
}

/// Constant-work decrypt: process every chunk regardless of tag failure.
pub fn decrypt_stream(
    prk: &[u8],
    ct: &[u8],
    base_iv: &[u8; IV_LEN],
    fixed_header: &[u8],
    salt: &[u8; SALT_LEN],
    chunk_count: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(ct.len()));
    // Reusable AAD buffer; one alloc instead of one per chunk.
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
        // Always decrypt; the work must be uniform across chunks.
        match aead::decrypt_chunk(&key, &iv, &aad_buf, chunk_ct) {
            Ok(pt) => {
                out.extend_from_slice(&pt);
            }
            Err(_) => {
                // Pad with zeros to match the success path's output size.
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

    // Passphrase is consumed by value and wiped after Argon2id.
    let (prk, commit_key) =
        kdf::derive_slot_secrets_from_secret(passphrase, &salt, kdf_mem_kib, kdf_iters, kdf_par)?;

    let padded = pad_plaintext(plaintext, target_len, paranoid)?;
    let (ct, chunk_count, ct_total_len) =
        encrypt_stream(&prk, &padded, &base_iv, fixed_header, &salt)?;

    // Hash of the first chunk's ciphertext, bound into the commit tag.
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

/// Encrypt a plaintext into a Sherd envelope. Refuses to re-encrypt an
/// input that already begins with the SHR1 magic. Use `encrypt_envelope_force`
/// to override.
pub fn encrypt_envelope(
    plaintext: &[u8],
    passphrase: SecretBytes,
    decoy_plaintext: Option<&[u8]>,
    decoy_passphrase: Option<SecretBytes>,
    kdf_preset: KdfPreset,
    paranoid: bool,
) -> Result<Vec<u8>> {
    // Refuse recursive encryption via the 4-byte magic check.
    if is_sherd_envelope(plaintext) {
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

/// `--force` override path. Skips the recursive-encryption check; the
/// output will need two passphrase entries to decrypt.
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

/// Internal encryption shared by the checked and force paths. Callers
/// gate the recursive-encryption check.
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
    // Always set FLAG_PARANOID and FLAG_DECOY. Setting them conditionally
    // leaks the operator's intent via the unencrypted fixed header.
    let flags = FLAG_DECOY | FLAG_PARANOID;
    let _ = has_decoy; // unused; flag is always set

    // Always produce 2 slots, even without a decoy.
    let slot_count: u8 = 2;

    // KDF params are stored in plaintext in the fixed header; the AEAD binds
    // them so tampering is detected on decrypt.
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

    // Pad both slots to the same target length. common_min is the max of the
    // two jittered padded lengths; target_len adds uniform random padding.
    let common_min = std::cmp::max(
        padded_len_with_jitter(plaintext.len(), paranoid),
        decoy_plaintext.map_or(0, |d| padded_len_with_jitter(d.len(), paranoid)),
    );
    let mut decoy_jitter_buf = [0u8; 4];
    rng::fill(&mut decoy_jitter_buf);
    // u32 mod 2^18 has negligible bias.
    let extra_decoy_pad = (u32::from_be_bytes(decoy_jitter_buf) as usize) % MAX_DECOY_JITTER;
    let target_len = common_min + extra_decoy_pad;

    // Real slot. passphrase moves into encrypt_slot and is wiped after Argon2id.
    // Same applies to decoy_passphrase below.
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

    // Second slot: either the user-supplied decoy, or random noise.
    if let (Some(dp), Some(dpass)) = (decoy_plaintext, decoy_passphrase) {
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
        // No user decoy; synthesize a structurally-identical random slot.
        let dummy_slot = generate_dummy_slot(&fixed_header, target_len, params, paranoid)?;
        out.extend_from_slice(&dummy_slot.to_bytes());
    }

    Ok(out)
}

/// Slot that is structurally identical to a real encrypted slot but filled
/// with random ciphertext, salt, IV, and commit tag. No passphrase unlocks
/// it. Used to fill the second slot when no decoy is supplied.
///
/// Ciphertext comes from AES-256-GCM with a random key on a random plaintext.
/// Chunk tags carry real GHASH structure rather than raw CSPRNG bytes.
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

    let padded_pt: Zeroizing<Vec<u8>> = {
        let mut pt = Zeroizing::new(vec![0u8; target_len]);
        rng::fill(&mut pt);
        pt
    };

    // Random master key; run the real encrypt pipeline.
    let random_master: SecretBytes = {
        let mut k = [0u8; 32];
        rng::fill(&mut k);
        SecretBytes::from_slice(&k)
    };
    let prk = kdf::hkdf_extract(&salt, &random_master)?;
    let commit_key = kdf::derive_commit_key(&prk)?;

    let (ct, chunk_count, ct_total_len) =
        encrypt_stream(&prk, &padded_pt, &base_iv, fixed_header, &salt)?;

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

/// Uniform-timing decrypt. `decrypt_stream` runs on every slot regardless of
/// commit-tag match.
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

    // Run decrypt_stream and unpad on every slot for uniform per-chunk and
    // per-slot timing. Each iteration takes a passphrase clone, wiped inside
    // derive_slot_secrets_from_secret.
    let mut result: Option<Zeroizing<Vec<u8>>> = None;
    for slot in &slots {
        let pass_clone = passphrase.try_clone();
        // Continue on derive failure; bailing here leaks via timing.
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

        // First-chunk ciphertext hash, bound into the commit tag.
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

        // Always run decrypt_stream; it processes all N chunks uniformly.
        let stream_result = decrypt_stream(
            prk.as_slice(),
            &slot.ct,
            &slot.base_iv,
            &fixed_header,
            &slot.salt,
            slot.chunk_count,
        );

        // Always unpad a padded-sized buffer. On stream failure, use a
        // zero-filled dummy of the expected length.
        let padded_for_unpad: Zeroizing<Vec<u8>> = match &stream_result {
            Ok(p) => p.clone(),
            Err(_) => {
                let padded_len = (slot.ct_total_len as usize)
                    .saturating_sub((slot.chunk_count as usize) * TAG_LEN);
                Zeroizing::new(vec![0u8; padded_len])
            }
        };
        let unpad_result = unpad_plaintext_ct(&padded_for_unpad);

        // Accept only if commit matched, the stream authenticated, the
        // unpad succeeded, and we have no prior result.
        if commit_ok && result.is_none() {
            if let Ok(ref _padded) = stream_result {
                if let Ok(pt) = unpad_result {
                    result = Some(pt);
                }
            }
        }
        // Otherwise discard; the work was for timing uniformity.
    }

    // Wipe the passphrase now to narrow the window before Drop.
    let mut passphrase = passphrase;
    passphrase.wipe();
    drop(passphrase);

    match result {
        Some(pt) => Ok(pt),
        None => bail!("bad"), // uniform error
    }
}

// ---------------------------------------------------------------------------
// Envelope v2: recipient-based (X25519 file-key wrapping)
// ---------------------------------------------------------------------------
//
// Wire layout:
//   MAGIC (4) || version=2 (1) || recipient_count (1) || base_iv (12)
//   || chunk_count (4 BE) || ct_total_len (4 BE)
//   || [ stanza: ephemeral_pub (32) || wrapped_key (48) ] * recipient_count
//   || ciphertext (ct_total_len)
//
// No Argon2id, no salt, no commit tag. The file_key (32 random bytes) is the
// PRK for HKDF-Expand chunk-key derivation; per-recipient stanzas wrap it via
// X25519 + HKDF + AES-256-GCM. AAD binds the 22-byte header
// (magic+version+rcount+base_iv+chunk_count); the salt field in chunk_aad is
// zero (placeholder for v2).

/// V2 header length before the stanza block: 4+1+1+12+4+4 = 26 bytes.
const V2_HEADER_LEN: usize = 26;
/// V2 AAD header length (excludes ct_total_len, which is unknown at AAD time):
/// 4+1+1+12+4 = 22 bytes.
const V2_AAD_HEADER_LEN: usize = 22;
/// Per-stanza on-wire size: ephemeral X25519 pub (32) + wrapped file_key (48).
const V2_STANZA_LEN: usize = X25519_PUB_LEN + WRAPPED_KEY_LEN;

/// Encrypt plaintext to one or more X25519 recipients. Returns the v2
/// envelope bytes. No Argon2id, no passphrase - the file key is wrapped
/// per-recipient.
pub fn encrypt_envelope_recipients(
    plaintext: &[u8],
    recipients: &[[u8; X25519_PUB_LEN]],
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("bad");
    }
    if recipients.len() > MAX_RECIPIENTS {
        bail!("bad");
    }
    if plaintext.len() > MAX_CT {
        bail!("bad");
    }
    // Refuse recursive encryption via the 4-byte magic check.
    if is_sherd_envelope(plaintext) {
        return Err(EnvelopeError::InputAlreadyEncrypted.into());
    }

    // 1. Random file_key - serves directly as the HKDF-Expand PRK.
    let mut file_key = recipient::generate_file_key();

    // 2. Wrap per recipient.
    let stanzas: Vec<recipient::Stanza> = recipients
        .iter()
        .map(|r| recipient::wrap_file_key(&file_key, r))
        .collect::<Result<_>>()?;

    // 3. Pad (reuse the v1 randomized padding; paranoid flag is unused
    //    inside pad_plaintext, only the target_len matters).
    let target_len = padded_len_with_jitter(plaintext.len(), false);
    let padded = pad_plaintext(plaintext, target_len, false)?;

    // 4. Random base_iv.
    let mut base_iv = [0u8; IV_LEN];
    rng::fill(&mut base_iv);

    // 5. Chunk count from padded length (matches what encrypt_stream will
    //    compute internally).
    let chunk_count = compute_chunk_count(padded.len());
    if chunk_count > MAX_CHUNKS {
        file_key.zeroize();
        bail!("bad");
    }

    // 6. Build the 22-byte AAD header. ct_total_len is NOT included - it
    //    is not known until after encryption.
    let mut aad_hdr = Vec::with_capacity(V2_AAD_HEADER_LEN);
    aad_hdr.extend_from_slice(&MAGIC);
    aad_hdr.push(VERSION_RECIPIENT);
    aad_hdr.push(stanzas.len() as u8);
    aad_hdr.extend_from_slice(&base_iv);
    aad_hdr.extend_from_slice(&chunk_count.to_be_bytes());
    debug_assert_eq!(aad_hdr.len(), V2_AAD_HEADER_LEN);

    // 7. Encrypt chunks. file_key (32 random bytes) is the PRK; HKDF-Expand
    //    on a random key is well-defined. Salt is zero - the AAD still
    //    binds the 22-byte header.
    let zero_salt = [0u8; SALT_LEN];
    let enc_result = encrypt_stream(&file_key, &padded, &base_iv, &aad_hdr, &zero_salt);
    if enc_result.is_err() {
        file_key.zeroize();
        return enc_result.map(|(_, _, _)| Vec::new());
    }
    let (ct, chunk_count_out, ct_total_len) = enc_result?;
    debug_assert_eq!(chunk_count, chunk_count_out);

    // 8. Assemble output: 26-byte header || stanzas || ciphertext.
    let mut out = Vec::with_capacity(V2_HEADER_LEN + stanzas.len() * V2_STANZA_LEN + ct.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION_RECIPIENT);
    out.push(stanzas.len() as u8);
    out.extend_from_slice(&base_iv);
    out.extend_from_slice(&chunk_count.to_be_bytes());
    out.extend_from_slice(&ct_total_len.to_be_bytes());
    for s in &stanzas {
        out.extend_from_slice(&s.ephemeral_pub);
        out.extend_from_slice(&s.wrapped_key);
    }
    out.extend_from_slice(&ct);

    file_key.zeroize();
    Ok(out)
}

/// Decrypt a v2 recipient-based envelope. Tries each identity against each
/// stanza until one unwraps the file_key, then decrypts the chunks.
pub fn decrypt_envelope_recipients(
    data: &[u8],
    identities: &[keygen::Identity],
) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < V2_HEADER_LEN + V2_STANZA_LEN {
        bail!("bad");
    }
    if &data[0..4] != MAGIC.as_slice() {
        bail!("bad");
    }
    if data[4] != VERSION_RECIPIENT {
        bail!("bad");
    }
    let recipient_count = data[5] as usize;
    if recipient_count == 0 || recipient_count > MAX_RECIPIENTS {
        bail!("bad");
    }
    let base_iv: [u8; IV_LEN] = data[6..18].try_into().unwrap();
    let chunk_count = u32::from_be_bytes(data[18..22].try_into().unwrap());
    let ct_total_len = u32::from_be_bytes(data[22..26].try_into().unwrap()) as usize;

    // Validate chunk_count and ct_total_len the same way Slot::parse does.
    if !(1..=MAX_CHUNKS).contains(&chunk_count) {
        bail!("bad");
    }
    if !(TAG_LEN..=MAX_CT).contains(&ct_total_len) {
        bail!("bad");
    }
    let min_ct_len = ((chunk_count as usize).saturating_sub(1))
        .saturating_mul(CHUNK_SIZE + TAG_LEN)
        .saturating_add(TAG_LEN);
    let max_ct_len = (chunk_count as usize).saturating_mul(CHUNK_SIZE + TAG_LEN);
    if ct_total_len < min_ct_len || ct_total_len > max_ct_len {
        bail!("bad");
    }

    // Locate the stanza block and ciphertext.
    let stanzas_start = V2_HEADER_LEN;
    let stanzas_end = stanzas_start + recipient_count * V2_STANZA_LEN;
    if data.len() < stanzas_end {
        bail!("bad");
    }
    let ct_end = stanzas_end + ct_total_len;
    // No trailing garbage allowed.
    if data.len() != ct_end {
        bail!("bad");
    }

    // Try to unwrap the file_key. Iterate stanzas outer, identities inner.
    let mut file_key: Option<SecretBytes> = None;
    for i in 0..recipient_count {
        let s_off = stanzas_start + i * V2_STANZA_LEN;
        let stanza = recipient::Stanza {
            ephemeral_pub: data[s_off..s_off + X25519_PUB_LEN].try_into().unwrap(),
            wrapped_key: data[s_off + X25519_PUB_LEN..s_off + V2_STANZA_LEN]
                .try_into()
                .unwrap(),
        };
        for id in identities {
            if let Some(fk) = recipient::unwrap_file_key(&stanza, id)? {
                file_key = Some(fk);
                break;
            }
        }
        if file_key.is_some() {
            break;
        }
    }
    let file_key = file_key.ok_or_else(|| anyhow::anyhow!("bad"))?;

    // Reconstruct the 22-byte AAD header used during encryption.
    let mut aad_hdr = Vec::with_capacity(V2_AAD_HEADER_LEN);
    aad_hdr.extend_from_slice(&MAGIC);
    aad_hdr.push(VERSION_RECIPIENT);
    aad_hdr.push(recipient_count as u8);
    aad_hdr.extend_from_slice(&base_iv);
    aad_hdr.extend_from_slice(&chunk_count.to_be_bytes());
    debug_assert_eq!(aad_hdr.len(), V2_AAD_HEADER_LEN);

    // Decrypt the chunks. file_key is the PRK; salt is zero.
    let zero_salt = [0u8; SALT_LEN];
    let ct = &data[stanzas_end..ct_end];
    let padded = decrypt_stream(
        file_key.as_slice(),
        ct,
        &base_iv,
        &aad_hdr,
        &zero_salt,
        chunk_count,
    )?;

    // Unpad (same as v1).
    unpad_plaintext(&padded)
}

/// True if `data` is a v2 recipient envelope (SHR1 magic + version byte 2).
pub fn is_sherd_recipient_envelope(data: &[u8]) -> bool {
    data.len() >= 5 && data[..4] == MAGIC && data[4] == VERSION_RECIPIENT
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    #[test]
    fn test_recipient_roundtrip_single() {
        let id = keygen::Identity::generate();
        let pub_bytes = id.public_key();
        let pt = b"hello recipient v2";
        let env = encrypt_envelope_recipients(pt, &[pub_bytes]).unwrap();
        assert!(is_sherd_recipient_envelope(&env));
        let recovered = decrypt_envelope_recipients(&env, &[id]).unwrap();
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_recipient_roundtrip_multi() {
        let ids: Vec<keygen::Identity> = (0..5).map(|_| keygen::Identity::generate()).collect();
        let pubs: Vec<[u8; X25519_PUB_LEN]> = ids.iter().map(|i| i.public_key()).collect();
        let pt = b"multi-recipient secret";
        let env = encrypt_envelope_recipients(pt, &pubs).unwrap();
        // Each identity alone can decrypt.
        for id in &ids {
            let recovered = decrypt_envelope_recipients(&env, std::slice::from_ref(id)).unwrap();
            assert_eq!(recovered.as_slice(), pt);
        }
    }

    #[test]
    fn test_recipient_wrong_identity_fails() {
        let id1 = keygen::Identity::generate();
        let id2 = keygen::Identity::generate();
        let pub_bytes = id1.public_key();
        let env = encrypt_envelope_recipients(b"only for id1", &[pub_bytes]).unwrap();
        let res = decrypt_envelope_recipients(&env, &[id2]);
        assert!(res.is_err(), "wrong identity must not decrypt");
    }

    #[test]
    fn test_recipient_any_identity_succeeds() {
        let id1 = keygen::Identity::generate();
        let id2 = keygen::Identity::generate();
        let id3 = keygen::Identity::generate();
        let pubs = [id1.public_key(), id2.public_key(), id3.public_key()];
        let pt = b"any of the three";
        let env = encrypt_envelope_recipients(pt, &pubs).unwrap();
        // id3 alone is enough.
        let recovered = decrypt_envelope_recipients(&env, std::slice::from_ref(&id3)).unwrap();
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_recipient_refuses_recursive_encrypt() {
        let id = keygen::Identity::generate();
        let pub_bytes = id.public_key();
        let env = encrypt_envelope_recipients(b"first layer", &[pub_bytes]).unwrap();
        let res = encrypt_envelope_recipients(&env, &[pub_bytes]);
        assert!(res.is_err(), "must refuse to re-wrap an existing envelope");
    }

    #[test]
    fn test_recipient_empty_recipients_rejected() {
        let res = encrypt_envelope_recipients(b"x", &[]);
        assert!(res.is_err());
    }

    #[test]
    fn test_recipient_tampered_header_rejected() {
        let id = keygen::Identity::generate();
        let pub_bytes = id.public_key();
        let mut env = encrypt_envelope_recipients(b"tamper me", &[pub_bytes]).unwrap();
        // Flip a bit in the chunk_count field.
        env[18] ^= 0x01;
        let res = decrypt_envelope_recipients(&env, std::slice::from_ref(&id));
        assert!(res.is_err());
    }

    #[test]
    fn test_recipient_large_plaintext_roundtrip() {
        let id = keygen::Identity::generate();
        let pub_bytes = id.public_key();
        // 2 MiB plaintext - exercises multi-chunk path.
        let pt = vec![0x42u8; 2 * 1024 * 1024];
        let env = encrypt_envelope_recipients(&pt, &[pub_bytes]).unwrap();
        let recovered = decrypt_envelope_recipients(&env, std::slice::from_ref(&id)).unwrap();
        assert_eq!(recovered.as_slice(), pt.as_slice());
    }
}
