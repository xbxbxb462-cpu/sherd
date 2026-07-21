//! Fortis v7 protocol constants.
//!
//! These mirror the browser FORTIS v7 constants byte-for-byte so that
//! files encrypted by the browser tool can be decrypted by this binary
//! and vice versa.

// Refuse to compile on non-Unix platforms. The Fortis security model
// depends on:
//   - mlock/mlockall (prevents secrets swapping to disk)
//   - RLIMIT_CORE / RLIMIT_MEMLOCK (prevents core dumps, raises memlock)
//   - termios ECHO disable (prevents passphrase being displayed)
//   - 0600 file permissions (prevents other users reading decrypted output)
// None of these are available on Windows in a form we can rely on.
// Silently compiling on Windows would produce a binary that *appears* to
// work but provides NONE of the memory/terminal/permission protections —
// a dangerous false sense of security for a tool that handles secrets.
//
// If you need Windows support, you MUST:
//   1. Use VirtualLock/VirtualUnlock instead of mlock/munlock.
//   2. Use SetProcessWorkingSetSize + JobObjectMemoryLimit instead of mlockall.
//   3. Use GetConsoleMode/SetConsoleMode instead of termios.
//   4. Use ACLs instead of 0600 permissions.
//   5. Re-audit the entire codebase for Unix-specific assumptions.
// Until that work is done, Windows is NOT supported for production use.
#[cfg(not(unix))]
compile_error!(
    "Fortis requires a Unix platform (Linux, macOS, BSD, etc.) for memory locking, \
     terminal echo control, and secure file permissions. Windows is NOT supported for \
     production use. If you must run on Windows, use WSL2 or re-audit the entire \
     codebase for the Win32 equivalents of mlock/mlockall/termios/0600."
);

// ---------------------------------------------------------------------------
// Shamir metadata layout
// ---------------------------------------------------------------------------
//
// The constants in this file do NOT encode Shamir K (threshold) or N (total
// shares) in any form. Shamir share metadata is owned entirely by
// `shamir.rs`. The only Shamir-relevant constant here is `ARMOR_SHARE`
// (the ASCII armor label for share files), which does NOT leak K or N —
// it is a fixed string constant identical for every share.
//
// RULE: if a future constant encodes K, N, share_index, or any quorum
// metadata, it MUST be authenticated (HMAC-bound) and MUST NOT appear in
// plaintext in the share header.

// ---------------------------------------------------------------------------
// Envelope format
// ---------------------------------------------------------------------------

/// Magic bytes "FRT7" — identifies a Fortis v7 envelope.
///
/// The magic bytes are intentionally public and appear in cleartext at the
/// start of every encrypted file. This is by design (file format
/// identification) and does NOT leak plaintext content. However, it DOES
/// allow an adversary to identify a file as Fortis-encrypted via traffic
/// analysis. If plausible-deniability against format detection is
/// required, the envelope layer would need a format-obfuscation mode.
pub const MAGIC: [u8; 4] = [0x46, 0x52, 0x54, 0x37];

/// Format version. Bumped only on backwards-incompatible changes.
pub const VERSION: u8 = 7;

/// Fixed header length: magic(4) + version(1) + flags(1) + cipher_id(1)
/// + kdf_id(1) + commit_id(1) + kdf_mem_kib(4) + kdf_iters(1) + kdf_par(1)
/// + slot_count(1) = 16 bytes.
pub const FIXED_HEADER_LEN: usize = 16;

/// Slot header length: salt(32) + base_iv(12) + commit_tag(16)
/// + chunk_count(4) + ct_total_len(4) = 68 bytes.
pub const SLOT_HEADER_LEN: usize = 68;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

pub const FLAG_DECOY: u8 = 0x01;
pub const FLAG_PARANOID: u8 = 0x02;
pub const KNOWN_FLAGS: u8 = FLAG_DECOY | FLAG_PARANOID;

// ---------------------------------------------------------------------------
// Algorithm IDs (cryptographic agility)
// ---------------------------------------------------------------------------

pub const CIPHER_ID_AES256_GCM: u8 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const COMMIT_ID_HMAC_SHA256_TRUNC128: u8 = 1;

// ---------------------------------------------------------------------------
// Lengths
// ---------------------------------------------------------------------------

pub const SALT_LEN: usize = 32;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const COMMIT_TAG_LEN: usize = 16;
pub const PAD_BLOCK: usize = 4096;
pub const CHUNK_SIZE: usize = 1 << 20; // 1 MiB

/// Maximum chunk count per file. With CHUNK_SIZE = 1 MiB and MAX_CT
/// accounting for tag overhead, the maximum legitimate chunk count is 256.
/// Tightening the bound (rather than something larger) eliminates audit
/// surface and matches the actual protocol invariant.
pub const MAX_CHUNKS: u32 = 256;

/// Maximum ciphertext length. A legitimate 256-chunk file has
/// `ct_total_len = 256 * (CHUNK_SIZE + TAG_LEN)` = 256 MiB + 4 KiB, so
/// this value accounts for the per-chunk GCM tag overhead.
pub const MAX_CT: usize = MAX_CHUNKS as usize * (CHUNK_SIZE + TAG_LEN); // ~256.004 MiB

// ---------------------------------------------------------------------------
// KDF presets (mirror the browser tool)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KdfPreset {
    /// 64 MiB / 3 passes / 4 lanes (~0.5-1s) — RFC 9106 §4 FIRST
    /// recommendation (64 MiB / 3 / 4).
    ///
    /// `par` is 4 (the RFC 9106 §4 first recommendation) for parallelism
    /// resistance. Files encrypted with `par < 4` are rejected at
    /// decryption time.
    Standard,
    /// 128 MiB / 4 passes / 4 lanes (~1-2s) — between first and second
    /// RFC 9106 recommendations, for moderately sensitive data.
    Paranoid,
    /// 256 MiB / 5 passes / 4 lanes (~3-6s) — close to RFC 9106 §4 SECOND
    /// recommendation (256 MiB / 5 / 1), with p=4 for parallelism
    /// resistance.
    Extreme,
}

impl KdfPreset {
    pub fn params(self) -> KdfParams {
        match self {
            KdfPreset::Standard => KdfParams {
                mem_kib: 65_536,
                iters: 3,
                par: 4,
            },
            KdfPreset::Paranoid => KdfParams {
                mem_kib: 131_072,
                iters: 4,
                par: 4,
            },
            KdfPreset::Extreme => KdfParams {
                mem_kib: 262_144,
                iters: 5,
                par: 4,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iters: u32,
    pub par: u32,
}

// KDF minimums enforced to prevent downgrade attacks. A crafted ciphertext
// with weak KDF params would otherwise cause the decryptor to use weak
// params, making brute-force 256× easier. RFC 9106 §4 FIRST recommendation
// is 64 MiB / 3 iters (memory-constrained).
//
// The KDF_MEM_MAX bound prevents a malicious .frts file from forcing the
// decryptor to allocate gigabytes of RAM for Argon2id (OOM DoS). 256 MiB
// matches the highest preset (Extreme) and is the maximum any legitimate
// Fortis file can ever request.
//
// KDF_PAR_MIN is 4 (RFC 9106 §4 first recommendation). The previous
// `par=1` minimum left the KDF vulnerable to parallelism-based brute-force
// attacks (an attacker with a GPU or multi-core rig could parallelize the
// Argon2id search across p=1 lanes trivially; p=4 forces the attacker to
// allocate 4× the memory bandwidth per candidate).
pub const KDF_MEM_MIN: u32 = 65_536; // 64 MiB — RFC 9106 §4 first recommendation
pub const KDF_MEM_MAX: u32 = 262_144; // 256 MiB — matches KdfPreset::Extreme
pub const KDF_ITERS_MIN: u32 = 3; // RFC 9106 §4 first recommendation
pub const KDF_ITERS_MAX: u32 = 5; // matches KdfPreset::Extreme iters
pub const KDF_PAR_MIN: u32 = 4; // RFC 9106 §4 first recommendation
pub const KDF_PAR_MAX: u32 = 4; // matches highest preset

// ---------------------------------------------------------------------------
// HKDF info strings (domain separation)
// ---------------------------------------------------------------------------

pub const HKDF_INFO_COMMIT: &[u8] = b"fortis-v7/commit";
pub const HKDF_INFO_CHUNK_PREFIX: &[u8] = b"fortis-v7/chunk/";

// ---------------------------------------------------------------------------
// Armor labels
// ---------------------------------------------------------------------------

pub const ARMOR_MSG: &str = "FORTIS MESSAGE";
#[allow(dead_code)]
pub const ARMOR_FILE: &str = "FORTIS FILE";
/// ASCII armor label for Shamir share files. A fixed string identical for
/// every share — does NOT encode K or N and does NOT leak quorum metadata.
pub const ARMOR_SHARE: &str = "FORTIS SHARE";

// ---------------------------------------------------------------------------
// Minimum passphrase length
// ---------------------------------------------------------------------------

pub const MIN_PASS: usize = 12;
