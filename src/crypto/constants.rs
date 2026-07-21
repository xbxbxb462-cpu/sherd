//! Fortis v7 protocol constants. Mirrors the browser tool byte-for-byte.

// Unix-only. mlock, termios echo control, and 0600 perms have no portable
// Win32 equivalents; silently compiling on Windows would ship a binary
// with none of the memory or permission protections.
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
// No K or N values live here. Quorum metadata belongs in shamir.rs and
// must be HMAC-bound if it is ever added to this file.

// ---------------------------------------------------------------------------
// Envelope format
// ---------------------------------------------------------------------------

/// Magic bytes "FRT7" for a Fortis v7 envelope. Public by design; does not
/// leak plaintext but marks the file as Fortis-encrypted to traffic analysis.
pub const MAGIC: [u8; 4] = [0x46, 0x52, 0x54, 0x37];

/// Format version. Bumped only on backwards-incompatible changes.
pub const VERSION: u8 = 7;

/// Fixed 16-byte header: magic 4, version 1, flags 1, cipher_id 1, kdf_id 1,
/// commit_id 1, kdf_mem_kib 4, kdf_iters 1, kdf_par 1, slot_count 1.
pub const FIXED_HEADER_LEN: usize = 16;

/// 68-byte slot header: salt 32, base_iv 12, commit_tag 16, chunk_count 4,
/// ct_total_len 4.
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

/// Max chunks per file. 256 with 1 MiB chunks gives ~256 MiB total.
pub const MAX_CHUNKS: u32 = 256;

/// Max ciphertext length: 256 chunks each with a 16-byte tag overhead.
pub const MAX_CT: usize = MAX_CHUNKS as usize * (CHUNK_SIZE + TAG_LEN); // ~256.004 MiB

// ---------------------------------------------------------------------------
// KDF presets (mirror the browser tool)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KdfPreset {
    /// 64 MiB / 3 passes / 4 lanes. RFC 9106 first recommendation. par=4.
    /// Files encrypted with par < 4 are rejected at decrypt time.
    Standard,
    /// 128 MiB / 4 passes / 4 lanes. Between RFC 9106 first and second.
    Paranoid,
    /// 256 MiB / 5 passes / 4 lanes. Close to RFC 9106 second recommendation
    /// with par=4.
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

// KDF minimums prevent downgrade attacks via crafted .frts headers.
// RFC 9106 first recommendation is the floor: 64 MiB, 3 iters, par 4.
// KDF_MEM_MAX caps allocations to 256 MiB so a hostile file cannot OOM
// the decryptor. par=4 raises brute-force cost on multi-core hardware.
pub const KDF_MEM_MIN: u32 = 65_536; // 64 MiB, RFC 9106 first
pub const KDF_MEM_MAX: u32 = 262_144; // 256 MiB, matches KdfPreset::Extreme
pub const KDF_ITERS_MIN: u32 = 3; // RFC 9106 first
pub const KDF_ITERS_MAX: u32 = 5; // matches KdfPreset::Extreme
pub const KDF_PAR_MIN: u32 = 4; // RFC 9106 first
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
/// ASCII armor label for Shamir share files. Fixed string; does not encode
/// K or N.
pub const ARMOR_SHARE: &str = "FORTIS SHARE";

// ---------------------------------------------------------------------------
// Minimum passphrase length
// ---------------------------------------------------------------------------

pub const MIN_PASS: usize = 12;
