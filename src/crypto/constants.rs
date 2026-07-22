//! Sherd v1 protocol constants.

// mlock, termios echo, and 0600 perms require a Unix kernel.
#[cfg(not(unix))]
compile_error!(
    "Sherd requires a Unix platform for memory locking, terminal echo control, \
     and 0600 file perms."
);

// ---------------------------------------------------------------------------
// Envelope format
// ---------------------------------------------------------------------------

/// Magic bytes "SHR1" marking a Sherd v1 envelope.
pub const MAGIC: [u8; 4] = [0x53, 0x48, 0x52, 0x31];

/// Envelope format version.
pub const VERSION: u8 = 1;

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
// Algorithm IDs
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
// KDF presets
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KdfPreset {
    /// 64 MiB / 3 passes / 4 lanes.
    Standard,
    /// 128 MiB / 4 passes / 4 lanes.
    Paranoid,
    /// 256 MiB / 5 passes / 4 lanes.
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

pub const KDF_MEM_MIN: u32 = 65_536; // 64 MiB
pub const KDF_MEM_MAX: u32 = 262_144; // 256 MiB
pub const KDF_ITERS_MIN: u32 = 3;
pub const KDF_ITERS_MAX: u32 = 5;
pub const KDF_PAR_MIN: u32 = 4;
pub const KDF_PAR_MAX: u32 = 4;

// ---------------------------------------------------------------------------
// HKDF info strings
// ---------------------------------------------------------------------------

pub const HKDF_INFO_COMMIT: &[u8] = b"sherd-v1/commit";
pub const HKDF_INFO_CHUNK_PREFIX: &[u8] = b"sherd-v1/chunk/";

// ---------------------------------------------------------------------------
// Armor labels
// ---------------------------------------------------------------------------

pub const ARMOR_MSG: &str = "SHERD MESSAGE";
#[allow(dead_code)]
pub const ARMOR_FILE: &str = "SHERD FILE";
/// ASCII armor label for Shamir share files.
pub const ARMOR_SHARE: &str = "SHERD SHARE";

// ---------------------------------------------------------------------------
// Minimum passphrase length
// ---------------------------------------------------------------------------

pub const MIN_PASS: usize = 12;

// ---------------------------------------------------------------------------
// Recipient-based envelope (v2): X25519 file-key wrapping.
// ---------------------------------------------------------------------------

/// Envelope version 2: recipient-based (no Argon2id, X25519 file-key wrapping).
#[allow(dead_code)]
pub const VERSION_RECIPIENT: u8 = 2;

/// HKDF info labels for recipient file-key wrapping.
#[allow(dead_code)]
pub const HKDF_INFO_WRAP_KEY: &[u8] = b"sherd-v1/wrap-key";
#[allow(dead_code)]
pub const HKDF_INFO_WRAP_NONCE: &[u8] = b"sherd-v1/wrap-nonce";

/// Sizes for recipient stanzas.
#[allow(dead_code)]
pub const X25519_PUB_LEN: usize = 32;
#[allow(dead_code)]
pub const FILE_KEY_LEN: usize = 32;
#[allow(dead_code)]
pub const WRAPPED_KEY_LEN: usize = FILE_KEY_LEN + TAG_LEN; // 32 + 16 = 48
#[allow(dead_code)]
pub const MAX_RECIPIENTS: usize = 255;

/// Identity file format prefixes (like age's AGE-SECRET-KEY-1).
#[allow(dead_code)]
pub const IDENTITY_PREFIX: &str = "SHERD-SECRET-KEY-1";
#[allow(dead_code)]
pub const RECIPIENT_PREFIX: &str = "sherd1";
