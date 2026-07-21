//! CLI argument parsing and command dispatch.
//!
//! All plaintext buffers (input read, decrypted output, Shamir-reconstructed
//! secret) are wrapped in `Zeroizing<Vec<u8>>` so they are wiped when the
//! caller drops them.
//!
//! The decoy-vs-real passphrase equality check uses `subtle::ConstantTimeEq`
//! to avoid timing side-channels.
//!
//! Output files are created with mode 0600 on Unix, regardless of the
//! process umask.
//!
//! Notable hardening:
//!   - Decoy-vs-real passphrase equality check uses `subtle::ConstantTimeEq`
//!     in constant time.
//!   - TOCTOU on input files is closed by opening the file ONCE, fstat'ing
//!     the fd, and reading from the SAME fd (via `open_and_read_bounded`).
//!   - Shamir K (threshold) and N (total) are never printed to stdout or
//!     stderr.
//!   - Decrypt-failure paths return `Err(anyhow!(...))` rather than
//!     `std::process::exit(1)` so Drop impls run.
//!   - `share_combine` checks `share_blobs.len() < threshold` instead of
//!     a hardcoded `< 2`.
//!   - `--force` flag added to `EncryptArgs` and `EncryptFileArgs`. The
//!     CLI performs a defense-in-depth check for already-encrypted input
//!     (FORTIS binary magic "FRT7\x07" or armor header
//!     "-----BEGIN FORTIS MESSAGE-----") and refuses to re-encrypt unless
//!     `--force` is given.
//!   - `cmd_encrypt_file` and `cmd_decrypt_file` use `open_and_read_bounded`
//!     which checks `is_file()` on the OPENED fd (not on a separate stat
//!     call), closing the device/FIFO bypass.
//!   - Share data read from stdin and from share files is wrapped in
//!     `Zeroizing` so it is wiped on drop. Shamir shares are secret
//!     material (K shares reconstruct the secret).

use crate::armor;
use crate::crypto::constants::*;
use crate::envelope;
use crate::memory::{self, SecretBytes};
use crate::shamir;
use anyhow::{anyhow, bail, Result};
use clap::Args;
use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Recursive-encryption detection helpers
// ---------------------------------------------------------------------------

/// The binary envelope magic is "FRT7" (4 bytes) followed by the version
/// byte (7). If an input file begins with these 5 bytes, it is almost
/// certainly an already-encrypted Fortis binary envelope. Re-encrypting
/// it would double-wrap the data and confuse decryption.
const FORTIS_BINARY_MAGIC: &[u8] = b"FRT7";

/// The ASCII-armored message begins with this exact line. We check for
/// it (allowing leading whitespace) to detect re-encryption of an
/// armored message.
const FORTIS_ARMOR_PREFIX: &str = "-----BEGIN FORTIS MESSAGE-----";

fn looks_like_fortis_binary(data: &[u8]) -> bool {
    data.len() >= 5 && &data[..4] == FORTIS_BINARY_MAGIC && data[4] == VERSION
}

fn looks_like_fortis_armored(data: &[u8]) -> bool {
    // Only treat as armored if the data is valid UTF-8 and starts with
    // the armor prefix (after trimming leading whitespace). This avoids
    // false positives on binary data that happens to contain the magic
    // bytes by coincidence.
    match std::str::from_utf8(data) {
        Ok(s) => s
            .trim_start_matches(|c: char| c.is_whitespace())
            .starts_with(FORTIS_ARMOR_PREFIX),
        Err(_) => false,
    }
}

/// Returns true if the input looks like an already-encrypted Fortis
/// artifact (binary envelope or armored message).
fn looks_like_fortis_output(data: &[u8]) -> bool {
    looks_like_fortis_binary(data) || looks_like_fortis_armored(data)
}

// ---------------------------------------------------------------------------
// TOCTOU-safe bounded file reader
// ---------------------------------------------------------------------------

/// Open the file ONCE, fstat the fd, then read from the SAME fd. The
/// naive `std::fs::metadata(p)` + `std::fs::read(p)` pattern opens the
/// file twice, allowing an attacker who can swap the path between calls
/// to make the second `read` operate on a non-regular, unbounded file
/// (e.g., /dev/zero → OOM, or a FIFO → indefinite block).
///
/// This helper:
///   1. Opens the path with `File::open` (single open).
///   2. Calls `file.metadata()` (fstat on the fd — no second open).
///   3. Rejects non-regular files (devices, FIFOs, sockets, symlinks-to-
///      devices). Symlinks to regular files ARE followed by `File::open`,
///      which is fine — the fstat sees through to the regular file.
///   4. Rejects files larger than `max`.
///   5. Reads the entire fd into a `Zeroizing<Vec<u8>>` (wiped on drop).
///
/// `label` is used in error messages (e.g., "--pass-file", "input") so the
/// operator knows which path failed WITHOUT the absolute path being echoed
/// (the path could itself be sensitive, e.g., "/home/agent/vault/key.bin").
fn open_and_read_bounded(
    path: &std::path::Path,
    max: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).map_err(|e| anyhow!("{} open failed: {}", label, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("{} metadata failed: {}", label, e))?;
    // Reject non-regular files. fstat on the fd means the attacker cannot
    // swap the path between the is_file check and the read — we hold the
    // only file descriptor.
    if !metadata.is_file() {
        bail!(
            "{} is not a regular file (devices, FIFOs, sockets not allowed)",
            label
        );
    }
    if metadata.len() as usize > max {
        bail!("{} exceeds {} MiB limit", label, max / (1024 * 1024));
    }
    // Pre-allocate based on fstat size (capped at `max`) to avoid
    // reallocation churn. Vec::with_capacity(0) is fine for empty files.
    let cap = std::cmp::min(metadata.len() as usize, max);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(cap));
    // Read from the SAME fd that we fstat'd. No TOCTOU.
    file.take(max as u64)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow!("{} read failed: {}", label, e))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Encrypt message
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct EncryptArgs {
    /// Read plaintext from this file instead of stdin
    #[arg(short = 'i', long)]
    pub input: Option<PathBuf>,

    /// Write ciphertext to this file instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// KDF memory preset
    #[arg(short = 'k', long, value_enum, default_value_t = KdfPresetArg::Standard)]
    pub kdf: KdfPresetArg,

    /// Enable paranoid padding (hides plaintext length within 4 KiB blocks)
    #[arg(long)]
    pub paranoid: bool,

    /// Decoy message file (plausible deniability — must supply a decoy passphrase too)
    #[arg(long)]
    pub decoy: Option<PathBuf>,

    /// Read decoy passphrase from this file (one line)
    #[arg(long)]
    pub decoy_pass_file: Option<PathBuf>,

    /// Read decoy passphrase from file descriptor N
    #[arg(long)]
    pub decoy_pass_fd: Option<u32>,

    /// Read passphrase from this file (one line). More secure than --pass
    /// because the file path (not the passphrase) appears in cmdline.
    #[arg(long)]
    pub pass_file: Option<PathBuf>,

    /// Read passphrase from file descriptor N (e.g. 3). Most secure for
    /// scripting: `./fortis encrypt --pass-fd 3 3<passfile`
    #[arg(long)]
    pub pass_fd: Option<u32>,

    /// Allow re-encrypting an input that already looks like a Fortis
    /// artifact (binary envelope or armored message). Without this flag,
    /// the CLI refuses to double-wrap. Use only when you genuinely need
    /// layered encryption (e.g., wrapping an armored message in a binary
    /// envelope for transport).
    #[arg(long)]
    pub force: bool,
    // The `decoy_pass` and `pass` fields are intentionally ABSENT. A
    // `--pass X` flag would put the passphrase in /proc/PID/cmdline,
    // shell history, and `ps aux` output. The only accepted passphrase
    // sources are: --pass-fd, --pass-file, the FORTIS_PASS env var
    // (debug convenience, see `get_passphrase`), or the interactive
    // prompt.
}

#[derive(Clone, clap::ValueEnum)]
pub enum KdfPresetArg {
    Standard,
    Paranoid,
    Extreme,
}

impl KdfPresetArg {
    fn to_preset(&self) -> KdfPreset {
        match self {
            KdfPresetArg::Standard => KdfPreset::Standard,
            KdfPresetArg::Paranoid => KdfPreset::Paranoid,
            KdfPresetArg::Extreme => KdfPreset::Extreme,
        }
    }
}

pub fn cmd_encrypt_message(args: EncryptArgs) -> Result<()> {
    // Read plaintext (wrapped in Zeroizing)
    let plaintext: Zeroizing<Vec<u8>> = read_input(&args.input)?;
    if plaintext.is_empty() {
        bail!("plaintext is empty");
    }
    if plaintext.len() > MAX_CT {
        bail!("plaintext exceeds 256 MiB limit");
    }

    // Defense-in-depth recursive-encryption check. If the input looks
    // like an already-encrypted Fortis artifact, refuse unless --force
    // was given. `envelope::encrypt_envelope` performs the same check
    // internally and returns an `InputAlreadyEncrypted` error; this
    // CLI-side check gives a clearer message and avoids wasting Argon2id
    // cycles on a doomed encrypt.
    if !args.force && looks_like_fortis_output(&plaintext) {
        bail!(
            "input appears to be an already-encrypted FORTIS message.\n\
             Re-encrypting would double-wrap the data and make decryption confusing.\n\
             If you genuinely need layered encryption, re-run with --force.\n\
             (If you intended to decrypt, use `fortis decrypt` instead.)"
        );
    }

    // Read passphrase (consumed by encrypt_envelope below)
    let passphrase = get_passphrase(
        &args.pass_file,
        &args.pass_fd,
        "Passphrase (min 12 chars): ",
    )?;
    if passphrase.len() < MIN_PASS {
        bail!("passphrase must be at least {} characters", MIN_PASS);
    }

    // Decoy
    let (decoy_pt, decoy_pass): (Option<Zeroizing<Vec<u8>>>, Option<SecretBytes>) =
        if let Some(decoy_path) = &args.decoy {
            let dp: Zeroizing<Vec<u8>> = read_input(&Some(decoy_path.clone()))?;
            let dpass = get_decoy_passphrase(&args.decoy_pass_file, &args.decoy_pass_fd)?;
            if dpass.len() < MIN_PASS {
                bail!("decoy passphrase must be at least {} characters", MIN_PASS);
            }
            // Use `subtle::ConstantTimeEq` directly. A pre-check on
            // `passphrase.len() != dpass.len()` would short-circuit ct_eq
            // and leak length-equality via timing. `ConstantTimeEq` for
            // `&[u8]` already returns false (0) for different-length slices
            // in constant time.
            let same = bool::from(passphrase.as_bytes().ct_eq(dpass.as_bytes()));
            if same {
                bail!("decoy passphrase must differ from the real passphrase");
            }
            (Some(dp), Some(dpass))
        } else {
            (None, None)
        };

    // Do NOT print the KDF preset to stderr. The preset name ("Standard"
    // / "Paranoid" / "Extreme") reveals the operator's sensitivity
    // assessment of the data — an adversary with access to terminal logs
    // can use this to prioritize which files to attack. Print only a
    // generic progress message that is identical for all presets.
    eprintln!("[fortis] Deriving key (Argon2id)…");

    let t0 = std::time::Instant::now();
    // `encrypt_envelope` consumes `passphrase` and `decoy_pass` by value;
    // both are wiped inside `derive_slot_secrets_from_secret` the moment
    // Argon2id finishes.
    //
    // `encrypt_envelope` may return an `InputAlreadyEncrypted` error.
    // We catch it here and re-print the --force hint, in case the
    // CLI-side check above missed a case (e.g., a wrapped format that
    // only envelope.rs recognizes).
    let env = match envelope::encrypt_envelope(
        &plaintext,
        passphrase,
        decoy_pt.as_deref().map(|v| v.as_slice()),
        decoy_pass,
        args.kdf.to_preset(),
        args.paranoid,
    ) {
        Ok(v) => v,
        Err(e) => {
            // Check whether this is the InputAlreadyEncrypted error by
            // examining the error chain text (anyhow errors are
            // type-erased, so we match on Display). This is robust
            // against the exact error type as long as the word "already
            // encrypted" appears somewhere in the chain.
            let mut found = false;
            let mut src: Option<&dyn std::error::Error> = Some(e.as_ref());
            while let Some(err) = src {
                let msg = err.to_string().to_lowercase();
                if msg.contains("already encrypted") || msg.contains("inputalreadyencrypted") {
                    found = true;
                    break;
                }
                src = err.source();
            }
            if found {
                bail!(
                    "input appears to be an already-encrypted FORTIS message.\n\
                     Re-encrypting would double-wrap the data.\n\
                     If you genuinely need layered encryption, re-run with --force."
                );
            }
            return Err(e);
        }
    };
    let elapsed = t0.elapsed();

    let armored = armor::armor(ARMOR_MSG, &env);
    write_output(&args.output, armored.as_bytes())?;

    // Do NOT print the envelope size or elapsed time. Both leak
    // information: size correlates with plaintext size (even with
    // --paranoid padding, the size modulo 4 KiB reveals the preset
    // jitter range), and elapsed time reveals the KDF preset (Extreme
    // is ~3× slower than Standard). The operator can wrap the
    // invocation in `time` and check the output file size themselves
    // if they want these numbers.
    let _ = elapsed;
    let _ = env.len();
    eprintln!("[fortis] Encrypted.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Decrypt message
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DecryptArgs {
    #[arg(short = 'i', long)]
    pub input: Option<PathBuf>,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Read passphrase from this file (one line).
    #[arg(long)]
    pub pass_file: Option<PathBuf>,

    /// Read passphrase from file descriptor N.
    #[arg(long)]
    pub pass_fd: Option<u32>,
    // The `pass` field is intentionally ABSENT (see EncryptArgs).
}

pub fn cmd_decrypt_message(args: DecryptArgs) -> Result<()> {
    let armored = read_input(&args.input)?;
    // Use strict armor parsing with label enforcement.
    let env: Zeroizing<Vec<u8>> = Zeroizing::new(armor::dearmor_with_label(
        &String::from_utf8_lossy(&armored),
        ARMOR_MSG,
    )?);
    // Wipe the armored copy now — we have the binary envelope. `armored`
    // is `Zeroizing<Vec<u8>>`, so Drop wipes it. But we drop explicitly
    // to release the memory ASAP (before passphrase prompt).
    drop(armored);

    let passphrase = get_passphrase(&args.pass_file, &args.pass_fd, "Passphrase: ")?;

    // Enforce MIN_PASS on decrypt too. The previous behavior of
    // enforcing MIN_PASS only on encrypt could leak information: an
    // adversary observing the error message ("passphrase too short" vs
    // "bad passphrase") could determine whether a short passphrase was
    // attempted. For uniform behavior, we enforce the same minimum on
    // both paths.
    //
    // We do NOT bail with "passphrase too short" — that would leak the
    // length. We bail with the same uniform "bad" error used for wrong
    // passphrases. The length check is purely a defense against
    // accidental submission of empty or 1-char passphrases that would
    // waste Argon2id cycles.
    if passphrase.len() < MIN_PASS {
        bail!("bad");
    }

    eprintln!("[fortis] Deriving key, verifying commit tag, decrypting…");
    // `decrypt_envelope` consumes `passphrase` by value (wiped inside
    // Argon2id). `env` is `Zeroizing<Vec<u8>>` and is wiped on Drop. On
    // the Err path we return Err (not std::process::exit) so Drop runs.
    let pt = match envelope::decrypt_envelope(env.as_slice(), passphrase) {
        Ok(pt) => pt,
        Err(_) => {
            // Returning `Err` (not `std::process::exit(1)`) ensures Drop
            // impls run: the `env` buffer (ciphertext) and any other
            // locals are wiped. main() prints only the top-level Display
            // message (no chain), so the operator sees a single curated
            // line.
            //
            // The message is uniform with `cmd_decrypt_file` so an
            // observer cannot distinguish message-decrypt failure from
            // file-decrypt failure by stderr text (the subcommand choice
            // is already visible in /proc/PID/cmdline, so no additional
            // leak).
            bail!("decryption failed — wrong passphrase or corrupted/tampered message");
        }
    };
    // `env` is dropped here (Zeroizing wipes it) before we write output.
    drop(env);
    write_output(&args.output, &pt)?;
    eprintln!("[fortis] Decrypted.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt file (binary envelope)
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct EncryptFileArgs {
    /// Input file to encrypt
    #[arg(short = 'i', long, required = true)]
    pub input: PathBuf,

    /// Output file (default: <input>.frts)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    #[arg(short = 'k', long, value_enum, default_value_t = KdfPresetArg::Standard)]
    pub kdf: KdfPresetArg,

    #[arg(long)]
    pub paranoid: bool,

    /// Read passphrase from this file (one line).
    #[arg(long)]
    pub pass_file: Option<PathBuf>,

    /// Read passphrase from file descriptor N.
    #[arg(long)]
    pub pass_fd: Option<u32>,

    /// Allow re-encrypting an input that already looks like a Fortis
    /// binary envelope. Without this flag, the CLI refuses to
    /// double-wrap a .frts file.
    #[arg(long)]
    pub force: bool,
    // The `pass` field is intentionally ABSENT (see EncryptArgs).
}

pub fn cmd_encrypt_file(args: EncryptFileArgs) -> Result<()> {
    // Use the TOCTOU-safe bounded reader (single open, fstat the fd,
    // read from the same fd).
    let plaintext: Zeroizing<Vec<u8>> =
        open_and_read_bounded(&args.input, MAX_INPUT_SIZE, "input")?;
    if plaintext.len() > MAX_CT {
        bail!("file exceeds 256 MiB limit");
    }

    // Defense-in-depth recursive-encryption check. A .frts file always
    // begins with the "FRT7\x07" magic. If the operator accidentally
    // passes an already-encrypted file as --input, refuse unless --force
    // is given.
    if !args.force && looks_like_fortis_binary(&plaintext) {
        bail!(
            "input appears to be an already-encrypted FORTIS envelope.\n\
             Re-encrypting would double-wrap the data and make decryption confusing.\n\
             If you genuinely need layered encryption, re-run with --force.\n\
             (If you intended to decrypt, use `fortis decrypt-file` instead.)"
        );
    }

    let passphrase = get_passphrase(
        &args.pass_file,
        &args.pass_fd,
        "Passphrase (min 12 chars): ",
    )?;
    if passphrase.len() < MIN_PASS {
        bail!("passphrase must be at least {} characters", MIN_PASS);
    }
    // File metadata: name + mime + size (all encrypted as a prefix)
    let name = args
        .input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.bin")
        .to_string();
    let mime = "application/octet-stream".to_string();
    if name.len() > 1024 {
        bail!("filename too long (max 1024 bytes)");
    }
    let mut combined: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        12 + name.len() + mime.len() + plaintext.len(),
    ));
    combined.extend_from_slice(&(name.len() as u32).to_be_bytes());
    combined.extend_from_slice(name.as_bytes());
    combined.extend_from_slice(&(mime.len() as u32).to_be_bytes());
    combined.extend_from_slice(mime.as_bytes());
    combined.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    combined.extend_from_slice(&plaintext);
    // plaintext is no longer needed — Zeroizing drops it on scope exit.

    // Do NOT print the input filename to stderr. The filename is itself
    // sensitive metadata — it can reveal the operation type, the unit,
    // the date, etc. The operator knows what they encrypted; printing it
    // to a terminal log that may be captured is unacceptable.
    eprintln!("[fortis] Encrypting file…");
    let t0 = std::time::Instant::now();
    // Catch InputAlreadyEncrypted from envelope.rs.
    let env = match envelope::encrypt_envelope(
        &combined,
        passphrase,
        None,
        None,
        args.kdf.to_preset(),
        args.paranoid,
    ) {
        Ok(v) => v,
        Err(e) => {
            let mut found = false;
            let mut src: Option<&dyn std::error::Error> = Some(e.as_ref());
            while let Some(err) = src {
                let msg = err.to_string().to_lowercase();
                if msg.contains("already encrypted") || msg.contains("inputalreadyencrypted") {
                    found = true;
                    break;
                }
                src = err.source();
            }
            if found {
                bail!(
                    "input appears to be an already-encrypted FORTIS envelope.\n\
                     Re-encrypting would double-wrap the data.\n\
                     If you genuinely need layered encryption, re-run with --force."
                );
            }
            return Err(e);
        }
    };
    let elapsed = t0.elapsed();

    let out_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        p.set_extension(format!(
            "{}.frts",
            args.input
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
        ));
        p
    });
    // Refuse to overwrite the input file.
    if let Ok(input_canon) = args.input.canonicalize() {
        if let Some(parent) = out_path.parent() {
            if let Ok(out_canon_parent) = parent.canonicalize() {
                let out_full = out_canon_parent.join(out_path.file_name().unwrap_or_default());
                if input_canon == out_full {
                    bail!("refusing to overwrite input file — use a different --output");
                }
            }
        }
    }
    // Use atomic write with randomized temp file name.
    write_atomic(&out_path, &env)?;
    // Do NOT print envelope size or elapsed time (leaks preset).
    let _ = elapsed;
    let _ = env.len();
    eprintln!("[fortis] Encrypted.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Decrypt file
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DecryptFileArgs {
    #[arg(short = 'i', long, required = true)]
    pub input: PathBuf,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Read passphrase from this file (one line).
    #[arg(long)]
    pub pass_file: Option<PathBuf>,

    /// Read passphrase from file descriptor N.
    #[arg(long)]
    pub pass_fd: Option<u32>,

    /// Allow overwriting an existing output file.
    ///
    /// Without this flag, decrypt-file refuses to overwrite an existing
    /// file. This prevents a crafted .frts file (with a known passphrase
    /// and a manipulated embedded filename) from silently clobbering an
    /// important file in the working directory.
    #[arg(long)]
    pub force: bool,
    // The `pass` field is intentionally ABSENT (see EncryptArgs).
}

pub fn cmd_decrypt_file(args: DecryptFileArgs) -> Result<()> {
    // Use the TOCTOU-safe bounded reader. `env` is wrapped in
    // `Zeroizing` so it is wiped on Drop (including the Err-return path,
    // since Drop runs during unwinding).
    let env: Zeroizing<Vec<u8>> = open_and_read_bounded(&args.input, MAX_INPUT_SIZE, "input")?;
    let passphrase = get_passphrase(&args.pass_file, &args.pass_fd, "Passphrase: ")?;

    // Enforce MIN_PASS on decrypt_file too (same as decrypt_message).
    if passphrase.len() < MIN_PASS {
        bail!("bad");
    }

    eprintln!("[fortis] Decrypting file…");
    // On Err, return Err (not std::process::exit) so Drop runs.
    let combined: Zeroizing<Vec<u8>> = match envelope::decrypt_envelope(env.as_slice(), passphrase)
    {
        Ok(c) => c,
        Err(_) => {
            // Returning `Err` (not `std::process::exit(1)`) ensures Drop
            // impls run: the `env` buffer (ciphertext) is wiped. main()
            // prints only the top-level Display message.
            bail!("decryption failed — wrong passphrase or corrupted file");
        }
    };
    // `env` is no longer needed — drop to wipe before parsing metadata.
    drop(env);

    // Parse metadata prefix
    if combined.len() < 12 {
        bail!("corrupted file metadata");
    }
    let mut o = 0;
    let name_len = u32::from_be_bytes([
        combined[o],
        combined[o + 1],
        combined[o + 2],
        combined[o + 3],
    ]) as usize;
    o += 4;
    if name_len > 1024 || o + name_len > combined.len() {
        bail!("corrupted filename");
    }
    let name = String::from_utf8_lossy(&combined[o..o + name_len]).to_string();
    o += name_len;
    // Boundary check before reading mime_len: the previous `o + name_len > combined.len()`
    // check accepts `o + name_len == combined.len()`, leaving no room for the 4-byte
    // mime_len field and causing an index-out-of-bounds panic on the next read.
    if o + 4 > combined.len() {
        bail!("corrupted file metadata");
    }
    let mime_len = u32::from_be_bytes([
        combined[o],
        combined[o + 1],
        combined[o + 2],
        combined[o + 3],
    ]) as usize;
    o += 4;
    if mime_len > 256 || o + mime_len > combined.len() {
        bail!("corrupted MIME");
    }
    let _mime = String::from_utf8_lossy(&combined[o..o + mime_len]).to_string();
    o += mime_len;
    // Boundary check before reading orig_size (same rationale as above).
    if o + 4 > combined.len() {
        bail!("corrupted file metadata");
    }
    let orig_size = u32::from_be_bytes([
        combined[o],
        combined[o + 1],
        combined[o + 2],
        combined[o + 3],
    ]) as usize;
    o += 4;
    let content = &combined[o..];
    if content.len() != orig_size {
        // Use a uniform "bad" message: leaking orig_size and
        // content.len() could reveal structural information about the
        // decrypted file to a terminal-log adversary.
        bail!("bad");
    }

    // Sanitize the filename to prevent path traversal.
    let safe_name = sanitize_filename(&name);
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(safe_name.clone()));
    // Refuse to overwrite the input file.
    if let Ok(input_canon) = args.input.canonicalize() {
        if let Some(out_canon) = out_path.parent().and_then(|p| p.canonicalize().ok()) {
            let out_full = out_canon.join(out_path.file_name().unwrap_or_default());
            if input_canon == out_full {
                bail!("refusing to overwrite input file — use a different --output");
            }
        }
    }
    // Refuse to overwrite an existing output file unless --force is given.
    // This blocks a crafted-.frts clobber attack: an adversary who knows
    // the passphrase can craft a file whose embedded filename matches a
    // victim file in the working directory, then trick the user into
    // running `fortis decrypt-file -i malicious.frts`.
    if out_path.exists() && !args.force {
        bail!(
            "output file '{}' already exists — use --force to overwrite",
            out_path.display()
        );
    }
    // Use atomic write with randomized temp file name.
    write_atomic(&out_path, content)?;
    // Do NOT print the output path or elapsed time. The path reveals
    // the decrypted filename (which itself may be sensitive), and
    // elapsed time reveals the KDF preset used by the encryptor. The
    // operator can `ls` the output directory if they need to confirm
    // the file was written.
    eprintln!("[fortis] Decrypted.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Shamir share split / combine
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct ShareSplitArgs {
    #[arg(short = 'i', long)]
    pub input: Option<PathBuf>,

    #[arg(short = 'k', long, default_value_t = 2)]
    pub threshold: u8,

    #[arg(short = 'n', long, default_value_t = 3)]
    pub total: u8,
}

pub fn cmd_share_split(args: ShareSplitArgs) -> Result<()> {
    let secret: Zeroizing<Vec<u8>> = read_input(&args.input)?;
    let shares = shamir::split(&secret, args.threshold, args.total)?;
    // Do NOT print N (total) or the share index in the human-readable
    // header. A header like `=== Share {i}/{N} (x={x}) ===` would reveal
    // the total number of shares to anyone reading the terminal log. The
    // share data itself already contains the x-coordinate (byte 1 of each
    // share), so repeating it in the header is redundant and the total N
    // is a metadata leak. The operator can label shares offline if needed.
    for share in shares.iter() {
        let armored = armor::armor(ARMOR_SHARE, share);
        println!("=== FORTIS Share ===");
        println!("{}", armored);
        println!();
    }
    // Do NOT print N or K to stderr. A message like `Split into {N}
    // shares (threshold {K})` reveals both the total share count and
    // the quorum threshold to terminal-log adversaries. Print only a
    // generic success message. The operator knows N and K (they
    // specified them on the command line).
    eprintln!("[fortis] Split complete.");
    Ok(())
}

#[derive(Args)]
pub struct ShareCombineArgs {
    /// Files containing shares (one per file). If omitted, reads shares from stdin
    /// separated by blank lines.
    #[arg(short = 's', long = "share")]
    pub shares: Vec<PathBuf>,

    /// Threshold K must be specified by the caller, NOT read from the
    /// share header (which an attacker could tamper with).
    #[arg(short = 'k', long, default_value_t = 2)]
    pub threshold: u8,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

pub fn cmd_share_combine(args: ShareCombineArgs) -> Result<()> {
    // Validate threshold up front. Deferring all validation to
    // shamir::combine would print a hardcoded "need at least 2 shares"
    // message that leaks the internal minimum. We validate the
    // threshold range here and use the caller's threshold for the
    // share-count check below.
    if !(2..=10).contains(&args.threshold) {
        bail!("bad");
    }

    let mut share_blobs: Vec<Vec<u8>> = Vec::new();
    if args.shares.is_empty() {
        // Bounded read from stdin to prevent OOM.
        // Wrap in Zeroizing so share data is wiped on drop.
        let mut input: Zeroizing<String> = Zeroizing::new(String::new());
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut chunk = [0u8; 65536];
        loop {
            let n = handle.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            // Avoid per-iteration String allocation that is not
            // zeroized. We push the raw bytes directly into the
            // Zeroizing<String> via push_str after a single lossy
            // conversion. The intermediate Cow from from_utf8_lossy is
            // short-lived (dropped at the end of this expression) but
            // its owned variant (if any) is NOT zeroized — accepted as
            // a minor residual leak since the data is share material
            // (not the secret itself) and the window is one iteration.
            input.push_str(&String::from_utf8_lossy(&chunk[..n]));
            if input.len() > MAX_INPUT_SIZE {
                bail!(
                    "stdin input exceeds {} MiB limit",
                    MAX_INPUT_SIZE / (1024 * 1024)
                );
            }
        }
        // Use the strict armor parser that validates BEGIN/END labels
        // match "FORTIS SHARE". Count shares as we parse, with a hard
        // cap to prevent DoS.
        let mut current = String::new();
        let mut in_block = false;
        for line in input.lines() {
            let trimmed = line.trim_end_matches('\r');
            if trimmed.starts_with("-----BEGIN FORTIS SHARE-----") {
                if in_block {
                    bail!("bad");
                }
                in_block = true;
                current.clear();
                current.push_str(trimmed);
                current.push('\n');
            } else if trimmed.starts_with("-----END FORTIS SHARE-----") {
                if !in_block {
                    bail!("bad");
                }
                in_block = false;
                current.push_str(trimmed);
                let bytes = armor::dearmor_with_label(&current, "FORTIS SHARE")?;
                share_blobs.push(bytes);
                current.clear();
                // Cap the number of shares at 10 (matches the max N
                // allowed by shamir::split). An attacker who pipes
                // millions of fake shares through stdin could otherwise
                // exhaust memory and CPU before the threshold check
                // rejects the combine.
                if share_blobs.len() > 10 {
                    bail!("too many shares (max 10)");
                }
            } else if in_block {
                current.push_str(trimmed);
                current.push('\n');
            }
            // Lines outside any BEGIN..END block are silently ignored
            // (allows for human-readable comments between shares).
        }
        if in_block {
            // Unterminated BEGIN block.
            bail!("bad");
        }
        // `input` (Zeroizing<String>) is wiped on drop at end of scope.
    } else {
        // Cap the number of share files at 10.
        if args.shares.len() > 10 {
            bail!("too many share files (max 10)");
        }
        for path in &args.shares {
            // Use the TOCTOU-safe bounded reader. Share files are
            // secret material (K shares reconstruct the secret), so we
            // also wrap the read data in Zeroizing.
            let content_bytes: Zeroizing<Vec<u8>> =
                open_and_read_bounded(path, MAX_INPUT_SIZE, "share")?;
            // Convert to String for the armor parser. The String is
            // short-lived; we wipe it via Zeroizing's Drop.
            let content = String::from_utf8_lossy(&content_bytes).into_owned();
            let content_z: Zeroizing<String> = Zeroizing::new(content);
            let bytes = armor::dearmor_with_label(&content_z, "FORTIS SHARE")?;
            // Zeroizing::drop wipes the String via volatile writes; no
            // manual `unsafe` wipe is needed (and a manual `*b = 0` loop
            // would be subject to LLVM dead-store elimination anyway).
            drop(content_z);
            share_blobs.push(bytes);
        }
    }
    // Check against the caller's threshold, not a hardcoded "2". A
    // hardcoded `share_blobs.len() < 2` would accept fewer shares than
    // the threshold and let shamir::combine detect the mismatch,
    // leaking the hardcoded minimum.
    if share_blobs.len() < args.threshold as usize {
        bail!("bad");
    }
    // Defensive re-check (should never trigger given the caps above,
    // but defense in depth).
    if share_blobs.len() > 10 {
        bail!("too many shares (max 10)");
    }
    // Pass the caller-specified threshold, not from shares.
    let secret = shamir::combine(&share_blobs, args.threshold)?;

    // Wipe share blobs — they are secret material.
    for blob in share_blobs.iter_mut() {
        use zeroize::Zeroize;
        blob.zeroize();
    }
    write_output(&args.output, &secret)?;
    // Do NOT print K or the share count to stderr. A message like
    // `Reconstructed from {K} shares (threshold {K})` reveals the
    // quorum threshold to terminal-log adversaries.
    eprintln!("[fortis] Reconstructed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitize a filename extracted from ciphertext to prevent path traversal.
///
/// An attacker who can craft a ciphertext (e.g., a coerced user is forced
/// to decrypt an attacker-crafted file) can embed a malicious filename
/// like `../../../etc/cron.d/backdoor`. Without sanitization, the
/// decrypted content is written to that path → RCE.
///
/// This function:
///   1. Rejects any path separators (`/`, `\`, U+FF0F fullwidth slash,
///      U+2044 fraction slash).
///   2. Rejects `..` components.
///   3. Rejects absolute paths.
///   4. Rejects control characters (0x00-0x1F, 0x7F-0x9F).
///   5. Rejects Windows reserved names (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
///   6. Rejects Unicode bidi override characters (U+202A-U+202E, U+2066-U+2069)
///      — these can cause display-time confusion where the filename appears
///      as one thing but is actually another (e.g., "txt.exe" displayed as
///      "txt.exe" with hidden ".bat" prefix).
///   7. Rejects zero-width characters (U+200B-U+200F, U+FEFF) — these can
///      create visually identical but distinct filenames, used for phishing
///      and to bypass "don't overwrite" checks.
///   8. Rejects trailing dots and spaces (Windows strips these, allowing
///      "secret.txt." to collide with "secret.txt").
///   9. Truncates to 255 bytes (filesystem limit), on a UTF-8 char boundary.
///  10. Falls back to "decrypted.bin" if the filename is empty/invalid.
fn sanitize_filename(name: &str) -> String {
    // Strip path separators FIRST, including Unicode lookalikes. Use the
    // basename (last path component) — this rejects any embedded `/`,
    // `\`, or lookalike that would split the path.
    let basename: String = name
        .rsplit(|c| {
            c == '/' || c == '\\'
                // Fullwidth solidus U+FF0F (looks like /)
                || c == '\u{FF0F}'
                // Fraction slash U+2044
                || c == '\u{2044}'
                // Reverse solidus lookalikes
                || c == '\u{FF3C}'  // fullwidth reverse solidus
                // Other Unicode separator categories
                || (c as u32 >= 0x2028 && c as u32 <= 0x2029)
        })
        .next()
        .unwrap_or("")
        .to_string();

    if basename == ".." || basename == "." || basename.is_empty() {
        return "decrypted.bin".to_string();
    }

    // Filter out dangerous Unicode categories AND ASCII characters that
    // are illegal in Windows filenames. Even though Fortis is Unix-only
    // (enforced by compile_error!), decrypted files may be transferred
    // to Windows machines via USB or network share. A filename like
    // "report:secret" would silently truncate to "report" on Windows
    // (NTFS ADS), causing data loss. "NUL.txt" would be rejected by
    // Windows but the operator may not understand why.
    let cleaned: String = basename
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            // Reject ASCII control chars (0x00-0x1F, 0x7F)
            if cp < 0x20 || cp == 0x7F {
                return false;
            }
            // Reject C1 control chars (0x80-0x9F)
            if (0x80..=0x9F).contains(&cp) {
                return false;
            }
            // Reject NUL explicitly
            if *c == '\0' {
                return false;
            }
            // Reject replacement char
            if *c == '\u{FFFD}' {
                return false;
            }
            // Reject bidi override characters (U+202A-U+202E, U+2066-U+2069)
            if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
                return false;
            }
            // Reject zero-width characters
            if cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF {
                return false;
            }
            // Reject zero-width space and joiners that affect rendering
            if (0x200B..=0x200F).contains(&cp) {
                return false;
            }
            // Reject path separator lookalikes
            if *c == '\u{FF0F}' || *c == '\u{2044}' || *c == '\u{FF3C}' {
                return false;
            }
            // Reject Windows-illegal ASCII chars. Even though Fortis is
            // Unix-only, decrypted files may be transferred to Windows.
            // Rejecting them now prevents silent data loss.
            //   : → NTFS Alternate Data Stream separator
            //   * → wildcard (cmd.exe)
            //   ? → wildcard (cmd.exe)
            //   " → quote (cmd.exe, also illegal in NTFS)
            //   < > → redirect operators (cmd.exe, illegal in NTFS)
            //   | → pipe operator (cmd.exe, illegal in NTFS)
            if *c == ':'
                || *c == '*'
                || *c == '?'
                || *c == '"'
                || *c == '<'
                || *c == '>'
                || *c == '|'
            {
                return false;
            }
            true
        })
        .collect();

    if cleaned.is_empty() {
        return "decrypted.bin".to_string();
    }

    // Reject trailing dots and spaces (Windows strips them, allowing
    // "secret.txt." to collide with "secret.txt").
    let trimmed = cleaned.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() {
        return "decrypted.bin".to_string();
    }
    let cleaned = trimmed.to_string();

    let mut bytes = cleaned.into_bytes();
    if bytes.len() > 255 {
        bytes.truncate(255);
        // Walk back to a valid UTF-8 boundary.
        while !bytes.is_empty() && (bytes[bytes.len() - 1] & 0xC0) == 0x80 {
            bytes.pop();
        }
        // If we ended mid-character, drop the partial leading byte.
        if !bytes.is_empty() {
            let last = bytes[bytes.len() - 1];
            // Check if `last` is a leading byte expecting more continuation
            // bytes than we have. If so, drop it.
            let expected = if last >= 0xF0 {
                3
            } else if last >= 0xE0 {
                2
            } else if last >= 0xC0 {
                1
            } else {
                0
            };
            // Count continuation bytes after `last`.
            let mut actual = 0;
            for i in (bytes.len() - expected - 1..bytes.len() - 1).rev() {
                if i < bytes.len() - 1 && (bytes[i + 1] & 0xC0) == 0x80 {
                    actual += 1;
                } else {
                    break;
                }
            }
            if actual < expected {
                bytes.pop();
            }
        }
    }
    let s = String::from_utf8(bytes).unwrap_or_else(|_| "decrypted.bin".to_string());
    let upper = s.to_uppercase();
    let stem = upper.split('.').next().unwrap_or("");
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    // Check the uppercased stem (without extension) against the reserved
    // list. For "NUL.txt" the stem is "NUL" — matches.
    if reserved.contains(&stem) {
        return format!("fortis_{}", s);
    }
    s
}

/// `--pass` is intentionally ABSENT from the CLI struct, so clap rejects
/// it at parse time before any String allocation occurs. The passphrase
/// can come from:
///   1. --pass-fd <N>      — read from file descriptor N (most secure for scripting)
///   2. --pass-file <path> — read from a file (path appears in cmdline, but not the passphrase)
///   3. FORTIS_PASS env var — read from environment (not in cmdline, but in /proc/PID/environ)
///   4. Interactive prompt  — most secure for interactive use (never leaves terminal)
fn get_passphrase(
    pass_file: &Option<PathBuf>,
    pass_fd: &Option<u32>,
    prompt: &str,
) -> Result<SecretBytes> {
    // Priority 1: --pass-fd (read from file descriptor — most secure for scripting)
    if let Some(fd) = pass_fd {
        return read_passphrase_from_fd(*fd);
    }

    // Priority 2: --pass-file (read from a file — path in cmdline, but not passphrase)
    if let Some(path) = pass_file {
        return read_passphrase_from_file(path);
    }

    // Priority 3: FORTIS_PASS environment variable.
    //
    // std::env::var and std::env::remove_var are NOT thread-safe — they
    // mutate a shared global environment. Rust marks them `unsafe` to
    // force the caller to acknowledge this. In Fortis, main() is
    // single-threaded at this point (no threads have been spawned yet),
    // so the unsafe is sound. If Fortis ever becomes multi-threaded
    // (e.g., for parallel Argon2id lanes via rayon), this code MUST be
    // moved to a single-threaded initialization phase.
    //
    // SECURITY caveat about /proc/PID/environ: On Linux, /proc/PID/environ
    // contains a SNAPSHOT of the environment at execve time.
    // std::env::remove_var updates the in-memory environ but does NOT
    // update /proc/PID/environ. The env var remains visible to ANY
    // process with the same UID for the ENTIRE lifetime of the process.
    // Prefer --pass-fd or interactive prompt. The env var is provided as
    // a convenience for CI/testing ONLY, and we print a warning when
    // it's used.
    if let Ok(p) = std::env::var("FORTIS_PASS") {
        eprintln!("[fortis] WARNING: FORTIS_PASS env var is visible in /proc/PID/environ");
        eprintln!("[fortis]          to ALL processes with the same UID for the process lifetime.");
        eprintln!("[fortis]          For production use, prefer --pass-fd or interactive prompt.");
        // Remove the env var from this process AND from any child
        // processes we might spawn, before we use it.
        // SAFETY: single-threaded context (no threads spawned yet).
        // NOTE: This does NOT remove it from /proc/PID/environ — see above.
        unsafe {
            std::env::remove_var("FORTIS_PASS");
        }
        // Wrap the String in Zeroizing<String> so the heap buffer is
        // wiped when we are done.
        let z: Zeroizing<String> = Zeroizing::new(p);
        let sb = SecretBytes::from_slice(z.as_bytes());
        // Zeroizing::drop on `z` (at end of scope) wipes the String via
        // volatile writes; no manual `unsafe` wipe is needed.
        return Ok(sb);
    }

    // Priority 4: interactive prompt (most secure for interactive use)
    memory::read_passphrase(prompt).map_err(|e| anyhow!("passphrase read failed: {}", e))
}

/// Read the decoy passphrase from --decoy-pass-fd or --decoy-pass-file.
/// Mirrors `get_passphrase` but never reads from a CLI string and never
/// falls back to interactive prompt (the decoy passphrase is optional
/// and must be supplied explicitly).
fn get_decoy_passphrase(
    decoy_pass_file: &Option<PathBuf>,
    decoy_pass_fd: &Option<u32>,
) -> Result<SecretBytes> {
    if let Some(fd) = decoy_pass_fd {
        return read_passphrase_from_fd(*fd);
    }
    if let Some(path) = decoy_pass_file {
        return read_passphrase_from_file(path);
    }
    bail!("--decoy requires --decoy-pass-file or --decoy-pass-fd");
}

/// Read a passphrase from a file descriptor (one byte at a time into a
/// pre-allocated mlock'd SecretBytes buffer).
///
/// Bounded read — never reads more than MAX_PASS_LEN bytes from the fd,
/// preventing a malicious fd writer from causing OOM.
///
/// Polls the fd with a 60-second timeout. A blocked `file.read(&mut byte)`
/// on a pipe whose writer never closes would leave the operator stuck
/// with no way to cancel except SIGKILL. We bail with an error if no
/// data arrives within 60 seconds.
const PASSPHRASE_FD_TIMEOUT_SECS: i32 = 60;

fn read_passphrase_from_fd(fd: u32) -> Result<SecretBytes> {
    // Validate fd value before casting to i32.
    if fd > (i32::MAX as u32) {
        bail!("bad");
    }
    let fd_i32 = fd as i32;
    let mut buf = SecretBytes::new(memory::MAX_PASS_LEN);
    let mut len = 0usize;
    let mut byte = [0u8; 1];

    // Create the File wrapper ONCE before the loop, then forget it
    // AFTER the loop. We use ManuallyDrop to prevent the File from
    // closing the fd (caller owns it).
    use std::mem::ManuallyDrop;
    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd_i32) });

    while len < memory::MAX_PASS_LEN {
        // Poll the fd before each read. If no data within
        // PASSPHRASE_FD_TIMEOUT_SECS, bail. This prevents indefinite
        // hangs on misbehaving pipe writers.
        #[cfg(unix)]
        unsafe {
            let mut pfd = libc::pollfd {
                fd: fd_i32,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = libc::poll(&mut pfd, 1, PASSPHRASE_FD_TIMEOUT_SECS * 1000);
            if ret < 0 {
                return Err(anyhow::anyhow!("bad"));
            }
            if ret == 0 {
                return Err(anyhow::anyhow!("bad"));
            }
            if (pfd.revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                return Err(anyhow::anyhow!("bad"));
            }
            if (pfd.revents & libc::POLLHUP) != 0 && (pfd.revents & libc::POLLIN) == 0 {
                break;
            }
        }

        match file.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break;
                }
                buf.as_bytes_mut()[len] = byte[0];
                len += 1;
            }
            Err(_) => return Err(anyhow::anyhow!("bad")),
        }
    }
    // file is ManuallyDrop — the fd is NOT closed (caller owns it).
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    buf.wipe();
    // Zeroize the 1-byte stack buffer that held the last passphrase byte
    // read. Without this, `byte[0]` lingers on the stack frame until the
    // function returns and the stack slot is reused by the caller — a
    // small but real leak of the final passphrase character.
    use zeroize::Zeroize;
    byte.zeroize();
    Ok(passphrase)
}

/// Read a passphrase from a file (one line, trailing newline stripped).
///
/// Bounded read — checks file size before read_to_string, and refuses
/// files larger than MAX_PASS_LEN+1 (allowing for a trailing newline).
/// This prevents OOM via a malicious pass-file.
///
/// TOCTOU-safe: opens the file ONCE, fstats the fd, and reads from the
/// same fd.
fn read_passphrase_from_file(path: &PathBuf) -> Result<SecretBytes> {
    // Single open + fstat + read from the same fd.
    let file = std::fs::File::open(path).map_err(|e| anyhow!("--pass-file open failed: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("--pass-file metadata failed: {}", e))?;
    if !metadata.is_file() {
        bail!("--pass-file is not a regular file");
    }
    // Check file size before reading.
    if metadata.len() as usize > memory::MAX_PASS_LEN + 1 {
        bail!("--pass-file too large (max {} bytes)", memory::MAX_PASS_LEN);
    }
    let mut content = String::new();
    // Take ownership of the file in a Read wrapper. Read from the SAME
    // fd that we fstat'd — no TOCTOU.
    let mut reader = file;
    reader
        .read_to_string(&mut content)
        .map_err(|e| anyhow!("--pass-file read failed: {}", e))?;
    // Wrap in Zeroizing<String> so the buffer is wiped on drop.
    let line: Zeroizing<String> = Zeroizing::new(content);
    let mut line = line;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.len() > memory::MAX_PASS_LEN {
        // Truncate defensively (should not happen given the size check above).
        line.truncate(memory::MAX_PASS_LEN);
    }
    let sb = SecretBytes::from_slice(line.as_bytes());
    // Zeroizing::drop on `line` (at end of scope) wipes the String via
    // volatile writes; no manual `unsafe` wipe is needed.
    Ok(sb)
}

/// Maximum input size to prevent memory-exhaustion DoS. Bumped from
/// 300 MiB to 512 MiB: a 256 MiB binary envelope (the legitimate max)
/// becomes ~341 MiB after base64 encoding (+33% overhead). With the
/// BEGIN/END armor headers and 64-char-per-line wrapping, an armored
/// 256 MiB ciphertext is ~342 MiB. The old 300 MiB limit would reject
/// legitimate large armored messages. 512 MiB provides ample headroom.
const MAX_INPUT_SIZE: usize = 512 * 1024 * 1024;

/// Write to a temp file with a randomized name, then atomically rename
/// to the final path. The random name prevents symlink attacks where an
/// attacker pre-creates a symlink at the predictable `.frts.tmp` path
/// pointing to a privileged file.
///
/// The temp file is created with mode 0600 on Unix so that no other user
/// can read the (possibly sensitive) output. The file is created with
/// 0600 FROM THE START via `OpenOptions::mode(0o600)`, eliminating the
/// previous race window where the file briefly existed with default
/// umask (typically 0644) before `set_permissions` was called. The final
/// file (after rename) inherits these permissions.
///
/// The temp file is fsync'd before the rename, and the parent directory
/// is fsync'd after the rename, ensuring the data is on disk before we
/// report success. Without this, a power loss after `rename` could leave
/// the file empty or corrupt.
fn write_atomic(final_path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 16 bytes of OsRng entropy (128 bits) plus pid+timestamp gives
    // well over 64 bits of unpredictability for the temp suffix, which
    // is sufficient to defeat predictive-symlink attacks on local
    // filesystems. The temp file is created with create_new(true) so an
    // attacker cannot pre-create it (symlink or otherwise).
    let mut rng_buf = [0u8; 16];
    crate::crypto::rng::fill(&mut rng_buf);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let suffix: String = rng_buf.iter().map(|b| format!("{:02x}", b)).collect();
    let tmp_name = format!(".fortis.tmp.{}.{}.{}", pid, ts, suffix);
    let tmp_path = final_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(tmp_name);

    // Create the temp file with 0600 FROM THE START. Using
    // OpenOptions::mode() ensures the file is created with the correct
    // permissions atomically — there is no window where the file exists
    // with default umask (0644) permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| anyhow!("temp file create failed: {}", e))?;
        file.write_all(data)
            .map_err(|e| anyhow!("temp file write failed: {}", e))?;
        // fsync the file before rename so the data is durable on disk.
        // Without this, a power loss between write() and rename() could
        // leave the file empty.
        file.sync_all()
            .map_err(|e| anyhow!("temp file fsync failed: {}", e))?;
        // Drop the file handle before rename (Windows requires this).
        drop(file);
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, data)?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, final_path) {
        // Retry the temp file cleanup before bailing. On a full disk or
        // read-only filesystem, the temp file containing encrypted
        // plaintext would otherwise remain on disk indefinitely. We
        // retry up to 3 times with short delays, and if all retries
        // fail, we panic with a clear message so the operator knows to
        // manually shred the temp file.
        let mut last_remove_err = None;
        for attempt in 0..3 {
            // Brief delay between retries to allow the filesystem to
            // recover from transient failures (e.g., NFS lag).
            std::thread::sleep(std::time::Duration::from_millis(50 * (1 << attempt)));
            match std::fs::remove_file(&tmp_path) {
                Ok(()) => {
                    last_remove_err = None;
                    break;
                }
                Err(re) => {
                    last_remove_err = Some(re);
                }
            }
        }
        if let Some(re) = last_remove_err {
            // Could not remove the temp file. The encrypted plaintext is
            // still on disk at tmp_path. Panic so the operator sees the
            // path and can manually shred it. The custom panic hook
            // (main.rs) will print a generic message; we print the temp
            // path HERE before panicking so the operator can shred it.
            // The path itself is not secret (it contains pid,
            // timestamp, and a random suffix — no key material).
            eprintln!(
                "[fortis] FATAL: atomic rename failed ({}) AND temp file cleanup failed ({}).",
                e, re
            );
            eprintln!(
                "[fortis] ENCRYPTED TEMP FILE REMAINS AT: {}",
                tmp_path.display()
            );
            eprintln!(
                "[fortis] Manually shred this file: shred -u \"{}\"",
                tmp_path.display()
            );
            panic!("fortis: atomic write failed and temp cleanup failed");
        }
        return Err(anyhow::anyhow!("bad"));
    }

    // fsync the parent directory so the rename is durable. Without this,
    // a power loss after rename could leave the directory entry pointing
    // to nothing.
    #[cfg(unix)]
    {
        if let Some(parent) = final_path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }

    // Also set 0600 on the final path (defense in depth).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(final_path, perms);
    }
    Ok(())
}

fn read_input(path: &Option<PathBuf>) -> Result<Zeroizing<Vec<u8>>> {
    match path {
        Some(p) => {
            // Use the TOCTOU-safe bounded reader.
            open_and_read_bounded(p, MAX_INPUT_SIZE, "input")
        }
        None => {
            // Bounded read from stdin to prevent OOM.
            let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            let mut chunk = [0u8; 65536];
            loop {
                let n = handle.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_INPUT_SIZE {
                    bail!(
                        "stdin input exceeds {} MiB limit",
                        MAX_INPUT_SIZE / (1024 * 1024)
                    );
                }
            }
            Ok(buf)
        }
    }
}

fn write_output(path: &Option<PathBuf>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) => {
            // Use write_atomic so the output file gets 0600 permissions
            // even when written via --output.
            write_atomic(p, data)?;
        }
        None => {
            // Refuse to write binary data to a TTY. Writing binary bytes
            // to a terminal may:
            //   - corrupt the terminal (lost cursor, wrong colors)
            //   - execute escape-sequence payloads (e.g., the "DECEMBER"
            //     attack where the terminal title is changed)
            //   - in rare cases, trigger terminal emulator
            //     vulnerabilities (e.g., xterm CSI sequences)
            // The operator should explicitly redirect to a file
            // (`fortis encrypt -o file.frts`) or pipe to another command.
            use std::io::IsTerminal;
            if io::stdout().is_terminal() {
                // Allow armored output (printable ASCII only) but refuse
                // raw binary. We check the first 16 bytes for
                // non-printable chars as a heuristic.
                let looks_binary = data.iter().take(64).any(|&b| {
                    b != b'\n' && b != b'\r' && b != b'\t' && !(0x20..=0x7E).contains(&b)
                });
                if looks_binary {
                    bail!(
                        "refusing to write binary data to terminal — \
                         redirect to a file with --output or pipe to another command"
                    );
                }
            }
            // io::stdout() is buffered (LineWriter when TTY, BufWriter
            // when not). The buffer holds a copy of the data (which may
            // be plaintext for `fortis decrypt` or ciphertext for `fortis
            // encrypt`) and is NOT zeroized on flush. A future hardening
            // pass could use a Zeroizing-wrapped writer. For now, the
            // buffer is small (default 8 KiB) and is overwritten on the
            // next write.
            io::stdout().write_all(data)?;
        }
    }
    Ok(())
}
