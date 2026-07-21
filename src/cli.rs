//! CLI argument parsing and command dispatch.
//!
//! Plaintext buffers are wrapped in `Zeroizing<Vec<u8>>`. Output files
//! use mode 0600 on Unix. Decrypt-failure paths return Err so Drop impls
//! wipe secrets; the decoy-vs-real passphrase check uses
//! `subtle::ConstantTimeEq`.

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

/// Binary envelope magic "SHR1" + version byte 1. Used to detect
/// already-encrypted input.
const SHERD_BINARY_MAGIC: &[u8] = b"SHR1";

/// Armored message header line. Used to detect re-encryption of an
/// already-armored message.
const SHERD_ARMOR_PREFIX: &str = "-----BEGIN SHERD MESSAGE-----";

fn looks_like_sherd_binary(data: &[u8]) -> bool {
    data.len() >= 5 && &data[..4] == SHERD_BINARY_MAGIC && data[4] == VERSION
}

fn looks_like_sherd_armored(data: &[u8]) -> bool {
    // Require valid UTF-8 and the armor prefix after leading whitespace
    // to avoid false positives on binary data.
    match std::str::from_utf8(data) {
        Ok(s) => s
            .trim_start_matches(|c: char| c.is_whitespace())
            .starts_with(SHERD_ARMOR_PREFIX),
        Err(_) => false,
    }
}

/// True if the input looks like an already-encrypted Sherd artifact.
fn looks_like_sherd_output(data: &[u8]) -> bool {
    looks_like_sherd_binary(data) || looks_like_sherd_armored(data)
}

// ---------------------------------------------------------------------------
// TOCTOU-safe bounded file reader
// ---------------------------------------------------------------------------

/// Open the file once, fstat the fd, then read from the same fd. The
/// naive metadata + read pattern opens twice and an attacker who swaps
/// the path between calls can point the second read at a non-regular,
/// unbounded file. Rejects non-regular files and files larger than `max`.
/// `label` is used in error messages so the operator knows which path
/// failed without the absolute path being echoed.
fn open_and_read_bounded(
    path: &std::path::Path,
    max: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).map_err(|e| anyhow!("{} open failed: {}", label, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("{} metadata failed: {}", label, e))?;
    // We hold the only fd, so the attacker cannot swap the path between
    // the is_file check and the read.
    if !metadata.is_file() {
        bail!(
            "{} is not a regular file (devices, FIFOs, sockets not allowed)",
            label
        );
    }
    if metadata.len() as usize > max {
        bail!("{} exceeds {} MiB limit", label, max / (1024 * 1024));
    }
    let cap = std::cmp::min(metadata.len() as usize, max);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(cap));
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

    /// Decoy message file for plausible deniability. Requires a decoy passphrase.
    #[arg(long)]
    pub decoy: Option<PathBuf>,

    /// Read decoy passphrase from this file (one line)
    #[arg(long)]
    pub decoy_pass_file: Option<PathBuf>,

    /// Read decoy passphrase from file descriptor N
    #[arg(long)]
    pub decoy_pass_fd: Option<u32>,

    /// Read passphrase from this file (one line). Safer than --pass: the
    /// path, not the passphrase, appears in cmdline.
    #[arg(long)]
    pub pass_file: Option<PathBuf>,

    /// Read passphrase from file descriptor N. Most secure for scripting:
    /// `./sherd encrypt --pass-fd 3 3<passfile`
    #[arg(long)]
    pub pass_fd: Option<u32>,

    /// Allow re-encrypting an input that already looks like a Sherd
    /// artifact. Without this flag the CLI refuses to double-wrap. Use
    /// only when you genuinely need layered encryption.
    #[arg(long)]
    pub force: bool,
    // `--pass X` is intentionally absent: it would put the passphrase in
    // /proc/PID/cmdline, shell history, and `ps aux`. Accepted sources
    // are --pass-fd, --pass-file, SHERD_PASS (debug convenience), or
    // the interactive prompt.
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
    let plaintext: Zeroizing<Vec<u8>> = read_input(&args.input)?;
    if plaintext.is_empty() {
        bail!("plaintext is empty");
    }
    if plaintext.len() > MAX_CT {
        bail!("plaintext exceeds 256 MiB limit");
    }

    // Check here too so the operator gets a clearer message and we skip
    // the Argon2id cost. envelope::encrypt_envelope performs the same
    // check on its own input.
    if !args.force && looks_like_sherd_output(&plaintext) {
        bail!(
            "input appears to be an already-encrypted SHERD message.\n\
             Re-encrypting would double-wrap the data and make decryption confusing.\n\
             If you genuinely need layered encryption, re-run with --force.\n\
             (If you intended to decrypt, use `sherd decrypt` instead.)"
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

    let (decoy_pt, decoy_pass): (Option<Zeroizing<Vec<u8>>>, Option<SecretBytes>) =
        if let Some(decoy_path) = &args.decoy {
            let dp: Zeroizing<Vec<u8>> = read_input(&Some(decoy_path.clone()))?;
            let dpass = get_decoy_passphrase(&args.decoy_pass_file, &args.decoy_pass_fd)?;
            if dpass.len() < MIN_PASS {
                bail!("decoy passphrase must be at least {} characters", MIN_PASS);
            }
            // ConstantTimeEq on &[u8] returns false for different-length
            // slices in constant time. A pre-check on length would
            // short-circuit and leak length-equality via timing.
            let same = bool::from(passphrase.as_bytes().ct_eq(dpass.as_bytes()));
            if same {
                bail!("decoy passphrase must differ from the real passphrase");
            }
            (Some(dp), Some(dpass))
        } else {
            (None, None)
        };

    // Do not print the KDF preset. The name reveals the operator's
    // sensitivity assessment; an adversary with terminal-log access
    // could use it to prioritize targets.
    eprintln!("[sherd] Deriving key (Argon2id)…");

    let t0 = std::time::Instant::now();
    // encrypt_envelope consumes passphrase and decoy_pass by value;
    // both are wiped inside Argon2id. Catch InputAlreadyEncrypted in
    // case the CLI-side check missed a format only envelope.rs recognizes.
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
            // Match InputAlreadyEncrypted by error-chain text. anyhow
            // errors are type-erased, so we match on Display.
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
                    "input appears to be an already-encrypted SHERD message.\n\
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

    // Do not print envelope size or elapsed time. Size correlates with
    // plaintext size and elapsed time reveals the KDF preset.
    let _ = elapsed;
    let _ = env.len();
    eprintln!("[sherd] Encrypted.");
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
    // The `pass` field is intentionally absent; see EncryptArgs.
}

pub fn cmd_decrypt_message(args: DecryptArgs) -> Result<()> {
    let armored = read_input(&args.input)?;
    let env: Zeroizing<Vec<u8>> = Zeroizing::new(armor::dearmor_with_label(
        &String::from_utf8_lossy(&armored),
        ARMOR_MSG,
    )?);
    // Drop the armored copy to release memory before the passphrase prompt.
    drop(armored);

    let passphrase = get_passphrase(&args.pass_file, &args.pass_fd, "Passphrase: ")?;

    // Enforce MIN_PASS with the same uniform "bad" error used for wrong
    // passphrases. A distinct "passphrase too short" message would leak
    // whether a short passphrase was attempted. The length check itself
    // just avoids wasting Argon2id cycles on empty or 1-char submissions.
    if passphrase.len() < MIN_PASS {
        bail!("bad");
    }

    eprintln!("[sherd] Deriving key, verifying commit tag, decrypting…");
    let pt = match envelope::decrypt_envelope(env.as_slice(), passphrase) {
        Ok(pt) => pt,
        Err(_) => {
            // Returning Err runs Drop on env and other locals. main()
            // prints only the top-level Display message. Uniform with
            // cmd_decrypt_file so stderr text does not distinguish the
            // two failure paths.
            bail!("decryption failed: wrong passphrase or corrupted/tampered message");
        }
    };
    drop(env);
    write_output(&args.output, &pt)?;
    eprintln!("[sherd] Decrypted.");
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

    /// Allow re-encrypting an input that already looks like a Sherd
    /// binary envelope. Without this flag, the CLI refuses to
    /// double-wrap a .frts file.
    #[arg(long)]
    pub force: bool,
    // The `pass` field is intentionally absent; see EncryptArgs.
}

pub fn cmd_encrypt_file(args: EncryptFileArgs) -> Result<()> {
    let plaintext: Zeroizing<Vec<u8>> =
        open_and_read_bounded(&args.input, MAX_INPUT_SIZE, "input")?;
    if plaintext.len() > MAX_CT {
        bail!("file exceeds 256 MiB limit");
    }

    // A .frts file begins with the "SHR1\x01" magic. Refuse to
    // double-wrap unless --force is given.
    if !args.force && looks_like_sherd_binary(&plaintext) {
        bail!(
            "input appears to be an already-encrypted SHERD envelope.\n\
             Re-encrypting would double-wrap the data and make decryption confusing.\n\
             If you genuinely need layered encryption, re-run with --force.\n\
             (If you intended to decrypt, use `sherd decrypt-file` instead.)"
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
    // File metadata prefix: name + mime + size, all encrypted.
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

    // Do not print the input filename. Filenames are sensitive metadata.
    eprintln!("[sherd] Encrypting file…");
    let t0 = std::time::Instant::now();
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
                    "input appears to be an already-encrypted SHERD envelope.\n\
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
                    bail!("refusing to overwrite input file, use a different --output");
                }
            }
        }
    }
    write_atomic(&out_path, &env)?;
    // Do not print envelope size or elapsed time; both leak the preset.
    let _ = elapsed;
    let _ = env.len();
    eprintln!("[sherd] Encrypted.");
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
    /// file. This prevents a crafted .frts file with a known passphrase
    /// and a manipulated embedded filename from silently clobbering an
    /// important file in the working directory.
    #[arg(long)]
    pub force: bool,
    // The `pass` field is intentionally absent; see EncryptArgs.
}

pub fn cmd_decrypt_file(args: DecryptFileArgs) -> Result<()> {
    let env: Zeroizing<Vec<u8>> = open_and_read_bounded(&args.input, MAX_INPUT_SIZE, "input")?;
    let passphrase = get_passphrase(&args.pass_file, &args.pass_fd, "Passphrase: ")?;

    // Enforce MIN_PASS with the uniform "bad" error; see cmd_decrypt_message.
    if passphrase.len() < MIN_PASS {
        bail!("bad");
    }

    eprintln!("[sherd] Decrypting file…");
    // Returning Err on failure runs Drop, which wipes env.
    let combined: Zeroizing<Vec<u8>> = match envelope::decrypt_envelope(env.as_slice(), passphrase)
    {
        Ok(c) => c,
        Err(_) => {
            bail!("decryption failed: wrong passphrase or corrupted file");
        }
    };
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
    // Boundary check: leaving no room for the 4-byte mime_len field
    // would panic on the next read.
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
        // Uniform "bad" message; leaking orig_size vs content.len()
        // reveals structural information about the decrypted file.
        bail!("bad");
    }

    let safe_name = sanitize_filename(&name);
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(safe_name.clone()));
    if let Ok(input_canon) = args.input.canonicalize() {
        if let Some(out_canon) = out_path.parent().and_then(|p| p.canonicalize().ok()) {
            let out_full = out_canon.join(out_path.file_name().unwrap_or_default());
            if input_canon == out_full {
                bail!("refusing to overwrite input file, use a different --output");
            }
        }
    }
    // Blocks a crafted-.frts clobber attack: an adversary who knows the
    // passphrase crafts a file whose embedded filename matches a victim
    // in the working directory, then tricks the user into running
    // `sherd decrypt-file -i malicious.frts`.
    if out_path.exists() && !args.force {
        bail!(
            "output file '{}' already exists, use --force to overwrite",
            out_path.display()
        );
    }
    write_atomic(&out_path, content)?;
    // Do not print the output path or elapsed time.
    eprintln!("[sherd] Decrypted.");
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
    // Do not print N or the share index in the header. A header like
    // `=== Share {i}/{N} ===` would reveal the total share count to
    // terminal-log readers. The share data already contains x at byte 1;
    // the operator can label shares offline.
    for share in shares.iter() {
        let armored = armor::armor(ARMOR_SHARE, share);
        println!("=== SHERD Share ===");
        println!("{}", armored);
        println!();
    }
    // Do not print N or K to stderr; both are visible to terminal-log
    // readers and the operator specified them on the command line.
    eprintln!("[sherd] Split complete.");
    Ok(())
}

#[derive(Args)]
pub struct ShareCombineArgs {
    /// Files containing shares (one per file). If omitted, reads shares from stdin
    /// separated by blank lines.
    #[arg(short = 's', long = "share")]
    pub shares: Vec<PathBuf>,

    /// Threshold K from the caller, not from the share header which an
    /// attacker could tamper with.
    #[arg(short = 'k', long, default_value_t = 2)]
    pub threshold: u8,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

pub fn cmd_share_combine(args: ShareCombineArgs) -> Result<()> {
    // Validate threshold up front. Deferring to shamir::combine would
    // print a hardcoded "need at least 2 shares" message leaking the
    // internal minimum.
    if !(2..=10).contains(&args.threshold) {
        bail!("bad");
    }

    let mut share_blobs: Vec<Vec<u8>> = Vec::new();
    if args.shares.is_empty() {
        // Bounded read from stdin to prevent OOM. Wrap in Zeroizing so
        // share data is wiped on drop.
        let mut input: Zeroizing<String> = Zeroizing::new(String::new());
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut chunk = [0u8; 65536];
        loop {
            let n = handle.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            // The intermediate Cow from from_utf8_lossy is short-lived
            // and its owned variant is not zeroized. Accepted as a minor
            // residual leak: this is share material, not the secret, and
            // the window is one iteration.
            input.push_str(&String::from_utf8_lossy(&chunk[..n]));
            if input.len() > MAX_INPUT_SIZE {
                bail!(
                    "stdin input exceeds {} MiB limit",
                    MAX_INPUT_SIZE / (1024 * 1024)
                );
            }
        }
        // Strict armor parser validates BEGIN/END labels match "SHERD
        // SHARE". Count shares as we parse, with a hard cap to prevent DoS.
        let mut current = String::new();
        let mut in_block = false;
        for line in input.lines() {
            let trimmed = line.trim_end_matches('\r');
            if trimmed.starts_with("-----BEGIN SHERD SHARE-----") {
                if in_block {
                    bail!("bad");
                }
                in_block = true;
                current.clear();
                current.push_str(trimmed);
                current.push('\n');
            } else if trimmed.starts_with("-----END SHERD SHARE-----") {
                if !in_block {
                    bail!("bad");
                }
                in_block = false;
                current.push_str(trimmed);
                let bytes = armor::dearmor_with_label(&current, "SHERD SHARE")?;
                share_blobs.push(bytes);
                current.clear();
                // Cap shares at 10, matching shamir::split's max N. An
                // attacker piping millions of fake shares through stdin
                // could otherwise exhaust memory and CPU before the
                // threshold check rejects the combine.
                if share_blobs.len() > 10 {
                    bail!("too many shares (max 10)");
                }
            } else if in_block {
                current.push_str(trimmed);
                current.push('\n');
            }
            // Lines outside BEGIN..END blocks are silently ignored,
            // allowing human-readable comments between shares.
        }
        if in_block {
            bail!("bad");
        }
    } else {
        if args.shares.len() > 10 {
            bail!("too many share files (max 10)");
        }
        for path in &args.shares {
            // Share files are secret material: K shares reconstruct the
            // secret. Wrap the read data in Zeroizing.
            let content_bytes: Zeroizing<Vec<u8>> =
                open_and_read_bounded(path, MAX_INPUT_SIZE, "share")?;
            let content = String::from_utf8_lossy(&content_bytes).into_owned();
            let content_z: Zeroizing<String> = Zeroizing::new(content);
            let bytes = armor::dearmor_with_label(&content_z, "SHERD SHARE")?;
            drop(content_z);
            share_blobs.push(bytes);
        }
    }
    // Check against the caller's threshold, not a hardcoded "2". A
    // hardcoded `< 2` would let shamir::combine detect the mismatch and
    // leak the hardcoded minimum.
    if share_blobs.len() < args.threshold as usize {
        bail!("bad");
    }
    if share_blobs.len() > 10 {
        bail!("too many shares (max 10)");
    }
    let secret = shamir::combine(&share_blobs, args.threshold)?;

    for blob in share_blobs.iter_mut() {
        use zeroize::Zeroize;
        blob.zeroize();
    }
    write_output(&args.output, &secret)?;
    // Do not print K or the share count; both leak the quorum threshold.
    eprintln!("[sherd] Reconstructed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitize a filename extracted from ciphertext to prevent path
/// traversal. An attacker who can craft a ciphertext can embed a
/// filename like `../../../etc/cron.d/backdoor`; without sanitization
/// the decrypted content is written to that path.
///
/// Rejects path separators including Unicode lookalikes, `..` components,
/// absolute paths, control chars, Windows reserved names, bidi override
/// and zero-width characters, and trailing dots/spaces. Truncates to
/// 255 bytes on a UTF-8 boundary. Falls back to "decrypted.bin" if the
/// filename is empty or invalid.
fn sanitize_filename(name: &str) -> String {
    // Strip path separators first, including Unicode lookalikes. Take
    // the basename.
    let basename: String = name
        .rsplit(|c| {
            c == '/' || c == '\\'
                // Fullwidth solidus U+FF0F, fraction slash U+2044,
                // fullwidth reverse solidus U+FF3C, and Unicode line/para
                // separators U+2028..U+2029.
                || c == '\u{FF0F}'
                || c == '\u{2044}'
                || c == '\u{FF3C}'
                || (c as u32 >= 0x2028 && c as u32 <= 0x2029)
        })
        .next()
        .unwrap_or("")
        .to_string();

    if basename == ".." || basename == "." || basename.is_empty() {
        return "decrypted.bin".to_string();
    }

    // Filter out dangerous Unicode and ASCII chars illegal in Windows
    // filenames. Sherd is Unix-only, but decrypted files may be
    // transferred to Windows via USB or network share.
    let cleaned: String = basename
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            // ASCII control chars 0x00-0x1F and 0x7F
            if cp < 0x20 || cp == 0x7F {
                return false;
            }
            // C1 control chars 0x80-0x9F
            if (0x80..=0x9F).contains(&cp) {
                return false;
            }
            if *c == '\0' || *c == '\u{FFFD}' {
                return false;
            }
            // Bidi overrides U+202A..U+202E, U+2066..U+2069
            if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
                return false;
            }
            // Zero-width chars
            if (0x200B..=0x200F).contains(&cp) || cp == 0xFEFF {
                return false;
            }
            // Path separator lookalikes
            if *c == '\u{FF0F}' || *c == '\u{2044}' || *c == '\u{FF3C}' {
                return false;
            }
            // Windows-illegal ASCII: wildcards, redirects, quotes, pipe,
            // and the NTFS Alternate Data Stream separator.
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

    // Reject trailing dots and spaces. Windows strips these, so
    // "secret.txt." would collide with "secret.txt".
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
            let expected = if last >= 0xF0 {
                3
            } else if last >= 0xE0 {
                2
            } else if last >= 0xC0 {
                1
            } else {
                0
            };
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
    // Match the uppercased stem without extension against the reserved
    // list. For "NUL.txt" the stem is "NUL" and matches.
    if reserved.contains(&stem) {
        return format!("sherd_{}", s);
    }
    s
}

/// `--pass` is intentionally absent from the CLI struct so clap rejects
/// it at parse time. Passphrase sources, in priority order: --pass-fd,
/// --pass-file, SHERD_PASS env var, interactive prompt.
fn get_passphrase(
    pass_file: &Option<PathBuf>,
    pass_fd: &Option<u32>,
    prompt: &str,
) -> Result<SecretBytes> {
    if let Some(fd) = pass_fd {
        return read_passphrase_from_fd(*fd);
    }

    if let Some(path) = pass_file {
        return read_passphrase_from_file(path);
    }

    // SHERD_PASS environment variable. std::env::var and remove_var
    // mutate a shared global environment, so Rust marks them unsafe.
    // main() is single-threaded here, so the unsafe is sound. If Sherd
    // ever becomes multi-threaded, move this to a single-threaded init
    // phase.
    //
    // /proc/PID/environ on Linux is a snapshot taken at execve time.
    // remove_var updates the in-memory environ but not /proc/PID/environ,
    // so the var stays visible to same-UID processes for the process
    // lifetime. Prefer --pass-fd or interactive prompt; the env var is
    // a CI/testing convenience.
    if let Ok(p) = std::env::var("SHERD_PASS") {
        eprintln!("[sherd] WARNING: SHERD_PASS env var is visible in /proc/PID/environ");
        eprintln!("[sherd]          to ALL processes with the same UID for the process lifetime.");
        eprintln!("[sherd]          For production use, prefer --pass-fd or interactive prompt.");
        // SAFETY: single-threaded context, no threads spawned yet.
        unsafe {
            std::env::remove_var("SHERD_PASS");
        }
        let z: Zeroizing<String> = Zeroizing::new(p);
        let sb = SecretBytes::from_slice(z.as_bytes());
        return Ok(sb);
    }

    memory::read_passphrase(prompt).map_err(|e| anyhow!("passphrase read failed: {}", e))
}

/// Read the decoy passphrase from --decoy-pass-fd or --decoy-pass-file.
/// Mirrors `get_passphrase` but never reads from a CLI string and never
/// falls back to interactive prompt; the decoy is optional and must be
/// supplied explicitly.
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

/// Read a passphrase from a file descriptor, one byte at a time into a
/// pre-allocated mlocked SecretBytes. Bounded to MAX_PASS_LEN bytes so a
/// malicious fd writer cannot OOM the process.
///
/// Polls the fd with a 60-second timeout. A blocked `file.read` on a
/// pipe whose writer never closes would leave the operator stuck without
/// SIGKILL; we bail instead.
const PASSPHRASE_FD_TIMEOUT_SECS: i32 = 60;

fn read_passphrase_from_fd(fd: u32) -> Result<SecretBytes> {
    if fd > (i32::MAX as u32) {
        bail!("bad");
    }
    let fd_i32 = fd as i32;
    let mut buf = SecretBytes::new(memory::MAX_PASS_LEN);
    let mut len = 0usize;
    let mut byte = [0u8; 1];

    // ManuallyDrop so we do not close the fd; the caller owns it.
    use std::mem::ManuallyDrop;
    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd_i32) });

    while len < memory::MAX_PASS_LEN {
        // Poll before each read so a misbehaving pipe writer cannot hang
        // the operator indefinitely.
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
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    buf.wipe();
    // Wipe the 1-byte stack buffer so the last byte does not linger.
    use zeroize::Zeroize;
    byte.zeroize();
    Ok(passphrase)
}

/// Read a passphrase from a file: one line, trailing newline stripped.
/// Checks file size before read_to_string and refuses files larger than
/// MAX_PASS_LEN+1 to prevent OOM. TOCTOU-safe: opens once, fstats the
/// fd, reads from the same fd.
fn read_passphrase_from_file(path: &PathBuf) -> Result<SecretBytes> {
    let file = std::fs::File::open(path).map_err(|e| anyhow!("--pass-file open failed: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("--pass-file metadata failed: {}", e))?;
    if !metadata.is_file() {
        bail!("--pass-file is not a regular file");
    }
    if metadata.len() as usize > memory::MAX_PASS_LEN + 1 {
        bail!("--pass-file too large (max {} bytes)", memory::MAX_PASS_LEN);
    }
    let mut content = String::new();
    let mut reader = file;
    reader
        .read_to_string(&mut content)
        .map_err(|e| anyhow!("--pass-file read failed: {}", e))?;
    let line: Zeroizing<String> = Zeroizing::new(content);
    let mut line = line;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    if line.len() > memory::MAX_PASS_LEN {
        line.truncate(memory::MAX_PASS_LEN);
    }
    let sb = SecretBytes::from_slice(line.as_bytes());
    Ok(sb)
}

/// Max input size, anti-DoS bound. A 256 MiB binary envelope becomes
/// ~342 MiB once base64-armored with BEGIN/END headers and 64-char
/// line wrapping, so the limit must exceed the 256 MiB ciphertext cap.
const MAX_INPUT_SIZE: usize = 512 * 1024 * 1024;

/// Write to a temp file with a randomized name, then atomically rename
/// to the final path. The random name prevents symlink attacks where an
/// attacker pre-creates a symlink at a predictable `.frts.tmp` path
/// pointing to a privileged file.
///
/// The temp file is created with mode 0600 from the start via
/// `OpenOptions::mode(0o600)`, so there is no window where the file
/// exists with default umask. The final file inherits these permissions.
///
/// fsync the temp file before the rename and the parent directory after,
/// so the data is durable before success is reported. Without this a
/// power loss after rename could leave the file empty or corrupt.
fn write_atomic(final_path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 128 bits of OsRng entropy plus pid and timestamp defeats
    // predictive-symlink attacks on local filesystems. create_new(true)
    // prevents an attacker from pre-creating the file.
    let mut rng_buf = [0u8; 16];
    crate::crypto::rng::fill(&mut rng_buf);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let suffix: String = rng_buf.iter().map(|b| format!("{:02x}", b)).collect();
    let tmp_name = format!(".sherd.tmp.{}.{}.{}", pid, ts, suffix);
    let tmp_path = final_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(tmp_name);

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
        // fsync before rename so the data is durable. Without this, a
        // power loss between write() and rename() could leave the file
        // empty.
        file.sync_all()
            .map_err(|e| anyhow!("temp file fsync failed: {}", e))?;
        // Drop the file handle before rename; Windows requires this.
        drop(file);
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, data)?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, final_path) {
        // Retry temp-file cleanup before bailing. On a full or read-only
        // filesystem the temp file containing encrypted plaintext would
        // otherwise remain on disk. Three retries with short delays; if
        // all fail, panic with a clear message so the operator can
        // manually shred the temp file.
        let mut last_remove_err = None;
        for attempt in 0..3 {
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
            // still on disk at tmp_path. Print the path so the operator
            // can shred it; the path itself contains no key material,
            // only pid, timestamp, and a random suffix.
            eprintln!(
                "[sherd] FATAL: atomic rename failed ({}) AND temp file cleanup failed ({}).",
                e, re
            );
            eprintln!(
                "[sherd] ENCRYPTED TEMP FILE REMAINS AT: {}",
                tmp_path.display()
            );
            eprintln!(
                "[sherd] Manually shred this file: shred -u \"{}\"",
                tmp_path.display()
            );
            panic!("sherd: atomic write failed and temp cleanup failed");
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

    // Also set 0600 on the final path.
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
        Some(p) => open_and_read_bounded(p, MAX_INPUT_SIZE, "input"),
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
            // write_atomic grants 0600 permissions even via --output.
            write_atomic(p, data)?;
        }
        None => {
            // Refuse to write binary data to a TTY. Binary bytes can
            // corrupt the terminal, execute escape-sequence payloads,
            // or trigger terminal emulator bugs.
            use std::io::IsTerminal;
            if io::stdout().is_terminal() {
                // Allow armored output, refuse raw binary. Heuristic:
                // check the first 64 bytes for non-printable chars.
                let looks_binary = data.iter().take(64).any(|&b| {
                    b != b'\n' && b != b'\r' && b != b'\t' && !(0x20..=0x7E).contains(&b)
                });
                if looks_binary {
                    bail!(
                        "refusing to write binary data to terminal, \
                         redirect to a file with --output or pipe to another command"
                    );
                }
            }
            // io::stdout() is buffered and the buffer holds a copy of
            // the data that is not zeroized on flush. The buffer is
            // small and overwritten on the next write.
            io::stdout().write_all(data)?;
        }
    }
    Ok(())
}
