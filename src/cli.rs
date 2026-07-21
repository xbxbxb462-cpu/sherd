//! CLI argument parsing and command dispatch.
//!
//! Plaintext buffers (input read, decrypted output, Shamir-reconstructed
//! secret) are wrapped in `Zeroizing<Vec<u8>>`. Output files are created
//! with mode 0600 on Unix. Decrypt-failure paths return Err so Drop impls
//! run; the decoy-vs-real passphrase check uses `subtle::ConstantTimeEq`.

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

/// Binary envelope magic "FRT7" + version byte 7. Used to detect
/// already-encrypted input.
const FORTIS_BINARY_MAGIC: &[u8] = b"FRT7";

/// Armored message header line. Used to detect re-encryption of an
/// already-armored message.
const FORTIS_ARMOR_PREFIX: &str = "-----BEGIN FORTIS MESSAGE-----";

fn looks_like_fortis_binary(data: &[u8]) -> bool {
    data.len() >= 5 && &data[..4] == FORTIS_BINARY_MAGIC && data[4] == VERSION
}

fn looks_like_fortis_armored(data: &[u8]) -> bool {
    // Require valid UTF-8 and the armor prefix after leading whitespace,
    // to avoid false positives on binary data.
    match std::str::from_utf8(data) {
        Ok(s) => s
            .trim_start_matches(|c: char| c.is_whitespace())
            .starts_with(FORTIS_ARMOR_PREFIX),
        Err(_) => false,
    }
}

/// True if the input looks like an already-encrypted Fortis artifact.
fn looks_like_fortis_output(data: &[u8]) -> bool {
    looks_like_fortis_binary(data) || looks_like_fortis_armored(data)
}

// ---------------------------------------------------------------------------
// TOCTOU-safe bounded file reader
// ---------------------------------------------------------------------------

/// Open the file once, fstat the fd, then read from the same fd. The
/// naive metadata + read pattern opens twice and an attacker who swaps
/// the path between calls can point the second read at a non-regular,
/// unbounded file. Rejects non-regular files and files larger than `max`.
/// Reads into a `Zeroizing<Vec<u8>>`. `label` is used in error messages
/// so the operator knows which path failed without the absolute path
/// being echoed.
fn open_and_read_bounded(
    path: &std::path::Path,
    max: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).map_err(|e| anyhow!("{} open failed: {}", label, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| anyhow!("{} metadata failed: {}", label, e))?;
    // Reject non-regular files. We hold the only fd, so the attacker
    // cannot swap the path between the is_file check and the read.
    if !metadata.is_file() {
        bail!(
            "{} is not a regular file (devices, FIFOs, sockets not allowed)",
            label
        );
    }
    if metadata.len() as usize > max {
        bail!("{} exceeds {} MiB limit", label, max / (1024 * 1024));
    }
    // Pre-allocate based on fstat size, capped at `max`.
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
    /// `./fortis encrypt --pass-fd 3 3<passfile`
    #[arg(long)]
    pub pass_fd: Option<u32>,

    /// Allow re-encrypting an input that already looks like a Fortis
    /// artifact. Without this flag the CLI refuses to double-wrap. Use
    /// only when you genuinely need layered encryption.
    #[arg(long)]
    pub force: bool,
    // `--pass X` is intentionally absent: it would put the passphrase in
    // /proc/PID/cmdline, shell history, and `ps aux`. Accepted sources
    // are --pass-fd, --pass-file, FORTIS_PASS (debug convenience), or
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
    // Read plaintext (wrapped in Zeroizing)
    let plaintext: Zeroizing<Vec<u8>> = read_input(&args.input)?;
    if plaintext.is_empty() {
        bail!("plaintext is empty");
    }
    if plaintext.len() > MAX_CT {
        bail!("plaintext exceeds 256 MiB limit");
    }

    // Refuse to re-encrypt an already-encrypted input unless --force is
    // given. envelope::encrypt_envelope performs the same check; doing
    // it here gives a clearer message and avoids wasting Argon2id cycles.
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
            // Use ConstantTimeEq directly. A pre-check on length would
            // short-circuit ct_eq and leak length-equality via timing.
            // ConstantTimeEq on &[u8] already returns false for
            // different-length slices in constant time.
            let same = bool::from(passphrase.as_bytes().ct_eq(dpass.as_bytes()));
            if same {
                bail!("decoy passphrase must differ from the real passphrase");
            }
            (Some(dp), Some(dpass))
        } else {
            (None, None)
        };

    // Do not print the KDF preset to stderr. The name reveals the
    // operator's sensitivity assessment; an adversary with terminal-log
    // access could use it to prioritize targets. Print a generic message
    // identical for all presets.
    eprintln!("[fortis] Deriving key (Argon2id)…");

    let t0 = std::time::Instant::now();
    // encrypt_envelope consumes passphrase and decoy_pass by value; both
    // are wiped inside derive_slot_secrets_from_secret when Argon2id
    // finishes. Catch InputAlreadyEncrypted in case the CLI-side check
    // above missed a wrapped format that only envelope.rs recognizes.
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
            // errors are type-erased, so we match on Display. Robust as
            // long as "already encrypted" appears somewhere in the chain.
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

    // Do not print the envelope size or elapsed time. Size correlates
    // with plaintext size (even with --paranoid, the size mod 4 KiB
    // reveals the preset jitter range) and elapsed time reveals the KDF
    // preset. The operator can use `time` and check the file size.
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
    // Drop the armored copy now to release memory before the passphrase
    // prompt. Drop wipes it via Zeroizing.
    drop(armored);

    let passphrase = get_passphrase(&args.pass_file, &args.pass_fd, "Passphrase: ")?;

    // Enforce MIN_PASS on decrypt too, with the same uniform "bad"
    // error used for wrong passphrases. A distinct "passphrase too
    // short" message would leak whether a short passphrase was
    // attempted. The length check itself just avoids wasting Argon2id
    // cycles on empty or 1-char submissions.
    if passphrase.len() < MIN_PASS {
        bail!("bad");
    }

    eprintln!("[fortis] Deriving key, verifying commit tag, decrypting…");
    // decrypt_envelope consumes passphrase by value (wiped in Argon2id).
    // env is Zeroizing<Vec<u8>>. On Err we return Err so Drop runs.
    let pt = match envelope::decrypt_envelope(env.as_slice(), passphrase) {
        Ok(pt) => pt,
        Err(_) => {
            // Return Err so Drop wipes env and other locals. main()
            // prints only the top-level Display message. Uniform with
            // cmd_decrypt_file so stderr text does not distinguish
            // message-decrypt from file-decrypt failure.
            bail!("decryption failed — wrong passphrase or corrupted/tampered message");
        }
    };
    // Drop env (Zeroizing wipes it) before writing output.
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

    // A .frts file always begins with the "FRT7\x07" magic. Refuse to
    // double-wrap unless --force is given.
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
    // plaintext is no longer needed; Zeroizing drops it on scope exit.

    // Do not print the input filename to stderr. Filenames are sensitive
    // metadata: operation type, unit, date. The operator knows what they
    // encrypted.
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
    // Use the TOCTOU-safe bounded reader. env is Zeroizing and wiped on
    // Drop, including the Err-return path.
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
            // Return Err so Drop wipes env. main() prints only the
            // top-level Display message.
            bail!("decryption failed — wrong passphrase or corrupted file");
        }
    };
    // env is no longer needed; drop to wipe before parsing metadata.
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
    // Boundary check: o + name_len == combined.len() would leave no
    // room for the 4-byte mime_len field, panicking on the next read.
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
    // Same boundary check before reading orig_size.
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
        // Use a uniform "bad" message; leaking orig_size vs content.len()
        // reveals structural information about the decrypted file.
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
    // Refuse to overwrite an existing output file unless --force is
    // given. Blocks a crafted-.frts clobber attack: an adversary who
    // knows the passphrase crafts a file whose embedded filename
    // matches a victim in the working directory, then tricks the user
    // into running `fortis decrypt-file -i malicious.frts`.
    if out_path.exists() && !args.force {
        bail!(
            "output file '{}' already exists — use --force to overwrite",
            out_path.display()
        );
    }
    // Use atomic write with randomized temp file name.
    write_atomic(&out_path, content)?;
    // Do not print the output path or elapsed time. The path reveals
    // the decrypted filename and elapsed time reveals the KDF preset.
    // The operator can `ls` the output directory to confirm.
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
    // Do not print N or the share index in the header. A header like
    // `=== Share {i}/{N} ===` would reveal the total share count to
    // terminal-log readers. The share data already contains x at byte 1;
    // the operator can label shares offline.
    for share in shares.iter() {
        let armored = armor::armor(ARMOR_SHARE, share);
        println!("=== FORTIS Share ===");
        println!("{}", armored);
        println!();
    }
    // Do not print N or K to stderr. A message like `Split into {N}
    // shares (threshold {K})` reveals both counts to terminal-log
    // readers. The operator specified them on the command line.
    eprintln!("[fortis] Split complete.");
    Ok(())
}

#[derive(Args)]
pub struct ShareCombineArgs {
    /// Files containing shares (one per file). If omitted, reads shares from stdin
    /// separated by blank lines.
    #[arg(short = 's', long = "share")]
    pub shares: Vec<PathBuf>,

    /// Threshold K from the caller, not from the share header (which an
    /// attacker could tamper with).
    #[arg(short = 'k', long, default_value_t = 2)]
    pub threshold: u8,

    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

pub fn cmd_share_combine(args: ShareCombineArgs) -> Result<()> {
    // Validate threshold up front. Deferring to shamir::combine would
    // print a hardcoded "need at least 2 shares" message leaking the
    // internal minimum. Use the caller's threshold for the share-count
    // check below.
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
            // Push bytes directly into the Zeroizing<String> via a
            // single from_utf8_lossy to avoid per-iteration allocation.
            // The intermediate Cow is short-lived; its owned variant is
            // not zeroized. Accepted as a minor residual leak: the data
            // is share material, not the secret, and the window is one
            // iteration.
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
                // Cap shares at 10, matching shamir::split's max N.
                // An attacker piping millions of fake shares through
                // stdin could otherwise exhaust memory and CPU before
                // the threshold check rejects the combine.
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
            // secret material: K shares reconstruct the secret. Wrap
            // the read data in Zeroizing.
            let content_bytes: Zeroizing<Vec<u8>> =
                open_and_read_bounded(path, MAX_INPUT_SIZE, "share")?;
            // Convert to String for the armor parser, wrapped in
            // Zeroizing so it is wiped on drop via volatile writes.
            let content = String::from_utf8_lossy(&content_bytes).into_owned();
            let content_z: Zeroizing<String> = Zeroizing::new(content);
            let bytes = armor::dearmor_with_label(&content_z, "FORTIS SHARE")?;
            drop(content_z);
            share_blobs.push(bytes);
        }
    }
    // Check against the caller's threshold, not a hardcoded "2". A
    // hardcoded `< 2` would let shamir::combine detect the mismatch
    // and leak the hardcoded minimum.
    if share_blobs.len() < args.threshold as usize {
        bail!("bad");
    }
    // Defensive re-check; should never trigger given the caps above.
    if share_blobs.len() > 10 {
        bail!("too many shares (max 10)");
    }
    // Pass the caller-specified threshold, not from shares.
    let secret = shamir::combine(&share_blobs, args.threshold)?;

    // Wipe share blobs; they are secret material.
    for blob in share_blobs.iter_mut() {
        use zeroize::Zeroize;
        blob.zeroize();
    }
    write_output(&args.output, &secret)?;
    // Do not print K or the share count to stderr. A message like
    // `Reconstructed from {K} shares` reveals the quorum threshold to
    // terminal-log readers.
    eprintln!("[fortis] Reconstructed.");
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
    // the basename: this rejects any embedded `/`, `\`, or lookalike
    // that would split the path.
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

    // Filter out dangerous Unicode and ASCII chars illegal in Windows
    // filenames. Fortis is Unix-only, but decrypted files may be
    // transferred to Windows via USB or network share. "report:secret"
    // would truncate to "report" on Windows NTFS ADS; "NUL.txt" would
    // be rejected with no clear reason.
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
            // Reject Windows-illegal ASCII chars. Fortis is Unix-only
            // but decrypted files may be transferred to Windows. The
            // chars below are wildcards, redirects, quotes, pipe, or
            // NTFS Alternate Data Stream separators.
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
    // Check the uppercased stem without extension against the reserved
    // list. For "NUL.txt" the stem is "NUL" and matches.
    if reserved.contains(&stem) {
        return format!("fortis_{}", s);
    }
    s
}

/// `--pass` is intentionally absent from the CLI struct so clap rejects
/// it at parse time. Passphrase sources, in priority order: --pass-fd,
/// --pass-file, FORTIS_PASS env var, interactive prompt.
fn get_passphrase(
    pass_file: &Option<PathBuf>,
    pass_fd: &Option<u32>,
    prompt: &str,
) -> Result<SecretBytes> {
    // Priority 1: --pass-fd. Most secure for scripting.
    if let Some(fd) = pass_fd {
        return read_passphrase_from_fd(*fd);
    }

    // Priority 2: --pass-file. Path in cmdline, not the passphrase.
    if let Some(path) = pass_file {
        return read_passphrase_from_file(path);
    }

    // Priority 3: FORTIS_PASS environment variable.
    //
    // std::env::var and std::env::remove_var mutate a shared global
    // environment, so Rust marks them unsafe. main() is single-threaded
    // here, so the unsafe is sound. If Fortis ever becomes multi-threaded,
    // move this to a single-threaded init phase.
    //
    // /proc/PID/environ on Linux is a snapshot taken at execve time.
    // std::env::remove_var updates the in-memory environ but not
    // /proc/PID/environ, so the var stays visible to same-UID processes
    // for the process lifetime. Prefer --pass-fd or interactive prompt.
    // The env var is a CI/testing convenience; we warn when it is used.
    if let Ok(p) = std::env::var("FORTIS_PASS") {
        eprintln!("[fortis] WARNING: FORTIS_PASS env var is visible in /proc/PID/environ");
        eprintln!("[fortis]          to ALL processes with the same UID for the process lifetime.");
        eprintln!("[fortis]          For production use, prefer --pass-fd or interactive prompt.");
        // Remove the env var from this process and any children before use.
        // This does not remove it from /proc/PID/environ; see above.
        // SAFETY: single-threaded context, no threads spawned yet.
        unsafe {
            std::env::remove_var("FORTIS_PASS");
        }
        // Wrap in Zeroizing<String> so the heap buffer is wiped on drop.
        let z: Zeroizing<String> = Zeroizing::new(p);
        let sb = SecretBytes::from_slice(z.as_bytes());
        return Ok(sb);
    }

    // Priority 4: interactive prompt.
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
    // Validate fd value before casting to i32.
    if fd > (i32::MAX as u32) {
        bail!("bad");
    }
    let fd_i32 = fd as i32;
    let mut buf = SecretBytes::new(memory::MAX_PASS_LEN);
    let mut len = 0usize;
    let mut byte = [0u8; 1];

    // Create the File wrapper once and ManuallyDrop it so we do not
    // close the fd; the caller owns it.
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
    // file is ManuallyDrop; the fd is not closed, caller owns it.
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    buf.wipe();
    // Zeroize the 1-byte stack buffer that held the last passphrase
    // byte. Without this, byte[0] lingers on the stack until the slot
    // is reused by the caller.
    use zeroize::Zeroize;
    byte.zeroize();
    Ok(passphrase)
}

/// Read a passphrase from a file: one line, trailing newline stripped.
/// Checks file size before read_to_string and refuses files larger than
/// MAX_PASS_LEN+1 to prevent OOM. TOCTOU-safe: opens once, fstats the
/// fd, reads from the same fd.
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
    // Read from the same fd that we fstat'd; no TOCTOU.
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
        // Defensive truncation; should not trigger given the size check.
        line.truncate(memory::MAX_PASS_LEN);
    }
    let sb = SecretBytes::from_slice(line.as_bytes());
    // Zeroizing::drop wipes the String via volatile writes.
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
    // 128 bits of OsRng entropy plus pid and timestamp gives plenty of
    // unpredictability for the temp suffix, defeating predictive-symlink
    // attacks on local filesystems. create_new(true) prevents an attacker
    // from pre-creating the file.
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

    // Create with 0600 from the start via OpenOptions::mode(). No window
    // where the file exists with default umask.
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
        // Drop the file handle before rename; Windows requires this.
        drop(file);
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, data)?;
    }

    if let Err(e) = std::fs::rename(&tmp_path, final_path) {
        // Retry temp-file cleanup before bailing. On a full or read-only
        // filesystem, the temp file containing encrypted plaintext
        // would otherwise remain on disk. Three retries with short
        // delays; if all fail, panic with a clear message so the
        // operator can manually shred the temp file.
        let mut last_remove_err = None;
        for attempt in 0..3 {
            // Brief delay between retries for transient failures like NFS lag.
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
            // path and can shred it. main.rs's panic hook prints a
            // generic message, so we print the temp path here first.
            // The path is not secret: it contains pid, timestamp, and a
            // random suffix, no key material.
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
            // Refuse to write binary data to a TTY. Binary bytes can
            // corrupt the terminal, execute escape-sequence payloads
            // like the "DECEMBER" title-change attack, or trigger
            // terminal emulator bugs. The operator should redirect to a
            // file via --output or pipe to another command.
            use std::io::IsTerminal;
            if io::stdout().is_terminal() {
                // Allow armored output (printable ASCII only) but refuse
                // raw binary. Heuristic: check the first 64 bytes for
                // non-printable chars.
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
            // io::stdout() is buffered and the buffer holds a copy of
            // the data that is not zeroized on flush. A future hardening
            // pass could use a Zeroizing-wrapped writer. For now the
            // buffer is small, 8 KiB by default, and overwritten on the
            // next write.
            io::stdout().write_all(data)?;
        }
    }
    Ok(())
}
