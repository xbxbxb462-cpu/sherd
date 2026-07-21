//! Fortis — offline symmetric encryption tool.
//!
//! Architecture:
//!   L1  Key Derivation      Argon2id → HKDF-Extract → HKDF-Expand
//!   L2  AEAD Encryption     AES-256-GCM (per-chunk, isolated keys)
//!   L4  Multi-Layer Integrity  AES-GCM tag + Key-commitment HMAC + chunk AAD
//!   L5  Constant-Time Ops   `subtle::ConstantTimeEq` for all secret comparisons
//!   L6  Streaming           1 MiB chunks, per-chunk HKDF-Expand keys
//!   L7  Key Commitment      HMAC-SHA256-trunc-128, verified BEFORE AEAD decrypt
//!   L8  Header Authentication  Entire header bound as AEAD AAD
//!   L9  Cryptographic Agility  cipher_id / kdf_id / commit_id bytes in header
//!   L10 Secure Metadata     No filename/MIME/timestamps in cleartext header
//!
//! Threat model:
//!   - Network adversaries: there is no network code in this binary.
//!   - Ciphertext-only attackers: throttled by Argon2id memory-hard cost.
//!   - Header tampering: every header byte is AEAD AAD AND commit_tag input.
//!   - Commit-tag forgery: HMAC-SHA256-trunc-128 is unforgeable.
//!   - Chunk compromise: per-chunk keys via HKDF-Expand are independent.
//!   - Nonce reuse: per-chunk counter nonces unique by construction.
//!   - Timing oracles: constant-time compare, uniform error messages,
//!     uniform chunk-processing count.
//!   - Coercion: optional decoy layer with plausible deniability.
//!   - Memory forensics: `zeroize` on every secret buffer (including
//!     plaintext); `mlock` on keys; `mlockall` on the whole process.
//!
//! NOT in scope (document openly):
//!   - Compromised OS / hardware implants (use Tails OS + air-gapped machine).
//!   - Cold boot attacks (reboot cold before/after sensitive operations).
//!   - Browser/OS 0-days (out of scope for any single tool).
//!   - Quantum adversaries with CRQC (AES-256 is Grover-resistant to 2^128).

use anyhow::Result;
use clap::{Parser, Subcommand};

mod armor;
mod cli;
mod crypto;
mod envelope;
mod memory;
mod selftest;
mod shamir;

#[derive(Parser)]
#[command(
    name = "fortis",
    version = "7.3.0",
    about = "Offline encryption tool",
    long_about = "Fortis v7.3.0 — single-binary offline encryption.\n\
                  Argon2id → HKDF → AES-256-GCM (per-chunk, isolated keys).\n\
                  Key Commitment (HMAC-SHA256-trunc-128) verified before AEAD decrypt.\n\
                  Plausible deniability via indistinguishable decoy slot.\n\
                  Shamir Secret Sharing over GF(256).\n\
                  All secret buffers (incl. plaintext) are zeroized after use.\n\
                  Uniform-timing decryption.\n\
                  Branchless GF(256).\n\n\
                  Run `fortis selftest` to verify cryptographic integrity before use."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a message from stdin (or a file) to stdout (or a file)
    Encrypt(cli::EncryptArgs),
    /// Decrypt a FORTIS message
    Decrypt(cli::DecryptArgs),
    /// Encrypt a file (binary envelope, .frts extension)
    EncryptFile(cli::EncryptFileArgs),
    /// Decrypt a .frts file
    DecryptFile(cli::DecryptFileArgs),
    /// Split a secret into N Shamir shares (threshold K)
    ShareSplit(cli::ShareSplitArgs),
    /// Reconstruct a secret from K or more Shamir shares
    ShareCombine(cli::ShareCombineArgs),
    /// Run cryptographic self-tests (KATs + round-trip + tamper rejection)
    Selftest,
    /// Print the binary's own SHA-256 hash for out-of-band verification
    Hash,
}

/// Install a panic hook that prints a GENERIC message with no source
/// paths, line numbers, or backtrace. The default Rust panic hook prints
/// `panicked at 'msg', src/foo.rs:123:45` and, if `RUST_BACKTRACE=1` is
/// set in the environment, a full backtrace including file paths and
/// memory addresses. For a crypto tool, these leaks to stderr are
/// unacceptable: terminal logs are often captured (syslog, journald,
/// screen hardcopy) and a backtrace can reveal the exact build tree
/// layout and potentially intermediate values in stack frames.
///
/// The hook still aborts the process (panics in a crypto tool are
/// unrecoverable). With `panic = "unwind"` (the project default), Drop
/// impls run during unwinding BEFORE the hook fires, so Zeroizing/SecretBytes
/// buffers are wiped. The hook is the LAST thing to run.
///
/// IMPORTANT: this hook is installed BEFORE mlockall and BEFORE any secret
/// material exists, so a panic during initialization (e.g., mlock retry
/// logic) is also covered.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_info| {
        eprintln!("[fortis] FATAL: internal error — aborting.");
        eprintln!("[fortis] No diagnostic details are printed to avoid leaking");
        eprintln!("[fortis] source paths or memory state to terminal logs.");
        eprintln!("[fortis] If this recurs, run `fortis selftest` to verify the");
        eprintln!("[fortis] binary, then re-deploy from a trusted build.");
    }));
}

fn main() -> Result<()> {
    // Install the sanitized panic hook BEFORE any other initialization.
    // This must be the very first thing main() does so that a panic in
    // any subsequent setup code (setrlimit, mlockall, CLI parsing) does
    // not leak paths via the default hook.
    install_panic_hook();

    // Disable core dumps to prevent secrets leaking into core files if
    // the process crashes. A core dump would contain the full process
    // memory including passphrases and keys.
    //
    // Report setrlimit failures instead of silently ignoring. The
    // previous `let _ = libc::setrlimit(...)` would silently ignore
    // failures. On a system with a strict seccomp profile or a container
    // that blocks setrlimit, core dumps would remain enabled and a crash
    // would dump all secrets to disk. We now print a warning so the
    // operator knows core dumps could not be disabled.
    #[cfg(unix)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "[fortis] WARNING: failed to disable core dumps ({}). \
                 If the process crashes, secrets may be written to a core file.",
                err
            );
        }
        // Also try to disable core dumps via prctl(PR_SET_DUMPABLE, 0).
        // setrlimit(RLIMIT_CORE, 0) prevents the kernel from writing a
        // core file, but prctl(PR_SET_DUMPABLE, 0) goes further: it
        // prevents ptrace attach by non-root users AND disables core
        // dump generation even when RLIMIT_CORE is non-zero. Defense in
        // depth.
        // PR_SET_DUMPABLE = 4 on Linux.
        //
        // prctl is Linux-specific. On macOS/BSD, the equivalent is
        // proc_trace_control (macOS) or procctl (FreeBSD). For now, we
        // only call prctl on Linux. On other Unix platforms, setrlimit
        // remains the only defense.
        //
        // The previous `let _ = libc::prctl(...)` would silently ignore
        // failures. A failure here means ptrace attach may still be
        // possible by a same-UID process, which is a memory-protection
        // concern. We now print a warning on failure.
        #[cfg(target_os = "linux")]
        {
            let pr_ret = libc::prctl(4, 0, 0, 0, 0);
            if pr_ret != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!(
                    "[fortis] WARNING: prctl(PR_SET_DUMPABLE, 0) failed ({}). \
                     ptrace attach by same-UID processes may still be possible.",
                    err
                );
            }
        }
    }

    // =====================================================================
    // FORTIS_ALLOW_NO_MLOCK hardening.
    // =====================================================================
    //
    // Policy:
    //   - RELEASE builds: if the FORTIS_ALLOW_NO_MLOCK variable is present
    //     in the environment AT ALL (regardless of its value), the process
    //     REFUSES TO START. This catches:
    //       (a) operators who copy-paste a CI command into production,
    //       (b) adversaries who set the variable non-interactively,
    //       (c) misconfigured wrapper scripts.
    //     The operator must unset the variable and grant CAP_IPC_LOCK
    //     (or run as root, or raise /etc/security/limits.conf memlock).
    //
    //   - DEBUG builds: the bypass IS honored (value must be "1" or
    //     "true"), but a LOUD multi-line warning is printed to stderr.
    //     This permits CI and local dev workflows (where mlockall may
    //     fail due to container limits) without weakening release
    //     binaries.
    #[cfg(unix)]
    {
        #[cfg(not(debug_assertions))]
        {
            // RELEASE build: refuse if the variable is present at all.
            if std::env::var_os("FORTIS_ALLOW_NO_MLOCK").is_some() {
                eprintln!("[fortis] FATAL: FORTIS_ALLOW_NO_MLOCK is set in the environment,");
                eprintln!("[fortis]        but this is a RELEASE build. The memory-lock");
                eprintln!("[fortis]        bypass is FORBIDDEN in release builds to prevent");
                eprintln!("[fortis]        a trivial memory-protection backdoor (an adversary");
                eprintln!("[fortis]        who can set env vars could otherwise disable mlockall");
                eprintln!("[fortis]        and cause secrets to swap to disk).");
                eprintln!("[fortis]        To fix, unset the variable and grant CAP_IPC_LOCK:");
                eprintln!("[fortis]          unset FORTIS_ALLOW_NO_MLOCK");
                eprintln!("[fortis]          sudo setcap cap_ipc_lock=ep ./fortis");
                eprintln!("[fortis]        or add to /etc/security/limits.conf:");
                eprintln!("[fortis]          *  soft  memlock  unlimited");
                eprintln!("[fortis]          *  hard  memlock  unlimited");
                eprintln!("[fortis]        Refusing to continue.");
                // Exit code 2 distinguishes "security policy violation" from
                // "operational error" (exit 1). No secrets exist yet at this
                // point, so skipping Drop is safe.
                std::process::exit(2);
            }
        }
    }
    let allow_no_mlock: bool = {
        #[cfg(debug_assertions)]
        {
            let v = std::env::var("FORTIS_ALLOW_NO_MLOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if v {
                eprintln!("[fortis] WARNING: FORTIS_ALLOW_NO_MLOCK=1 — DEBUG BUILD ONLY.");
                eprintln!("[fortis]          Secrets MAY swap to disk. DO NOT use this");
                eprintln!("[fortis]          configuration with real sensitive data.");
            }
            v
        }
        #[cfg(not(debug_assertions))]
        {
            false
        }
    };

    // Lock ALL current and future memory pages to prevent ANY swapping
    // to disk. This covers Argon2id internal memory (64-256 MiB), AES-GCM
    // buffers, HKDF intermediates — ALL of which contain secret-derived
    // data. Without mlockall, only SecretBytes buffers are locked, but
    // the argon2 crate's internal allocations are NOT covered and can
    // swap to disk.
    //
    // For high-sensitivity use, mlockall failure is FATAL. Previously
    // the code printed a warning and continued, which meant that on a
    // system without CAP_IPC_LOCK the tool would silently operate
    // without memory locking — leaving secrets free to swap to disk.
    // The operator must either:
    //   (a) run with `sudo setcap cap_ipc_lock=ep ./fortis`, or
    //   (b) configure /etc/security/limits.conf with `* memlock unlimited`,
    //   (c) run as root.
    //
    // In release builds, the FORTIS_ALLOW_NO_MLOCK escape hatch is
    // restricted to debug builds (see the block above). In release
    // builds the variable is rejected before we even reach mlockall, so
    // `allow_no_mlock` is always `false` in release.
    #[cfg(unix)]
    {
        // Track whether mlockall actually succeeded so the memory
        // module knows future allocations are already covered by
        // MCL_FUTURE. Without this, SecretBytes::try_lock would
        // wrongly abort on per-buffer mlock failures even when the
        // page was already locked process-wide.
        let mut mlockall_ok = false;
        unsafe {
            // MCL_CURRENT = lock all currently mapped pages
            // MCL_FUTURE   = lock all future mappings automatically
            let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
            if libc::mlockall(flags) != 0 {
                // Capture errno for diagnosis.
                let mlockall_err = std::io::Error::last_os_error();
                // mlockall failed — likely RLIMIT_MEMLOCK too low.
                // Try to raise the limit first, then retry.
                let mut rlim: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
                    let mut new_rlim = rlim;
                    new_rlim.rlim_cur = rlim.rlim_max; // raise soft to hard
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlim) != 0 {
                        let setrlimit_err = std::io::Error::last_os_error();
                        eprintln!(
                            "[fortis] WARNING: could not raise RLIMIT_MEMLOCK ({}). \
                             Current soft={}, hard={}.",
                            setrlimit_err, rlim.rlim_cur, rlim.rlim_max
                        );
                    }
                }
                // Retry mlockall
                if libc::mlockall(flags) != 0 {
                    let retry_err = std::io::Error::last_os_error();
                    if !allow_no_mlock {
                        eprintln!("[fortis] FATAL: mlockall failed — secrets could swap to disk.");
                        eprintln!(
                            "[fortis]   Initial error: {} ({:?})",
                            mlockall_err,
                            mlockall_err.kind()
                        );
                        eprintln!(
                            "[fortis]   Retry error:   {} ({:?})",
                            retry_err,
                            retry_err.kind()
                        );
                        eprintln!("[fortis] Memory locking is MANDATORY for this tool.");
                        eprintln!("[fortis] Fix ONE of:");
                        eprintln!("[fortis]   1. sudo setcap cap_ipc_lock=ep ./fortis");
                        eprintln!("[fortis]   2. Add to /etc/security/limits.conf:");
                        eprintln!("[fortis]        *  soft  memlock  unlimited");
                        eprintln!("[fortis]        *  hard  memlock  unlimited");
                        eprintln!("[fortis]      Then log out and back in.");
                        eprintln!("[fortis]   3. Re-run as root.");
                        #[cfg(debug_assertions)]
                        eprintln!("[fortis]   (DEBUG BUILD: set FORTIS_ALLOW_NO_MLOCK=1 to accept the risk.)");
                        #[cfg(not(debug_assertions))]
                        eprintln!(
                            "[fortis]   NOTE: this is a RELEASE build; the FORTIS_ALLOW_NO_MLOCK"
                        );
                        #[cfg(not(debug_assertions))]
                        eprintln!(
                            "[fortis]   bypass is intentionally disabled. Use one of the above."
                        );
                        eprintln!("[fortis] Refusing to continue without memory locking.");
                        // Use exit(2) here because at this point no secret
                        // buffers exist yet (CLI parsing hasn't happened), so
                        // skipping Drop is safe. Exit code 2 = security policy.
                        std::process::exit(2);
                    } else {
                        // Debug-build bypass path.
                        eprintln!("[fortis] WARNING: mlockall failed but FORTIS_ALLOW_NO_MLOCK=1");
                        eprintln!(
                            "[fortis]          Error: {} ({:?})",
                            retry_err,
                            retry_err.kind()
                        );
                        eprintln!(
                            "[fortis]          Secrets MAY swap to disk. NON-PRODUCTION use only."
                        );
                    }
                } else {
                    mlockall_ok = true;
                }
            } else {
                mlockall_ok = true;
            }
        }
        // Inform the memory module of process-wide protection state.
        // - If mlockall succeeded: mark it active so per-buffer mlock
        //   failures become non-fatal (MCL_FUTURE already covers the page).
        // - If mlockall failed but the operator accepted the no-mlock risk
        //   via FORTIS_ALLOW_NO_MLOCK=1 (debug builds only): mark the
        //   bypass as accepted so per-buffer mlock failures do not abort.
        //   Without this, SecretBytes::try_lock would abort on the first
        //   per-buffer mlock failure, defeating the bypass.
        if mlockall_ok {
            memory::mark_process_mlockall_active();
        } else if allow_no_mlock {
            memory::mark_mlockall_bypass_accepted();
        }
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Encrypt(args) => cli::cmd_encrypt_message(args),
        Command::Decrypt(args) => cli::cmd_decrypt_message(args),
        Command::EncryptFile(args) => cli::cmd_encrypt_file(args),
        Command::DecryptFile(args) => cli::cmd_decrypt_file(args),
        Command::ShareSplit(args) => cli::cmd_share_split(args),
        Command::ShareCombine(args) => cli::cmd_share_combine(args),
        Command::Selftest => match selftest::run_all_selftests() {
            Ok(()) => {
                println!("✓ All FORTIS v7.3.0 self-tests passed.");
                Ok(())
            }
            Err(e) => Err(e),
        },
        Command::Hash => {
            let hash = selftest::compute_binary_hash()?;
            println!("FORTIS v7.3.0 binary SHA-256:");
            println!("  {}", hash);
            println!();
            println!("Verify this hash out-of-band before trusting the binary.");
            println!("If the hash does not match a trusted fingerprint, DO NOT USE.");
            Ok(())
        }
    };

    // Command handlers NEVER call std::process::exit() on the
    // decrypt-failure path — they return Err(...) so that Drop impls
    // (Zeroizing, SecretBytes) run during stack unwinding, wiping
    // secrets before the process exits.
    //
    // We print only the TOP-LEVEL error message (Display, not Debug).
    // anyhow's default Termination uses {:?} (Debug) which prints the
    // full error chain — that could leak OS error strings, absolute
    // paths from canonicalize(), or other internal diagnostics to
    // stderr. By printing {} (Display) we show only the curated
    // top-level message that the command handler chose to surface.
    //
    // At this point all command-handler locals are already dropped
    // (the handlers returned), so std::process::exit(1) skipping Drop
    // is safe — no secret buffers remain in scope.
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("[fortis] Error: {}", e);
            std::process::exit(1);
        }
    }
}
