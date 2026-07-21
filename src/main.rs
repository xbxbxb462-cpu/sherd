//! Fortis: offline symmetric encryption tool.
//!
//! Argon2id -> HKDF -> AES-256-GCM with per-chunk isolated keys.
//! Key-commitment HMAC verified before AEAD decrypt. Secret buffers are
//! zeroized on drop; mlockall locks the whole process against swap.

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

/// Replace the default panic hook with one that prints a generic message.
/// The default hook leaks source paths, line numbers, and backtraces to
/// stderr, which terminal logs often capture. Drop impls run during
/// unwinding before the hook fires, so secret buffers get wiped. Installed
/// first, before mlockall and any secret material exists.
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
    // First thing in main: a panic in any later setup code must not leak
    // paths via the default hook.
    install_panic_hook();

    // Disable core dumps. A core file would contain the full process
    // memory including passphrases and keys. Report failures so the
    // operator knows dumps could not be disabled.
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
        // Also call prctl(PR_SET_DUMPABLE, 0) on Linux. setrlimit covers
        // core files; prctl additionally blocks ptrace attach by non-root
        // users and disables dumps even if RLIMIT_CORE is later raised.
        // PR_SET_DUMPABLE = 4. Linux-only; on other Unix only setrlimit
        // applies.
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

    // FORTIS_ALLOW_NO_MLOCK policy:
    //   - Release builds refuse to start if the env var is present at all,
    //     catching operator mistakes or an adversary setting it.
    //   - Debug builds honor it (value "1" or "true") with a loud warning,
    //     so CI can run without CAP_IPC_LOCK.
    #[cfg(unix)]
    {
        #[cfg(not(debug_assertions))]
        {
            // Release: refuse if the variable is present at all.
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
                // Exit 2 = security policy violation. No secrets exist yet.
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

    // mlockall(MCL_CURRENT | MCL_FUTURE) so the kernel never swaps any
    // page: Argon2id working set, AES-GCM buffers, HKDF intermediates.
    // The per-buffer mlock in SecretBytes does not cover third-party
    // crate allocations; only mlockall does.
    //
    // Failure is fatal in release: secrets could otherwise swap to disk.
    // The operator must grant CAP_IPC_LOCK, configure limits.conf, or
    // run as root. The FORTIS_ALLOW_NO_MLOCK bypass is debug-only.
    #[cfg(unix)]
    {
        // Track whether mlockall succeeded so the memory module knows
        // future pages are already covered by MCL_FUTURE and per-buffer
        // mlock failures can be non-fatal.
        let mut mlockall_ok = false;
        unsafe {
            // MCL_CURRENT: lock existing pages. MCL_FUTURE: lock future ones.
            let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
            if libc::mlockall(flags) != 0 {
                // Likely RLIMIT_MEMLOCK too low. Try raising it, then retry.
                let mlockall_err = std::io::Error::last_os_error();
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
        // Tell the memory module whether MCL_FUTURE is in effect so
        // per-buffer mlock failures in SecretBytes::try_lock are
        // non-fatal (already covered) or treated as an accepted bypass.
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

    // Command handlers return Err on the decrypt-failure path so Drop
    // impls wipe secrets during unwinding. We print only the top-level
    // Display message; anyhow's default Termination uses Debug and
    // would print the full chain, leaking OS strings or paths. Handler
    // locals are already dropped by here, so exit(1) skipping Drop is
    // safe.
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("[fortis] Error: {}", e);
            std::process::exit(1);
        }
    }
}
