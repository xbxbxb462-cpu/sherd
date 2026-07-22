//! Sherd: offline symmetric encryption tool.
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
mod wordlist;

#[derive(Parser)]
#[command(
    version,
    about = "Offline encryption tool",
    long_about = "Sherd v1.0.0 - single-binary offline encryption.\n\
                  Argon2id -> HKDF -> AES-256-GCM (per-chunk, isolated keys).\n\
                  Key Commitment (HMAC-SHA256-trunc-128) verified before AEAD decrypt.\n\
                  Plausible deniability via indistinguishable decoy slot.\n\
                  Shamir Secret Sharing over GF(256).\n\
                  All secret buffers (incl. plaintext) are zeroized after use.\n\
                  Uniform-timing decryption.\n\
                  Branchless GF(256).\n\n\
                  Run `sherd selftest` to verify cryptographic integrity before use."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a message from stdin (or a file) to stdout (or a file)
    Encrypt(cli::EncryptArgs),
    /// Decrypt a Sherd message
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
    /// Inspect an encrypted file's metadata without decrypting
    Inspect(cli::InspectArgs),
    /// Generate a new X25519 identity, or print the public key of an existing one
    Keygen(cli::KeygenArgs),
    /// Print shell completion script for bash, zsh, fish, or powershell
    Completion {
        /// Shell to generate completion for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

const BANNER: &str = "\n\
\x1b[1m\x1b[38;5;179m    _  _ ___ ___ ___ ___ _  _ _____\x1b[0m\n\
\x1b[1m\x1b[38;5;179m   | || | __/ __| __| _ \\ || |_   _|\x1b[0m\n\
\x1b[1m\x1b[38;5;179m   | __ | _|\\__ \\ _\\   / __ | | |\x1b[0m\n\
\x1b[1m\x1b[38;5;179m   |_||_|___|___/___|_\\_\\_||_| |_|\x1b[0m\n\
\x1b[2m   v1.0.0 - offline encryption\x1b[0m\n";

/// Replace the default panic hook with one that prints a generic message.
/// The default hook leaks source paths, line numbers, and backtraces to
/// stderr. Drop impls run during unwinding before the hook fires, so
/// secret buffers get wiped first.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_info| {
        eprintln!("[sherd] FATAL: internal error, aborting.");
        eprintln!("[sherd] No diagnostic details are printed to avoid leaking");
        eprintln!("[sherd] source paths or memory state to terminal logs.");
        eprintln!("[sherd] If this recurs, run `sherd selftest` to verify the");
        eprintln!("[sherd] binary, then re-deploy from a trusted build.");
    }));
}

fn main() -> Result<()> {
    // Install before any code that could panic and leak paths via the hook.
    install_panic_hook();

    // Disable core dumps. A core file would contain the full process
    // memory including passphrases and keys.
    #[cfg(unix)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "[sherd] WARNING: failed to disable core dumps ({}). \
                 If the process crashes, secrets may be written to a core file.",
                err
            );
        }
        // prctl(PR_SET_DUMPABLE, 0) also blocks ptrace attach by non-root
        // users and disables dumps even if RLIMIT_CORE is later raised.
        // Linux-only; on other Unix only setrlimit applies.
        #[cfg(target_os = "linux")]
        {
            let pr_ret = libc::prctl(4, 0, 0, 0, 0);
            if pr_ret != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!(
                    "[sherd] WARNING: prctl(PR_SET_DUMPABLE, 0) failed ({}). \
                     ptrace attach by same-UID processes may still be possible.",
                    err
                );
            }
        }
    }

    // SHERD_ALLOW_NO_MLOCK: release builds refuse to start if the env var
    // is present at all; debug builds honor it with a warning so CI can
    // run without CAP_IPC_LOCK.
    //
    // Skip mlockall entirely for commands that never touch secrets:
    // --help, --version, completion, hash. These run before any crypto
    // and would otherwise refuse to start on systems without CAP_IPC_LOCK,
    // which defeats their purpose (e.g. shell completion setup).
    let is_safe_command = {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .any(|a| a == "--version" || a == "-V" || a == "--help" || a == "-h")
            || args.windows(2).any(|w| w[0] == "completion")
    };
    if is_safe_command {
        // Show banner before clap prints version/help.
        if std::env::args().any(|a| a == "--version" || a == "-V") {
            eprint!("{}", BANNER);
        }
        let cli = Cli::parse();
        return match cli.command {
            Command::Completion { shell } => {
                use clap::CommandFactory;
                let mut cmd = Cli::command();
                clap_complete::generate(shell, &mut cmd, "sherd", &mut std::io::stdout());
                Ok(())
            }
            _ => Ok(()),
        };
    }

    #[cfg(unix)]
    {
        #[cfg(not(debug_assertions))]
        {
            if std::env::var_os("SHERD_ALLOW_NO_MLOCK").is_some() {
                eprintln!("[sherd] FATAL: SHERD_ALLOW_NO_MLOCK is set in the environment,");
                eprintln!("[sherd]        but this is a RELEASE build. The memory-lock");
                eprintln!("[sherd]        bypass is forbidden in release builds to prevent");
                eprintln!("[sherd]        a trivial memory-protection backdoor: an adversary");
                eprintln!("[sherd]        who can set env vars could otherwise disable mlockall");
                eprintln!("[sherd]        and cause secrets to swap to disk.");
                eprintln!("[sherd]        To fix, unset the variable and grant CAP_IPC_LOCK:");
                eprintln!("[sherd]          unset SHERD_ALLOW_NO_MLOCK");
                eprintln!("[sherd]          sudo setcap cap_ipc_lock=ep ./sherd");
                eprintln!("[sherd]        or add to /etc/security/limits.conf:");
                eprintln!("[sherd]          *  soft  memlock  unlimited");
                eprintln!("[sherd]          *  hard  memlock  unlimited");
                eprintln!("[sherd]        Refusing to continue.");
                // Exit 2 = security policy violation. No secrets exist yet.
                std::process::exit(2);
            }
        }
    }
    let allow_no_mlock: bool = {
        #[cfg(debug_assertions)]
        {
            let v = std::env::var("SHERD_ALLOW_NO_MLOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if v {
                eprintln!("[sherd] WARNING: SHERD_ALLOW_NO_MLOCK=1, DEBUG BUILD ONLY.");
                eprintln!("[sherd]          Secrets MAY swap to disk. DO NOT use this");
                eprintln!("[sherd]          configuration with real sensitive data.");
            }
            v
        }
        #[cfg(not(debug_assertions))]
        {
            false
        }
    };

    // mlockall(MCL_CURRENT | MCL_FUTURE) locks the whole address space
    // against swap, covering Argon2id working set and any third-party
    // crate allocations the per-buffer mlock in SecretBytes cannot reach.
    // Fatal in release; the operator must grant CAP_IPC_LOCK, configure
    // limits.conf, or run as root. SHERD_ALLOW_NO_MLOCK bypass is debug-only.
    #[cfg(unix)]
    {
        let mut mlockall_ok = false;
        unsafe {
            let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
            if libc::mlockall(flags) != 0 {
                // Likely RLIMIT_MEMLOCK too low. Try raising it, then retry.
                let mlockall_err = std::io::Error::last_os_error();
                let mut rlim: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
                    let mut new_rlim = rlim;
                    new_rlim.rlim_cur = rlim.rlim_max;
                    if libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlim) != 0 {
                        let setrlimit_err = std::io::Error::last_os_error();
                        eprintln!(
                            "[sherd] WARNING: could not raise RLIMIT_MEMLOCK ({}). \
                             Current soft={}, hard={}.",
                            setrlimit_err, rlim.rlim_cur, rlim.rlim_max
                        );
                    }
                }
                if libc::mlockall(flags) != 0 {
                    let retry_err = std::io::Error::last_os_error();
                    if !allow_no_mlock {
                        eprintln!("[sherd] FATAL: mlockall failed, secrets could swap to disk.");
                        eprintln!(
                            "[sherd]   Initial error: {} ({:?})",
                            mlockall_err,
                            mlockall_err.kind()
                        );
                        eprintln!(
                            "[sherd]   Retry error:   {} ({:?})",
                            retry_err,
                            retry_err.kind()
                        );
                        eprintln!("[sherd] Memory locking is required for this tool.");
                        eprintln!("[sherd] Fix one of:");
                        eprintln!("[sherd]   sudo setcap cap_ipc_lock=ep ./sherd");
                        eprintln!("[sherd]   add to /etc/security/limits.conf:");
                        eprintln!("[sherd]     *  soft  memlock  unlimited");
                        eprintln!("[sherd]     *  hard  memlock  unlimited");
                        eprintln!("[sherd]   then log out and back in; or re-run as root.");
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "[sherd]   DEBUG BUILD: set SHERD_ALLOW_NO_MLOCK=1 to accept the risk."
                        );
                        #[cfg(not(debug_assertions))]
                        eprintln!(
                            "[sherd]   This is a RELEASE build; the SHERD_ALLOW_NO_MLOCK \
                             bypass is disabled. Use one of the above."
                        );
                        eprintln!("[sherd] Refusing to continue without memory locking.");
                        // No secret buffers exist yet, so skipping Drop is safe.
                        std::process::exit(2);
                    } else {
                        eprintln!("[sherd] WARNING: mlockall failed but SHERD_ALLOW_NO_MLOCK=1");
                        eprintln!(
                            "[sherd]          Error: {} ({:?})",
                            retry_err,
                            retry_err.kind()
                        );
                        eprintln!(
                            "[sherd]          Secrets MAY swap to disk. NON-PRODUCTION use only."
                        );
                    }
                } else {
                    mlockall_ok = true;
                }
            } else {
                mlockall_ok = true;
            }
        }
        // Let the memory module know whether MCL_FUTURE is in effect so
        // per-buffer mlock failures in SecretBytes::try_lock can be downgraded.
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
                println!("✓ All Sherd v1.0.0 self-tests passed.");
                Ok(())
            }
            Err(e) => Err(e),
        },
        Command::Hash => {
            let hash = selftest::compute_binary_hash()?;
            println!("Sherd v1.0.0 binary SHA-256:");
            println!("  {}", hash);
            println!();
            println!("Verify this hash out-of-band before trusting the binary.");
            println!("If the hash does not match a trusted fingerprint, DO NOT USE.");
            Ok(())
        }
        Command::Inspect(args) => cli::cmd_inspect(&args.input),
        Command::Keygen(args) => cli::cmd_keygen(args),
        Command::Completion { .. } => Ok(()), // handled before mlockall
    };

    // Handlers return Err on the decrypt-failure path so Drop impls wipe
    // secrets during unwinding. We print only the top-level Display message;
    // anyhow's default Termination uses Debug and would print the full
    // chain. Handler locals are already dropped by here, so exit(1) is safe.
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("[sherd] Error: {}", e);
            std::process::exit(1);
        }
    }
}
