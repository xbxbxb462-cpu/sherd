//! Secure memory helpers.
//!
//! `SecretBytes` is a `Vec<u8>` that:
//!   1. Wraps its contents in `Zeroizing<>` so the buffer is zeroized on drop
//!      via the `zeroize` crate (which uses `write_volatile` to defeat
//!      compiler DCE / reordering — a plain `*b = 0` loop can be elided by
//!      LLVM when the buffer is about to be freed).
//!   2. Calls `mlock` on the buffer to prevent the OS from swapping it to
//!      disk, AND marks it `MADV_DONTDUMP` (Linux) so it is excluded from
//!      core dumps.
//!   3. Provides `as_bytes` / `as_bytes_mut` accessors with explicit lifetimes.
//!   4. Provides `ct_eq` for constant-time comparison (no short-circuit).
//!
//! All secret material (passphrase bytes, master keys, PRK, commit keys,
//! per-chunk keys, padded plaintext) should be stored in `SecretBytes`.
//!
//! # Security invariants
//!
//! * `SecretBytes` does **NOT** implement `Clone` (use `try_clone` for an
//!   explicit, audited copy that re-mlocks). This prevents accidental
//!   duplication of secret material via `let x = y.clone()`.
//! * `SecretBytes` does **NOT** implement `Debug` or `Display`. This
//!   prevents accidental leakage via `{:?}` / `{}` formatting or error
//!   messages that include the secret contents. If a `Debug` impl is ever
//!   required for ergonomics, it MUST print only `<redacted SecretBytes
//!   len=N>` and never the bytes themselves.
//! * `SecretBytes` zeroizes its buffer on `Drop` via `Zeroizing<Vec<u8>>`.
//! * `mlock` failure is **FATAL** if process-wide `mlockall(MCL_FUTURE)`
//!   has not been initialized via `init_process_memory_protection()`.
//!   See `try_lock` for the rationale.

use std::io;
use zeroize::{Zeroize, Zeroizing};

/// Maximum passphrase length we are willing to read in one go.
/// 4 KiB is generous (real passphrases are <256 bytes) but bounded so we can
/// pre-allocate a single mlock'd buffer instead of growing it byte-by-byte.
pub const MAX_PASS_LEN: usize = 4096;

// ============================================================================
// Process-wide memory protection state
// ============================================================================

/// Process-wide flag indicating whether `init_process_memory_protection()`
/// has been called and succeeded (i.e., `mlockall(MCL_CURRENT | MCL_FUTURE)`
/// is active).
///
/// Once this is `true`, every future page the kernel maps for this process
/// is automatically locked against swap. Per-buffer `mlock` calls in
/// `SecretBytes::try_lock` become belt-and-suspenders defense and a
/// failure there is non-fatal (logged once for diagnosis).
///
/// While this is `false` (e.g., a unit test linking `memory.rs` directly
/// without going through `main`), per-buffer `mlock` is the ONLY defense
/// against swap — a failure is therefore FATAL and the process aborts.
static PROCESS_MLOCKALL_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set when the operator has explicitly accepted the risk of running
/// without mlockall (debug builds only, via FORTIS_ALLOW_NO_MLOCK=1).
/// When this is set, per-buffer `mlock` failures in `try_lock` become
/// non-fatal — matching the behavior of `process_mlockall_active()`.
static MLOCKALL_BYPASS_ACCEPTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Initialize process-wide memory protection. MUST be called once at
/// program startup, BEFORE any secret material is allocated.
///
/// # When to use this
///
/// `main.rs` performs its own mlockall sequence with the
/// `FORTIS_ALLOW_NO_MLOCK` env-var policy (debug-only bypass). For
/// normal production runs, `main.rs` does NOT call this function —
/// the two paths would duplicate work.
///
/// This function exists for two reasons:
///   1. Test harnesses that link `memory.rs` directly without going
///      through `main` (e.g., integration tests that need memory
///      protection but do not invoke the CLI).
///   2. Future embedders of the crypto core as a library (not yet
///      implemented).
///
/// If you call this function, do NOT also run the `main.rs` mlockall
/// sequence — pick ONE path. The two paths set the same atomic flag
/// (`PROCESS_MLOCKALL_DONE`), so calling both is harmless but
/// confusing.
///
/// This function performs, in order:
///   1. Best-effort raise of `RLIMIT_MEMLOCK` to the hard limit (so that
///      subsequent `mlockall` and per-buffer `mlock` calls can succeed for
///      large crypto buffers such as Argon2id's 64–256 MiB working set).
///   2. Disable core dumps process-wide via:
///      a. `setrlimit(RLIMIT_CORE, 0)` — kernel will not write a core
///      file even on crash.
///      b. `prctl(PR_SET_DUMPABLE, 0)` (Linux only) — also blocks
///      `ptrace` attach by non-root users and is defense-in-depth
///      against core-dump generation even if `RLIMIT_CORE` is later
///      raised.
///   3. `mlockall(MCL_CURRENT | MCL_FUTURE)` — lock ALL currently-mapped
///      pages AND all future pages automatically. This covers Argon2id
///      internal memory, AES-GCM buffers, HKDF intermediates — all of
///      which contain secret-derived data that the per-buffer `mlock`
///      in `SecretBytes::try_lock` does NOT cover (those buffers are
///      allocated inside third-party crates).
///   4. On failure of step 3: HARD ABORT via `std::process::exit(2)`.
///      There is **NO** environment-variable bypass. An env-var bypass
///      would allow a compromised host to silently disable swap
///      protection — unacceptable for a tool that handles secrets.
///
/// # Idempotency
///
/// Safe to call multiple times. The second and subsequent calls are
/// no-ops (the atomic guard ensures this).
///
/// # Platform support
///
/// On non-Unix targets this is a no-op (memory locking is not available).
/// Crypto operations on such targets remain functional but the operator
/// must be aware that swap protection is absent — restrict deployment to
/// Unix targets with `CAP_IPC_LOCK` configured.
#[allow(dead_code)]
pub fn init_process_memory_protection() {
    // Idempotency guard.
    use std::sync::atomic::Ordering;
    if PROCESS_MLOCKALL_DONE.load(Ordering::SeqCst) {
        return;
    }

    #[cfg(unix)]
    {
        // Step 1: raise RLIMIT_MEMLOCK (best-effort).
        ensure_mlock_limit_raised();

        // Step 2: disable core dumps process-wide.
        disable_core_dumps();

        // Step 3: mlockall(MCL_CURRENT | MCL_FUTURE).
        // Retry once after the rlimit raise above (in case the kernel's
        // accounting needs the new limit visible).
        let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
        let first = unsafe { libc::mlockall(flags) };
        if first != 0 {
            let first_err = io::Error::last_os_error();
            // Try raising the limit one more time, explicitly, then retry.
            force_raise_memlock_rlimit();
            let second = unsafe { libc::mlockall(flags) };
            if second != 0 {
                let second_err = io::Error::last_os_error();
                eprintln!("[fortis] FATAL: mlockall(MCL_CURRENT | MCL_FUTURE) failed.");
                eprintln!(
                    "[fortis]   Initial error: {} ({:?})",
                    first_err,
                    first_err.kind()
                );
                eprintln!(
                    "[fortis]   Retry error:   {} ({:?})",
                    second_err,
                    second_err.kind()
                );
                eprintln!("[fortis] Memory locking is mandatory; secrets could otherwise");
                eprintln!("[fortis] swap to disk or appear in core dumps.");
                eprintln!("[fortis] Fix ONE of:");
                eprintln!("[fortis]   1. sudo setcap cap_ipc_lock=ep ./fortis");
                eprintln!("[fortis]   2. Add to /etc/security/limits.conf:");
                eprintln!("[fortis]        *  soft  memlock  unlimited");
                eprintln!("[fortis]        *  hard  memlock  unlimited");
                eprintln!("[fortis]      Then log out and back in.");
                eprintln!("[fortis]   3. Re-run as root.");
                // No escape hatch — refuse to continue.
                eprintln!("[fortis] Refusing to continue without memory locking.");
                // exit(2) is safe here: no secret buffers exist yet
                // (CLI parsing / crypto have not started). We avoid
                // abort() because a SIGABRT could itself trigger a core
                // dump if RLIMIT_CORE could not be lowered above.
                std::process::exit(2);
            }
        }

        // Mark process-wide protection as active. From this point on,
        // per-buffer mlock failures in SecretBytes::try_lock are
        // non-fatal (the kernel already locks every future page).
        PROCESS_MLOCKALL_DONE.store(true, Ordering::SeqCst);
    }
}

/// Returns true if `init_process_memory_protection()` has been called
/// and succeeded. Used by `try_lock` to decide whether per-buffer
/// `mlock` failure is fatal (no process-wide protection) or merely
/// diagnostic (process-wide protection active).
#[inline]
pub fn process_mlockall_active() -> bool {
    PROCESS_MLOCKALL_DONE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Mark process-wide mlockall as active.
///
/// `init_process_memory_protection()` (above) is the canonical entry
/// point: it performs rlimit raise + disable core dumps + prctl +
/// mlockall with the correct ordering and atomic-flag setting. It is
/// the recommended way to initialize memory protection.
///
/// However, `main.rs` performs its OWN mlockall sequence (with the
/// FORTIS_ALLOW_NO_MLOCK env var policy, which
/// `init_process_memory_protection()` does not honor). After
/// successfully calling mlockall (or accepting the no-mlock risk in a
/// debug build), `main.rs` calls this function to inform the memory
/// module that process-wide protection is in effect. After this call,
/// per-buffer mlock failures in `SecretBytes::try_lock` become
/// non-fatal (warn-once) — matching the behavior of
/// `init_process_memory_protection()` on its success path.
///
/// This function is `pub` (not `pub(crate)`) so external test harnesses
/// and integration tests can also use it. It is safe to call multiple
/// times (the atomic is idempotent).
#[allow(dead_code)]
pub fn mark_process_mlockall_active() {
    PROCESS_MLOCKALL_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Mark the FORTIS_ALLOW_NO_MLOCK bypass as accepted by the operator.
///
/// Called by `main` in debug builds when `mlockall` failed but the operator
/// set `FORTIS_ALLOW_NO_MLOCK=1`. After this call, per-buffer `mlock`
/// failures in `SecretBytes::try_lock` become non-fatal (warn-once),
/// matching the behavior of `process_mlockall_active()`.
///
/// In release builds this function is never called: `main` rejects the
/// env var before reaching the mlockall path.
#[allow(dead_code)]
pub fn mark_mlockall_bypass_accepted() {
    MLOCKALL_BYPASS_ACCEPTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Returns true if the operator has accepted the no-mlock risk.
#[inline]
pub fn mlockall_bypass_accepted() -> bool {
    MLOCKALL_BYPASS_ACCEPTED.load(std::sync::atomic::Ordering::SeqCst)
}

// ============================================================================
// SecretBytes
// ============================================================================

/// A byte buffer that is zeroized on drop and (optionally) mlock'd.
///
/// See the module-level documentation for the full list of security
/// invariants. In particular, this type intentionally does NOT implement
/// `Clone`, `Debug`, or `Display`.
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SecretBytes {
    /// Allocate a new `SecretBytes` of the given length, filled with zeros.
    /// Automatically calls mlock to prevent swap to disk.
    pub fn new(len: usize) -> Self {
        let mut s = Self {
            inner: Zeroizing::new(vec![0u8; len]),
            locked: false,
        };
        s.try_lock();
        s
    }

    /// Create a `SecretBytes` from an existing slice (copies and zeroizes the source).
    /// Automatically calls mlock to prevent swap to disk.
    ///
    /// NOTE: the source slice is NOT zeroized by this function — the caller
    /// owns the source and is responsible for wiping it (e.g., by storing
    /// it in a `SecretBytes` of its own, or by calling `.zeroize()` on it).
    pub fn from_slice(src: &[u8]) -> Self {
        let mut v = Self::new(src.len());
        v.inner[..].copy_from_slice(src);
        v
    }

    /// Get a reference to the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get a mutable reference to the inner bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Length of the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Dereference to `&[u8]` for ergonomic use with crypto APIs.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Produce an independent copy of this secret buffer.
    ///
    /// Used when the same passphrase needs to be fed to multiple slot-derivation
    /// calls (e.g., `decrypt_envelope` tries both slots with the same passphrase).
    /// Each clone has its own mlock'd backing store and is independently zeroized
    /// on drop.
    ///
    /// This is the ONLY way to duplicate a `SecretBytes`. The type does NOT
    /// implement `Clone` to prevent accidental duplication of secret material
    /// via `.clone()` — every duplication must be explicit and auditable.
    pub fn try_clone(&self) -> Self {
        Self::from_slice(&self.inner)
    }

    /// Constant-time equality comparison with another byte slice.
    ///
    /// The standard `PartialEq` impl on `&[u8]` short-circuits on the first
    /// differing byte, leaking the position of the first difference via
    /// timing. For secret material this is a side-channel (e.g., an attacker
    /// who can measure decryption time can progressively recover a key by
    /// observing which byte position first differs). This method accumulates
    /// XOR differences across the entire buffer and only compares the
    /// accumulator at the end, so the running time is independent of where
    /// (or whether) the buffers differ.
    ///
    /// # Length leakage
    ///
    /// Length comparison is NOT constant-time: if `self.len() !=
    /// other.len()`, this returns `false` immediately. Length is rarely
    /// secret (it is fixed by the algorithm — e.g., 32 bytes for a
    /// master key, 24 bytes for a nonce). If length IS secret in your
    /// context, pad both sides to the same length before calling this.
    #[allow(dead_code)]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        let a = self.as_bytes();
        let b = other;
        if a.len() != b.len() {
            return false;
        }
        // Accumulate XOR differences. The compiler cannot short-circuit
        // this because `diff` is only inspected after the loop. We use
        // a `u8` accumulator (sufficient for any buffer size since we
        // only care about zero-vs-nonzero).
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        // The final `diff == 0` comparison is on a single byte and is
        // not a timing-sensitive operation (no secret-dependent branch
        // on buffer contents).
        diff == 0
    }

    /// Try to `mlock` the buffer to prevent swap, and mark it
    /// `MADV_DONTDUMP` (Linux) so it is excluded from core dumps.
    ///
    /// # Failure modes
    ///
    /// * If `init_process_memory_protection()` has been called
    ///   successfully (i.e., `mlockall(MCL_FUTURE)` is active), the
    ///   kernel already locks this page against swap. Per-buffer `mlock`
    ///   is belt-and-suspenders. A failure here is logged ONCE per
    ///   process for diagnosis and the buffer is still used (it is
    ///   already locked by `mlockall`).
    ///
    /// * If `init_process_memory_protection()` has NOT been called
    ///   (e.g., a unit test or a misbehaving caller), per-buffer `mlock`
    ///   is the ONLY defense against swap. A failure here is FATAL: the
    ///   process aborts via `std::process::abort()`. This prevents
    ///   silent insecure operation where a secret buffer is allocated
    ///   without swap protection and the operator is never informed.
    ///
    /// # MADV_DONTDUMP
    ///
    /// On Linux, after a successful `mlock` we call
    /// `madvise(MADV_DONTDUMP)` on the same range. This excludes the
    /// page from core dumps even if `RLIMIT_CORE=0` and
    /// `PR_SET_DUMPABLE=0` were not set or were reverted by a
    /// misbehaving library — defense in depth.
    pub fn try_lock(&mut self) {
        if self.locked {
            return;
        }
        #[cfg(unix)]
        {
            // Raise RLIMIT_MEMLOCK before attempting mlock.
            ensure_mlock_limit_raised();

            let ptr = self.inner.as_mut_ptr() as *mut libc::c_void;
            let len = self.inner.len();
            let mlock_ok = unsafe { libc::mlock(ptr, len) } == 0;

            if mlock_ok {
                self.locked = true;
                // Exclude this region from core dumps (Linux).
                // Defense-in-depth even when RLIMIT_CORE=0 / dumpable=0
                // are set process-wide by init_process_memory_protection().
                #[cfg(target_os = "linux")]
                unsafe {
                    // Best-effort: ignore failure. MADV_DONTDUMP failure
                    // is not security-critical if process-wide dump
                    // disabling succeeded.
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                }
            } else {
                // Decide fatality based on whether process-wide
                // mlockall(MCL_FUTURE) is active OR the operator has
                // explicitly accepted the no-mlock risk in a debug build.
                if process_mlockall_active() || mlockall_bypass_accepted() {
                    // Process-wide protection is active (or the operator
                    // accepted the risk). Per-buffer mlock failure is
                    // informational only. Warn ONCE per process for
                    // diagnosis (and only for buffers large enough that
                    // the warning is meaningful).
                    if len >= 1024 {
                        warn_mlock_failed_once(len);
                    }
                } else {
                    // Per-buffer mlock is the ONLY defense, and it failed.
                    // Using this buffer for secret material would allow
                    // swap-to-disk. Abort.
                    let err = io::Error::last_os_error();
                    eprintln!(
                        "[fortis] FATAL: mlock failed on secret buffer of {} bytes ({}).",
                        len, err
                    );
                    eprintln!(
                        "[fortis]        init_process_memory_protection() was not called or failed;"
                    );
                    eprintln!(
                        "[fortis]        per-buffer mlock is the only swap defense and it failed."
                    );
                    eprintln!("[fortis]        Refusing to use unprotected memory for secrets.");
                    eprintln!(
                        "[fortis]        Fix: grant CAP_IPC_LOCK or run as root, then retry."
                    );
                    // abort() — do NOT run Drop. The buffer is still
                    // all-zeros at this point (we have not written any
                    // secret into it yet — try_lock is called from
                    // new()/from_slice() before any secret data is
                    // copied in), so skipping Drop is safe.
                    //
                    // Why abort() here (SIGABRT) vs exit(2) in
                    // init_process_memory_protection()? Because at this
                    // point the buffer's Drop impl would try to munlock
                    // and zeroize — but the buffer is already all-zeros
                    // and munlock is best-effort, so the Drop is
                    // unnecessary. abort() is the fastest way to halt.
                    // In init_process_memory_protection() no secret
                    // buffers exist yet and exit(2) avoids generating a
                    // core dump (a SIGABRT could trigger one if
                    // RLIMIT_CORE could not be lowered above).
                    std::process::abort();
                }
            }
        }
    }

    /// Explicitly wipe the buffer now (also done on drop).
    ///
    /// This delegates to `zeroize::Zeroize`, which uses
    /// `ptr::write_volatile` to defeat LLVM dead-store elimination and
    /// compiler reordering. A plain `*b = 0` loop can be elided by LLVM
    /// when the buffer is about to be dropped.
    pub fn wipe(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Zeroizing<> handles the zero-fill via volatile writes; we
        // additionally munlock if we successfully mlock'd this buffer.
        // We do NOT need to undo MADV_DONTDUMP: the kernel reclaims
        // the page when the allocator frees it, and the DONTDUMP flag
        // is per-VMA, not per-page (a stale DONTDUMP flag on a freed
        // range is a no-op).
        #[cfg(unix)]
        {
            if self.locked {
                unsafe {
                    let ptr = self.inner.as_mut_ptr() as *mut libc::c_void;
                    let len = self.inner.len();
                    let _ = libc::munlock(ptr, len);
                }
            }
        }
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

// ============================================================================
// Passphrase reading
// ============================================================================

/// Read a passphrase from stdin with terminal echo disabled.
///
/// The implementation pre-allocates a single mlock'd `SecretBytes` of
/// `MAX_PASS_LEN` and writes each byte directly into it. No intermediate
/// `Vec`, no `String`, no per-byte reallocation. The buffer is wiped on
/// drop.
pub fn read_passphrase(prompt: &str) -> io::Result<SecretBytes> {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    let is_tty = stdin.is_terminal();
    if is_tty {
        eprint!("{}", prompt);
        // Disable terminal echo while reading the passphrase.
        #[cfg(unix)]
        {
            let fd = libc::STDIN_FILENO;
            let mut term: libc::termios = unsafe { std::mem::zeroed() };
            // If tcgetattr fails on a TTY, we MUST NOT fall back to
            // reading with echo enabled — that would print the passphrase
            // to the screen. Instead, return an error immediately. The
            // operator must fix the terminal (e.g., not a real TTY, race
            // with terminal close).
            if unsafe { libc::tcgetattr(fd, &mut term) } == 0 {
                let original = term;
                term.c_lflag &= !libc::ECHO;
                // If tcsetattr fails, ECHO is not disabled and reading
                // the passphrase would echo it to the terminal in
                // cleartext. Fail hard rather than silently leak.
                if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
                    return Err(io::Error::other(
                        "tcsetattr failed — refusing to read passphrase with echo enabled",
                    ));
                }

                // Use a Drop guard to restore terminal settings. If
                // `read_passphrase_into_buffer` panicked, the terminal
                // would be left with echo DISABLED — forcing the
                // operator to type `stty echo` blindly to recover. The
                // guard's Drop impl runs even during unwind.
                struct TtyGuard {
                    fd: i32,
                    original: libc::termios,
                    restored: bool,
                }
                impl Drop for TtyGuard {
                    fn drop(&mut self) {
                        if !self.restored {
                            unsafe {
                                let _ = libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
                            }
                        }
                    }
                }
                let mut guard = TtyGuard {
                    fd,
                    original,
                    restored: false,
                };

                let result = read_passphrase_into_buffer();

                // Restore explicitly (the guard would also do it on drop).
                unsafe {
                    let _ = libc::tcsetattr(fd, libc::TCSANOW, &original);
                }
                guard.restored = true;
                drop(guard);

                eprintln!();
                return result;
            } else {
                return Err(io::Error::other(
                    "tcgetattr failed on TTY — refusing to read passphrase with echo enabled",
                ));
            }
        }
    }
    read_passphrase_into_buffer()
}

fn read_passphrase_into_buffer() -> io::Result<SecretBytes> {
    use std::io::Read;
    // Pre-allocate a single mlock'd buffer.
    // On return, we copy the used prefix into a fresh SecretBytes (so the
    // oversized buffer is wiped) — but the oversized buffer itself is also
    // SecretBytes and is wiped on drop, so no leak occurs.
    let mut buf = SecretBytes::new(MAX_PASS_LEN);
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    let stdin = std::io::stdin();
    while len < MAX_PASS_LEN {
        match stdin.lock().read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break;
                }
                buf.as_bytes_mut()[len] = byte[0];
                len += 1;
            }
            Err(e) => {
                // Zeroize the 1-byte stack buffer before returning on
                // error, so the last-read byte does not linger on the stack.
                byte.zeroize();
                return Err(e);
            }
        }
    }
    // Copy the used prefix into a tightly-sized SecretBytes.
    // `buf` (full MAX_PASS_LEN) will be zeroized on drop.
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    // Wipe the oversized buffer immediately (don't wait for drop).
    buf.wipe();
    // Zeroize the 1-byte stack buffer that held the last passphrase byte
    // read. Without this, `byte[0]` lingers on the stack frame until the
    // function returns and the stack slot is reused by the caller — a
    // small but real leak of the final passphrase character.
    byte.zeroize();
    Ok(passphrase)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Print a one-time warning that per-buffer mlock failed for a
/// large buffer. Called from `try_lock` only when process-wide
/// `mlockall(MCL_FUTURE)` is already active (so the warning is
/// informational, not security-critical).
#[cfg(unix)]
fn warn_mlock_failed_once(len: usize) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    let err = io::Error::last_os_error();
    eprintln!(
        "[fortis] WARNING: per-buffer mlock failed on a {}-byte secret buffer ({}).",
        len, err
    );
    eprintln!("[fortis]          Process-wide mlockall(MCL_FUTURE) is active, so the buffer");
    eprintln!("[fortis]          is still locked against swap. This warning is informational.");
}

/// Disable core dumps process-wide. Called once from
/// `init_process_memory_protection()`.
///
/// Defense in depth:
///   1. `setrlimit(RLIMIT_CORE, 0)` — kernel will not write a core file
///      even on crash. Available on all Unix.
///   2. `prctl(PR_SET_DUMPABLE, 0)` (Linux only) — also blocks ptrace
///      attach by non-root users and disables core-dump generation even
///      if RLIMIT_CORE is later raised. PR_SET_DUMPABLE = 4 on Linux.
#[cfg(unix)]
#[allow(dead_code)]
fn disable_core_dumps() {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            let err = io::Error::last_os_error();
            eprintln!(
                "[fortis] WARNING: failed to disable core dumps via setrlimit(RLIMIT_CORE, 0) ({}).",
                err
            );
            eprintln!(
                "[fortis]          If the process crashes, secrets may appear in a core file."
            );
        }
        // PR_SET_DUMPABLE = 4. Linux only.
        #[cfg(target_os = "linux")]
        {
            // Use the literal constant 4 rather than libc::PR_SET_DUMPABLE
            // for compatibility with older versions of the libc crate that
            // may not expose the symbolic constant.
            let pr_set_dumpable: libc::c_int = 4;
            if libc::prctl(pr_set_dumpable, 0, 0, 0, 0) != 0 {
                let err = io::Error::last_os_error();
                eprintln!(
                    "[fortis] WARNING: prctl(PR_SET_DUMPABLE, 0) failed ({}).",
                    err
                );
            }
        }
    }
}

/// Raise RLIMIT_MEMLOCK before the first mlock call. Called once per
/// process (the static AtomicBool ensures it only runs once).
#[cfg(unix)]
fn ensure_mlock_limit_raised() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static TRIED: AtomicBool = AtomicBool::new(false);
    if TRIED.swap(true, Ordering::SeqCst) {
        return; // Already tried this process.
    }
    force_raise_memlock_rlimit();
}

/// Unconditionally attempt to raise RLIMIT_MEMLOCK soft limit to the
/// hard limit. Safe to call multiple times. Used both by the lazy
/// `ensure_mlock_limit_raised()` (called from `try_lock`) and by
/// `init_process_memory_protection()` (called eagerly at startup).
///
/// On most Linux systems, the default soft limit is 64 KB — far too
/// small for crypto buffers (Argon2id uses 64+ MiB). We try to raise
/// the soft limit to the hard limit. This requires either:
///   (a) CAP_IPC_LOCK capability, OR
///   (b) /etc/security/limits.conf with `* soft memlock unlimited`
///   (c) systemd user session with `LimitMEMLOCK=infinity`
/// If none of these are set, the raise fails silently — the caller
/// (init_process_memory_protection or try_lock) handles the consequences.
#[cfg(unix)]
fn force_raise_memlock_rlimit() {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
            // Try to raise the soft limit to the hard limit.
            // If the hard limit is RLIM_INFINITY, set soft to infinity too.
            let new_soft = rlim.rlim_max;
            if new_soft > rlim.rlim_cur {
                let mut new_rlim = rlim;
                new_rlim.rlim_cur = new_soft;
                // Best-effort: on failure, emit a single diagnostic
                // line so the operator knows the raise was attempted
                // and rejected. The caller (init_process_memory_protection)
                // will report a fatal error if mlockall subsequently
                // fails. Using eprintln! (not log) keeps this dependency-
                // free. The diagnostic is intentionally terse to avoid
                // leaking the actual limit values to a terminal-log
                // adversary (though they are already observable via
                // /proc/self/limits).
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlim) != 0 {
                    static RLIMIT_WARNED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !RLIMIT_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        eprintln!(
                            "[fortis] warning: could not raise RLIMIT_MEMLOCK \
                             (need CAP_IPC_LOCK or limits.conf entry)."
                        );
                    }
                }
            }
        }
    }
}
