//! Secure memory helpers.
//!
//! `SecretBytes` is a `Vec<u8>` wrapper that zeroizes on drop via
//! `Zeroizing` (volatile writes LLVM cannot elide), mlocks the buffer
//! against swap, marks it `MADV_DONTDUMP` on Linux, and exposes a
//! constant-time `ct_eq`. Store all secret material in `SecretBytes`.
//!
//! Invariants: no `Clone` (use `try_clone` for an explicit re-mlocked
//! copy), no `Debug` or `Display` (no accidental `{}`/`{:?}` leaks),
//! zeroized on Drop. Per-buffer `mlock` failure is fatal unless
//! `mlockall(MCL_FUTURE)` is active.

use std::io;
use zeroize::{Zeroize, Zeroizing};

/// Max passphrase length. Bounded so we can pre-allocate one mlocked
/// buffer instead of growing it byte-by-byte. 4 KiB is generous.
pub const MAX_PASS_LEN: usize = 4096;

// ============================================================================
// Process-wide memory protection state
// ============================================================================

/// True once `mlockall(MCL_CURRENT | MCL_FUTURE)` is active. While true,
/// per-buffer `mlock` in `SecretBytes::try_lock` is redundant and failure
/// there is non-fatal. While false, per-buffer `mlock` is the only swap
/// defense and failure aborts.
static PROCESS_MLOCKALL_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set when the operator accepted the no-mlockall risk in a debug build
/// via FORTIS_ALLOW_NO_MLOCK=1. While set, per-buffer `mlock` failures
/// in `try_lock` are non-fatal, matching `process_mlockall_active()`.
static MLOCKALL_BYPASS_ACCEPTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Initialize process-wide memory protection: raise RLIMIT_MEMLOCK,
/// disable core dumps, then mlockall(MCL_CURRENT | MCL_FUTURE). Call once
/// at startup before any secret material is allocated. Idempotent; on
/// non-Unix targets this is a no-op.
///
/// `main.rs` runs its own mlockall sequence with the FORTIS_ALLOW_NO_MLOCK
/// policy and does not call this. This function exists for test harnesses
/// and future library embedders. Pick one path; do not run both.
///
/// mlockall failure aborts via `exit(2)`. There is no env-var bypass: a
/// compromised host must not be able to silently disable swap protection.
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

        // Step 3: mlockall(MCL_CURRENT | MCL_FUTURE). Retry once after the
        // rlimit raise above in case the kernel needs the new limit visible.
        let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
        let first = unsafe { libc::mlockall(flags) };
        if first != 0 {
            let first_err = io::Error::last_os_error();
            // Try raising the limit one more time, then retry.
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
                // No escape hatch.
                eprintln!("[fortis] Refusing to continue without memory locking.");
                // exit(2): no secret buffers exist yet. Avoid abort()
                // because SIGABRT could itself trigger a core dump if
                // RLIMIT_CORE could not be lowered above.
                std::process::exit(2);
            }
        }

        // Mark process-wide protection as active. From this point on,
        // per-buffer mlock failures in SecretBytes::try_lock are non-fatal.
        PROCESS_MLOCKALL_DONE.store(true, Ordering::SeqCst);
    }
}

/// True if process-wide mlockall is active. Used by `try_lock` to decide
/// whether per-buffer mlock failure is fatal or merely diagnostic.
#[inline]
pub fn process_mlockall_active() -> bool {
    PROCESS_MLOCKALL_DONE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Mark process-wide mlockall as active. Called by `main.rs` after its
/// own mlockall sequence (which honors FORTIS_ALLOW_NO_MLOCK, unlike
/// `init_process_memory_protection`). After this call, per-buffer mlock
/// failures in `SecretBytes::try_lock` are non-fatal. Idempotent.
#[allow(dead_code)]
pub fn mark_process_mlockall_active() {
    PROCESS_MLOCKALL_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Mark the FORTIS_ALLOW_NO_MLOCK bypass as accepted. Called by `main`
/// in debug builds when mlockall failed but the operator opted in. After
/// this call, per-buffer mlock failures are non-fatal. Never called in
/// release builds.
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

/// Byte buffer that is zeroized on drop and mlocked. Intentionally does
/// not implement `Clone`, `Debug`, or `Display`; see module docs.
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SecretBytes {
    /// Allocate a zero-filled buffer of `len` bytes. mlocks automatically.
    pub fn new(len: usize) -> Self {
        let mut s = Self {
            inner: Zeroizing::new(vec![0u8; len]),
            locked: false,
        };
        s.try_lock();
        s
    }

    /// Copy `src` into a new mlocked `SecretBytes`. The source slice is
    /// not wiped; the caller owns it and must wipe it themselves.
    pub fn from_slice(src: &[u8]) -> Self {
        let mut v = Self::new(src.len());
        v.inner[..].copy_from_slice(src);
        v
    }

    /// Borrow the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Mutably borrow the inner bytes.
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

    /// Independent copy with its own mlocked backing store. The only way
    /// to duplicate a `SecretBytes`; `Clone` is intentionally absent so
    /// every copy is explicit. Used when the same passphrase feeds
    /// multiple slot derivations.
    pub fn try_clone(&self) -> Self {
        Self::from_slice(&self.inner)
    }

    /// Constant-time equality with `other`. Accumulates XOR differences
    /// across the whole buffer and only checks the accumulator at the end,
    /// so running time does not depend on where (or whether) buffers
    /// differ. Length comparison is not constant-time; if length is secret
    /// in your context, pad both sides first.
    #[allow(dead_code)]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        let a = self.as_bytes();
        let b = other;
        if a.len() != b.len() {
            return false;
        }
        // Accumulate XOR differences. The compiler cannot short-circuit
        // because `diff` is only inspected after the loop. A u8 accumulator
        // is enough; we only care about zero-vs-nonzero.
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        // Single-byte comparison at the end; no secret-dependent branch
        // on buffer contents.
        diff == 0
    }

    /// mlock the buffer against swap and mark it `MADV_DONTDUMP` on Linux.
    ///
    /// If process-wide mlockall is active, per-buffer mlock is redundant
    /// and failure is informational (warned once). Otherwise per-buffer
    /// mlock is the only swap defense and failure aborts the process.
    /// MADV_DONTDUMP excludes the page from core dumps even if
    /// RLIMIT_CORE/dumpable settings are missing or get reverted.
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
                // Exclude this region from core dumps on Linux even if
                // the process-wide dump disabling did not stick.
                #[cfg(target_os = "linux")]
                unsafe {
                    // Best-effort: MADV_DONTDUMP failure is not
                    // security-critical if process-wide dump disabling
                    // succeeded.
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                }
            } else {
                // Decide fatality based on whether process-wide
                // mlockall(MCL_FUTURE) is active OR the operator has
                // explicitly accepted the no-mlock risk in a debug build.
                if process_mlockall_active() || mlockall_bypass_accepted() {
                    // Process-wide protection is active or the operator
                    // accepted the risk. Warn once for diagnosis and only
                    // for buffers large enough that the warning matters.
                    if len >= 1024 {
                        warn_mlock_failed_once(len);
                    }
                } else {
                    // Per-buffer mlock is the only swap defense and it
                    // failed. Abort rather than use unprotected memory.
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
                    // abort(): do not run Drop. The buffer is still all
                    // zeros at this point (try_lock runs from new() /
                    // from_slice() before any secret is copied in), so
                    // skipping Drop is safe. Faster than exit(2).
                    std::process::abort();
                }
            }
        }
    }

    /// Wipe the buffer now via volatile writes (also done on drop).
    pub fn wipe(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Zeroizing<> zero-fills via volatile writes. munlock if we
        // mlock'd this buffer. MADV_DONTDUMP does not need undoing: it
        // is per-VMA and a stale flag on a freed range is a no-op.
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

/// Read a passphrase from stdin with terminal echo disabled. Pre-allocates
/// one mlocked `SecretBytes` of `MAX_PASS_LEN` and writes each byte
/// directly into it; no intermediate Vec or String.
pub fn read_passphrase(prompt: &str) -> io::Result<SecretBytes> {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    let is_tty = stdin.is_terminal();
    if is_tty {
        eprint!("{}", prompt);
        // Disable echo while reading.
        #[cfg(unix)]
        {
            let fd = libc::STDIN_FILENO;
            let mut term: libc::termios = unsafe { std::mem::zeroed() };
            // Do not fall back to echo-enabled read if tcgetattr fails on
            // a TTY: that would print the passphrase. Fail hard.
            if unsafe { libc::tcgetattr(fd, &mut term) } == 0 {
                let original = term;
                term.c_lflag &= !libc::ECHO;
                // If tcsetattr fails, ECHO is not disabled. Fail hard
                // rather than echo the passphrase.
                if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
                    return Err(io::Error::other(
                        "tcsetattr failed — refusing to read passphrase with echo enabled",
                    ));
                }

                // Drop guard restores terminal settings if the read
                // panics, so the operator is not left with echo disabled.
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
    // Pre-allocate one mlocked buffer. The used prefix is copied into a
    // tightly-sized SecretBytes; the oversized original is wiped on drop.
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
                // Wipe the 1-byte stack buffer before returning on error.
                byte.zeroize();
                return Err(e);
            }
        }
    }
    // Copy the used prefix into a tightly-sized SecretBytes.
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    // Wipe the oversized buffer and the 1-byte stack read buffer now
    // rather than waiting for drop, so the last byte does not linger.
    buf.wipe();
    byte.zeroize();
    Ok(passphrase)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// One-time warning that per-buffer mlock failed for a large buffer.
/// Called from `try_lock` only when mlockall(MCL_FUTURE) is already
/// active, so the warning is informational.
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
/// `init_process_memory_protection()`. Uses setrlimit(RLIMIT_CORE, 0)
/// on all Unix and prctl(PR_SET_DUMPABLE, 0) on Linux, which also
/// blocks ptrace attach by non-root users.
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
            // Use the literal 4 for compatibility with older libc crate
            // versions that may not expose the symbolic constant.
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

/// Raise RLIMIT_MEMLOCK before the first mlock call. Runs once per
/// process via a static AtomicBool guard.
#[cfg(unix)]
fn ensure_mlock_limit_raised() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static TRIED: AtomicBool = AtomicBool::new(false);
    if TRIED.swap(true, Ordering::SeqCst) {
        return; // Already tried this process.
    }
    force_raise_memlock_rlimit();
}

/// Raise the RLIMIT_MEMLOCK soft limit to the hard limit. Safe to call
/// multiple times; used by `ensure_mlock_limit_raised` (lazy, from
/// `try_lock`) and `init_process_memory_protection` (eager, at startup).
///
/// The default 64 KB soft limit is far too small for Argon2id's 64+ MiB
/// working set. Raising requires CAP_IPC_LOCK, a limits.conf entry, or
/// a systemd LimitMEMLOCK setting; otherwise the raise fails silently
/// and the caller decides what to do.
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
                // Best-effort: emit one diagnostic line on failure so the
                // operator knows the raise was rejected. The caller
                // reports a fatal error if mlockall then fails. Terse to
                // avoid leaking limit values to terminal logs (they are
                // already visible via /proc/self/limits).
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
