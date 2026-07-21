//! Secure memory helpers.
//!
//! `SecretBytes` wraps `Vec<u8>` with zeroize-on-drop, mlock against swap,
//! and `MADV_DONTDUMP` on Linux. No `Clone`/`Debug`/`Display` so secrets
//! cannot leak through formatting. Per-buffer mlock failure is fatal
//! unless mlockall(MCL_FUTURE) is active.

use std::io;
use zeroize::{Zeroize, Zeroizing};

/// Max passphrase length. Bounded so we pre-allocate one mlocked buffer
/// instead of growing byte-by-byte.
pub const MAX_PASS_LEN: usize = 4096;

// ============================================================================
// Process-wide memory protection state
// ============================================================================

/// True once mlockall(MCL_CURRENT | MCL_FUTURE) is active. When true,
/// per-buffer mlock is redundant and failure is non-fatal.
static PROCESS_MLOCKALL_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set when the operator accepted the no-mlockall risk in a debug build
/// via SHERD_ALLOW_NO_MLOCK=1.
static MLOCKALL_BYPASS_ACCEPTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Raise RLIMIT_MEMLOCK, disable core dumps, then mlockall. Call once at
/// startup before any secret is allocated. Idempotent; no-op on non-Unix.
/// `main.rs` runs its own sequence with the SHERD_ALLOW_NO_MLOCK policy
/// and does not call this. Pick one path; do not run both. mlockall
/// failure aborts via exit(2) with no env-var bypass.
#[allow(dead_code)]
pub fn init_process_memory_protection() {
    use std::sync::atomic::Ordering;
    if PROCESS_MLOCKALL_DONE.load(Ordering::SeqCst) {
        return;
    }

    #[cfg(unix)]
    {
        ensure_mlock_limit_raised();
        disable_core_dumps();

        let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
        let first = unsafe { libc::mlockall(flags) };
        if first != 0 {
            let first_err = io::Error::last_os_error();
            force_raise_memlock_rlimit();
            let second = unsafe { libc::mlockall(flags) };
            if second != 0 {
                let second_err = io::Error::last_os_error();
                eprintln!("[sherd] FATAL: mlockall(MCL_CURRENT | MCL_FUTURE) failed.");
                eprintln!(
                    "[sherd]   Initial error: {} ({:?})",
                    first_err,
                    first_err.kind()
                );
                eprintln!(
                    "[sherd]   Retry error:   {} ({:?})",
                    second_err,
                    second_err.kind()
                );
                eprintln!("[sherd] Memory locking is mandatory; secrets could otherwise");
                eprintln!("[sherd] swap to disk or appear in core dumps.");
                eprintln!("[sherd] Fix one of:");
                eprintln!("[sherd]   sudo setcap cap_ipc_lock=ep ./sherd");
                eprintln!("[sherd]   add to /etc/security/limits.conf:");
                eprintln!("[sherd]     *  soft  memlock  unlimited");
                eprintln!("[sherd]     *  hard  memlock  unlimited");
                eprintln!("[sherd]   then log out and back in; or re-run as root.");
                eprintln!("[sherd] Refusing to continue without memory locking.");
                // exit(2): no secret buffers exist yet. Avoid abort()
                // because SIGABRT could itself trigger a core dump.
                std::process::exit(2);
            }
        }

        PROCESS_MLOCKALL_DONE.store(true, Ordering::SeqCst);
    }
}

/// True if process-wide mlockall is active.
#[inline]
pub fn process_mlockall_active() -> bool {
    PROCESS_MLOCKALL_DONE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Mark process-wide mlockall as active. Called by `main.rs` after its
/// own sequence. After this call, per-buffer mlock failures are non-fatal.
#[allow(dead_code)]
pub fn mark_process_mlockall_active() {
    PROCESS_MLOCKALL_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Mark the SHERD_ALLOW_NO_MLOCK bypass as accepted. Debug builds only.
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

/// Byte buffer that is zeroized on drop and mlocked. No `Clone`/`Debug`/
/// `Display`; see module docs.
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
    /// not wiped; the caller owns it.
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

    /// Independent copy with its own mlocked backing store. `Clone` is
    /// absent so every copy is explicit.
    pub fn try_clone(&self) -> Self {
        Self::from_slice(&self.inner)
    }

    /// Constant-time equality with `other`. Accumulates XOR differences
    /// across the whole buffer and checks the accumulator only at the
    /// end. Length comparison is not constant-time; pad both sides first
    /// if length is secret in your context.
    #[allow(dead_code)]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        let a = self.as_bytes();
        let b = other;
        if a.len() != b.len() {
            return false;
        }
        // Single u8 accumulator; we only care about zero-vs-nonzero.
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// mlock the buffer against swap and mark it `MADV_DONTDUMP` on Linux.
    /// If mlockall is active, per-buffer mlock failure is informational.
    /// Otherwise it is the only swap defense and aborts the process.
    /// MADV_DONTDUMP excludes the page from core dumps even if
    /// RLIMIT_CORE/dumpable settings get reverted.
    pub fn try_lock(&mut self) {
        if self.locked {
            return;
        }
        #[cfg(unix)]
        {
            ensure_mlock_limit_raised();

            let ptr = self.inner.as_mut_ptr() as *mut libc::c_void;
            let len = self.inner.len();
            let mlock_ok = unsafe { libc::mlock(ptr, len) } == 0;

            if mlock_ok {
                self.locked = true;
                #[cfg(target_os = "linux")]
                unsafe {
                    // Best-effort: process-wide dump disabling covers this
                    // if it fails.
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                }
            } else if process_mlockall_active() || mlockall_bypass_accepted() {
                // Warn once for diagnosis on buffers large enough to matter.
                if len >= 1024 {
                    warn_mlock_failed_once(len);
                }
            } else {
                let err = io::Error::last_os_error();
                eprintln!(
                    "[sherd] FATAL: mlock failed on secret buffer of {} bytes ({}).",
                    len, err
                );
                eprintln!(
                    "[sherd]        init_process_memory_protection() was not called or failed;"
                );
                eprintln!(
                    "[sherd]        per-buffer mlock is the only swap defense and it failed."
                );
                eprintln!("[sherd]        Refusing to use unprotected memory for secrets.");
                eprintln!("[sherd]        Fix: grant CAP_IPC_LOCK or run as root, then retry.");
                // abort(): the buffer is still zeros at this point because
                // try_lock runs from new()/from_slice() before any secret
                // is copied in, so skipping Drop is safe.
                std::process::abort();
            }
        }
    }

    /// Wipe the buffer now via volatile writes. Also done on drop.
    pub fn wipe(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Zeroizing<> zero-fills via volatile writes. munlock if we
        // mlock'd this buffer. MADV_DONTDUMP needs no undo.
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
        #[cfg(unix)]
        {
            let fd = libc::STDIN_FILENO;
            let mut term: libc::termios = unsafe { std::mem::zeroed() };
            // Fail hard if tcgetattr fails: falling back to echo-enabled
            // read would print the passphrase.
            if unsafe { libc::tcgetattr(fd, &mut term) } == 0 {
                let original = term;
                term.c_lflag &= !libc::ECHO;
                if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
                    return Err(io::Error::other(
                        "tcsetattr failed, refusing to read passphrase with echo enabled",
                    ));
                }

                // Restore terminal settings if the read panics.
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

                unsafe {
                    let _ = libc::tcsetattr(fd, libc::TCSANOW, &original);
                }
                guard.restored = true;
                drop(guard);

                eprintln!();
                return result;
            } else {
                return Err(io::Error::other(
                    "tcgetattr failed on TTY, refusing to read passphrase with echo enabled",
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
                byte.zeroize();
                return Err(e);
            }
        }
    }
    let passphrase = SecretBytes::from_slice(&buf.as_bytes()[..len]);
    // Wipe now rather than waiting for drop, so the last byte does not linger.
    buf.wipe();
    byte.zeroize();
    Ok(passphrase)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// One-time warning that per-buffer mlock failed for a large buffer.
/// Only called when mlockall(MCL_FUTURE) is already active.
#[cfg(unix)]
fn warn_mlock_failed_once(len: usize) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    let err = io::Error::last_os_error();
    eprintln!(
        "[sherd] WARNING: per-buffer mlock failed on a {}-byte secret buffer ({}).",
        len, err
    );
    eprintln!("[sherd]          Process-wide mlockall(MCL_FUTURE) is active, so the buffer");
    eprintln!("[sherd]          is still locked against swap. This warning is informational.");
}

/// Disable core dumps process-wide via setrlimit(RLIMIT_CORE, 0) on all
/// Unix, plus prctl(PR_SET_DUMPABLE, 0) on Linux which also blocks ptrace
/// attach by non-root users.
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
                "[sherd] WARNING: failed to disable core dumps via setrlimit(RLIMIT_CORE, 0) ({}).",
                err
            );
            eprintln!(
                "[sherd]          If the process crashes, secrets may appear in a core file."
            );
        }
        // PR_SET_DUMPABLE = 4. Linux only.
        #[cfg(target_os = "linux")]
        {
            // Literal 4 for older libc crate versions.
            let pr_set_dumpable: libc::c_int = 4;
            if libc::prctl(pr_set_dumpable, 0, 0, 0, 0) != 0 {
                let err = io::Error::last_os_error();
                eprintln!(
                    "[sherd] WARNING: prctl(PR_SET_DUMPABLE, 0) failed ({}).",
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
        return;
    }
    force_raise_memlock_rlimit();
}

/// Raise the RLIMIT_MEMLOCK soft limit to the hard limit. Safe to call
/// multiple times. The default 64 KB soft limit is too small for
/// Argon2id's 64+ MiB working set; raising requires CAP_IPC_LOCK or a
/// limits.conf/systemd LimitMEMLOCK entry.
#[cfg(unix)]
fn force_raise_memlock_rlimit() {
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) == 0 {
            let new_soft = rlim.rlim_max;
            if new_soft > rlim.rlim_cur {
                let mut new_rlim = rlim;
                new_rlim.rlim_cur = new_soft;
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rlim) != 0 {
                    static RLIMIT_WARNED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !RLIMIT_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        eprintln!(
                            "[sherd] warning: could not raise RLIMIT_MEMLOCK \
                             (need CAP_IPC_LOCK or limits.conf entry)."
                        );
                    }
                }
            }
        }
    }
}
