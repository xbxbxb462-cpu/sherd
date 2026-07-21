//! Secure RNG wrapper.
//!
//! Uses `rand::rngs::OsRng` which delegates to the OS CSPRNG
//! (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, etc.).
//!
//! This module is the sole entry point for random bytes in Fortis. All
//! secret material (keys, IVs, salts) is derived from the OS CSPRNG.
//! User-supplied RNGs (deterministic PRNGs, hardware RNG drivers, etc.)
//! are forbidden for key generation.
//!
//! After every `fill` call the buffer is checked for the all-zeros
//! pattern — the canonical signal of a broken CSPRNG (e.g. `getrandom`
//! returning uninitialized memory, or a kernel bug). If detected, the
//! process panics immediately. The check only applies to buffers >= 8
//! bytes (probability of a false positive for an 8-byte buffer from a
//! working RNG is 2^-64, negligible).
//!
//! The health check is constant-time (OR-accumulation over the full
//! buffer, no early break) to avoid timing side-channels on the RNG
//! output, even though the output is not secret-derived. This is
//! defense-in-depth: a timing leak on RNG output position could
//! indirectly reveal buffer-length-dependent behavior to a side-channel
//! observer.

use rand::{rngs::OsRng, RngCore};

/// Minimum buffer size for the all-zeros health check. Buffers smaller than
/// this are not checked (a 1-byte zero is legitimate with probability 1/256;
/// a 4-byte zero has probability 2^-32 which is still too high for a
/// panic-on-failure check; 8 bytes gives 2^-64 false-positive rate).
const HEALTH_CHECK_MIN_LEN: usize = 8;

/// Fill `buf` with cryptographically-secure random bytes from the OS CSPRNG.
///
/// Panics if the OS CSPRNG fails (extremely rare: requires early-boot
/// entropy starvation on Linux <3.17 or a broken getrandom syscall) OR if
/// the output fails the all-zeros health check (catastrophic RNG failure).
/// With `panic = "unwind"`, panics run Drop impls, so secret buffers are
/// still wiped before the process exits.
pub(crate) fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
    health_check(buf);
}

/// Runtime weak-RNG detection.
///
/// Checks that the buffer is not all-zeros. A zero-filled buffer from the
/// OS CSPRNG indicates a catastrophic failure (e.g., `getrandom` returning
/// uninitialized memory, or a kernel bug). The probability of a false
/// positive from a working RNG is 2^(-8*len), which for len >= 8 is
/// 2^-64 — negligible.
///
/// We deliberately do NOT perform more sophisticated statistical tests
/// (chi-square, monobit, runs test, etc.) because:
///   (a) They have non-trivial false-positive rates that would cause
///       spurious panics on legitimate random data.
///   (b) The OS CSPRNG is already vetted by the kernel; our check is a
///       last-resort safety net, not a substitute for kernel-level
///       continuous RNG testing.
///   (c) Performance matters — `fill` is called for every salt, IV, and
///       key generation, and a statistical test over a 32-byte salt on
///       every encrypt would add measurable overhead.
///
/// The scan is constant-time (OR-accumulates all bytes, no early break)
/// to prevent timing leakage of the position of the first non-zero byte.
/// While RNG output is not secret, a timing leak could reveal buffer-size
/// correlations to a side-channel observer.
fn health_check(buf: &[u8]) {
    if buf.len() < HEALTH_CHECK_MIN_LEN {
        return;
    }
    // Constant-time: OR all bytes together. If the result is 0, every
    // byte was 0. No early break, no data-dependent branch.
    let mut acc: u8 = 0;
    for b in buf.iter() {
        acc |= *b;
    }
    if acc == 0 {
        // Fatal: the OS CSPRNG produced an all-zero buffer. This means
        // every secret in the system is compromised. Panic immediately.
        // The error message is intentionally generic — do NOT include the
        // buffer length or contents, as that could leak information to an
        // observer of stderr.
        panic!("FORTIS: OS CSPRNG health check failed");
    }
}
