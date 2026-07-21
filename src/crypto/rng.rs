//! OS RNG wrapper. All secrets come from `OsRng`. After every fill the
//! buffer is checked for the all-zeros pattern; if seen, the process
//! panics. The scan is constant-time.

use rand::{rngs::OsRng, RngCore};

/// Minimum buffer size checked for all-zeros. 8 bytes gives a 2^-64
/// false-positive rate from a working RNG.
const HEALTH_CHECK_MIN_LEN: usize = 8;

/// Fill `buf` from the OS CSPRNG. Panics on CSPRNG failure or if the
/// all-zeros health check trips. With `panic = "unwind"`, Drop still runs
/// and secret buffers get wiped.
pub(crate) fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
    health_check(buf);
}

/// Panic if `buf` is all-zeros, the signature of a dead CSPRNG. Skipped
/// for buffers under `HEALTH_CHECK_MIN_LEN`. No statistical tests: kernel
/// RNG health is the kernel's job, and false positives on real random
/// data would be worse than catching the rare zero output.
fn health_check(buf: &[u8]) {
    if buf.len() < HEALTH_CHECK_MIN_LEN {
        return;
    }
    // OR-accumulate. Constant-time, no early break.
    let mut acc: u8 = 0;
    for b in buf.iter() {
        acc |= *b;
    }
    if acc == 0 {
        // Generic message; never echo buffer length or contents.
        panic!("FORTIS: OS CSPRNG health check failed");
    }
}
