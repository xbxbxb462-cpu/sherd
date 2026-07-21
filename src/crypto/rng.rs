//! OS RNG wrapper. All secrets come from `OsRng`. After every fill the
//! buffer is checked for the all-zeros pattern; if seen, the process
//! panics.

use rand::{rngs::OsRng, RngCore};

/// Smallest buffer checked for all-zeros. 8 bytes = 2^-64 false positive rate.
const HEALTH_CHECK_MIN_LEN: usize = 8;

/// Fill `buf` from the OS CSPRNG. Panics on failure or if the all-zeros
/// health check trips.
pub(crate) fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
    health_check(buf);
}

/// Panic if `buf` is all-zeros, the signature of a dead CSPRNG. Skipped
/// for buffers under `HEALTH_CHECK_MIN_LEN`.
fn health_check(buf: &[u8]) {
    if buf.len() < HEALTH_CHECK_MIN_LEN {
        return;
    }
    let mut acc: u8 = 0;
    for b in buf.iter() {
        acc |= *b;
    }
    if acc == 0 {
        // Generic message; do not echo buffer contents.
        panic!("SHERD: OS CSPRNG health check failed");
    }
}
