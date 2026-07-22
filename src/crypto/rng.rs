//! OS RNG wrapper with an all-zeros health check. Crypto code should route
//! every random fill through `fill` so the check runs uniformly.

use rand::{rngs::OsRng, RngCore};

/// Smallest buffer checked for all-zeros. 8 bytes gives a 2^-64 false positive rate.
const HEALTH_CHECK_MIN_LEN: usize = 8;

/// Fill `buf` from the OS CSPRNG and panic if the result is all zeros.
pub(crate) fn fill(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
    health_check(buf);
}

/// Panic if `buf` is all zeros. Skipped for buffers under `HEALTH_CHECK_MIN_LEN`.
fn health_check(buf: &[u8]) {
    if buf.len() < HEALTH_CHECK_MIN_LEN {
        return;
    }
    let mut acc: u8 = 0;
    for b in buf.iter() {
        acc |= *b;
    }
    if acc == 0 {
        panic!("SHERD: OS CSPRNG health check failed");
    }
}
