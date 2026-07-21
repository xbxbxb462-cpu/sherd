//! Cryptographic primitives.
//!
//! Submodules are declared `pub(crate)` so the internals cannot be imported
//! by external consumers if Fortis is ever converted to a library crate.
//!
//! Every secret buffer passed in or out of this module is wrapped in
//! `Zeroizing<Vec<u8>>` or `SecretBytes` (which zeroizes on drop). Callers
//! that move secret-derived data into non-`Zeroizing` containers are
//! considered bugs and must be fixed.

pub(crate) mod aead;
pub(crate) mod commit;
pub(crate) mod constants;
pub(crate) mod kdf;
pub(crate) mod rng;
