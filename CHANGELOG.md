# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-21

### Added

- Plausible deniability via indistinguishable two-slot envelope. Every
  file has exactly two slots; if no decoy is supplied, the second slot
  is a structurally identical dummy. Sizes are randomized so an
  observer cannot tell which slot is "real".
- Shamir Secret Sharing over GF(256) with branchless, constant-time
  arithmetic. Shares are a fixed 4098 bytes regardless of secret
  length; threshold K and total N are not stored in any share, so an
  interceptor of a single share learns nothing about the quorum.
- `--force` flag on `encrypt` and `encrypt-file` to override the
  recursive-encryption check.
- `--pass-fd`, `--pass-file`, and `--decoy-pass-fd`/`--decoy-pass-file`
  options for non-interactive passphrase input.
- `sherd selftest` command runs Argon2id, HKDF-SHA256, HMAC-SHA256,
  AES-256-GCM known-answer tests plus round-trip and tamper-rejection
  tests.
- `sherd hash` command prints the SHA-256 of the running binary for
  out-of-band verification.
- Uniform-timing decryption: every chunk of every slot is processed
  regardless of commit-tag match, closing the timing side-channel that
  would otherwise break plausible deniability.
- Constant-time padding-length unpadder that copies a data-independent
  number of bytes per slot.

### Changed

- All secret buffers (passphrase, master key, PRK, commit key,
  per-chunk keys, padded plaintext, decrypted output, Shamir-
  reconstructed secret) are wrapped in `Zeroizing<…>` and wiped on
  drop.
- `mlockall(MCL_CURRENT | MCL_FUTURE)` is mandatory in release builds.
  The `SHERD_ALLOW_NO_MLOCK` environment variable is honored only in
  debug builds (with a loud warning); in release builds the variable
  is rejected before `mlockall` runs.
- Core dumps are disabled process-wide via `setrlimit(RLIMIT_CORE, 0)`
  and `prctl(PR_SET_DUMPABLE, 0)` (Linux).
- Output files are created with mode 0600 on Unix regardless of umask.
- Argon2id parameter minimums enforced: 64 MiB memory, 3 iterations,
  4 parallelism lanes (RFC 9106 §4 first recommendation).
- AES-256-GCM per-chunk keys are derived via HKDF-Expand with
  `chunk_index` and `chunk_count` bound into the `info` label for
  domain separation.
- Per-chunk nonces use the full 96 bits of `base_iv` entropy
  (XOR scheme instead of the previous truncating scheme).
- Padding is randomized and non-block-aligned (replaces the
  deterministic 4 KiB-block quantization that leaked plaintext length
  within 4 KiB).
- `FLAG_PARANOID` is always set in the wire format so an observer
  cannot distinguish paranoid from non-paranoid encryptions.
- Commit tag now binds a SHA-256 hash of the first chunk's ciphertext
  to prevent the "invisible salamander" ciphertext-swap attack.
- ASCII armor parser is strict: validates BEGIN/END labels, rejects
  multiple blocks, rejects non-canonical base64, and rejects
  Unicode whitespace injection.

### Security

- Closed length-oracle: output file size is no longer padded to
  multiples of 8192 bytes.
- Closed Shamir metadata leak: share header no longer encodes K (was
  at byte 2 of every share).
- Closed decoy size leak: both slots are padded to the same randomized
  target length.
- Closed recursive-encryption footgun: `encrypt_envelope` refuses
  input that begins with the `SHRD `magic unless `--force` is given.
- Closed memory-protection bypass: `SHERD_ALLOW_NO_MLOCK` is no
  longer honored in release builds.
- Closed TOCTOU on input files: `open_and_read_bounded` opens the
  file once, fstats the fd, and reads from the same fd.
- Closed AEAD keystream leak: `decrypt_chunk` uses
  `decrypt_in_place_detached` with a `Zeroizing` buffer so the
  AES-CTR keystream is wiped even on tag mismatch.
- Closed GF(256) timing leak: `gmul` is branchless (bitmask-based).
- Closed HMAC-SHA256 KAT gap: the KAT now compares the full 32-byte
  RFC 4231 Test Case 1 reference value.
