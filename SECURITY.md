# Security Policy

## Supported versions

Only the latest released version of Sherd receives security updates.
If you are running an older version, upgrade before reporting an
issue.

## Reporting a vulnerability

**Please do not open public GitHub issues for security-related
problems.**

Instead, report vulnerabilities privately:

1. Open a new **GitHub Security Advisory** via the
   "Security" → "Advisories" → "Report a vulnerability" tab on the
   Sherd repository, **or**
2. Email the maintainers directly at `xbxbxb462@gmail.com` (PGP
   key fingerprint published in the repository root as
   `SECURITY-PGP.asc` if available).

Please include the following in your report, where applicable:

- A description of the issue and its impact.
- The exact Sherd version (`sherd --version`) and how it was built
  (`cargo build --release` flags, target platform, Rust toolchain
  version).
- A minimal reproducer (commands, input files, expected vs. actual
  behavior).
- Any mitigations you have already applied.

We will acknowledge receipt within **72 hours** and aim to provide an
initial assessment within **14 days**. If a fix is warranted, we will
coordinate a disclosure date with you (default 90 days from
acknowledgment, extendable on request).

## Threat model

Sherd is designed to defend against:

- Ciphertext-only attackers (throttled by Argon2id memory-hard cost).
- Header tampering (every header byte is AEAD AAD AND commit-tag input).
- Commit-tag forgery (HMAC-SHA256-truncated-128 is unforgeable).
- Per-chunk compromise (per-chunk keys via HKDF-Expand are independent).
- Nonce reuse (per-chunk counter nonces unique by construction).
- Timing oracles (constant-time compare, uniform error messages,
  uniform chunk-processing count).
- Coercion (optional decoy layer with plausible deniability).
- Memory forensics (`zeroize` on every secret buffer; `mlock` on keys;
  `mlockall` on the whole process).

Sherd does **not** defend against:

- A compromised OS or hardware implant. Use an air-gapped machine
  running Tails OS for the highest-sensitivity operations.
- Cold boot attacks. Reboot cold before and after sensitive
  operations.
- Browser/OS 0-days. Out of scope for any single tool.
- Quantum adversaries with a cryptographically relevant quantum
  computer. AES-256 is Grover-resistant to 2^128; Argon2id and
  SHA-256 are similarly resistant.

## Hardening checklist for production deployment

- Build with `cargo build --release` (the release profile enables LTO,
  panic=abort, and strips symbols).
- Grant the binary `CAP_IPC_LOCK`:
  `sudo setcap cap_ipc_lock=ep ./sherd`.
- Run on a system with `RLIMIT_MEMLOCK` raised to unlimited (see
  `/etc/security/limits.conf`) or as root.
- Run `sherd selftest` once after install and verify the SHA-256 of
  the binary out-of-band (`sherd hash`).
- Do **not** set `SHERD_ALLOW_NO_MLOCK` in release builds — the
  binary will refuse to start if the variable is present at all.
- For interactive use, prefer the passphrase prompt. For scripting,
  prefer `--pass-fd N` (file descriptor) over `--pass-file` or
  `SHERD_PASS`.

## Cryptographic primitives

| Component            | Primitive                                   | Standard / Reference    |
| -------------------- | ------------------------------------------- | ----------------------- |
| AEAD                 | AES-256-GCM                                 | NIST SP 800-38D         |
| KDF                  | Argon2id                                    | RFC 9106                |
| Key expansion        | HKDF-SHA256                                 | RFC 5869                |
| Key commitment       | HMAC-SHA256, truncated to 128 bits          | RFC 2104, RFC 4231      |
| Secret sharing       | Shamir over GF(2^8) with AES polynomial     | Shamir 1979             |
| Constant-time ops    | `subtle::ConstantTimeEq`                    |                         |

## Dependency audit

Sherd uses the following audited cryptographic crates:

- `aes-gcm` 0.10 — audited by NCC Group in 2020.
- `argon2` 0.5 — RustCrypto implementation.
- `sha2` 0.10 — RustCrypto implementation.
- `hkdf` 0.12, `hmac` 0.12 — RustCrypto implementations.
- `subtle` 2 — constant-time primitives.
- `zeroize` 1 — secure memory wiping.

The `cargo audit` tool can be run against `Cargo.lock` to check for
known advisories in the dependency tree.
