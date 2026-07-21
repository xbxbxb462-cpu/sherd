# Fortis

A paranoid-grade, single-binary offline encryption tool. Fortis encrypts
messages and files with **AES-256-GCM** using a key derived from your
passphrase via **Argon2id** and **HKDF-SHA256**. It supports
**plausible deniability** through an indistinguishable decoy slot,
**Shamir Secret Sharing** over GF(256), and a **paranoid mode** that
adds randomized padding to obscure plaintext length. All secret
buffers — including plaintext — are zeroized on drop, the entire
process address space is locked against swap via `mlockall`, and core
dumps are disabled.

> Fortis targets Unix platforms (Linux, macOS, BSD). Windows is not
> supported; use WSL2 if you must run on Windows.

## Features

- **Symmetric encryption** — AES-256-GCM per-chunk streaming AEAD with
  cryptographically independent per-chunk keys derived via HKDF-Expand.
- **Argon2id KDF** — three presets (`standard`, `paranoid`, `extreme`)
  with RFC 9106 §4 first-recommendation minimums enforced.
- **Key commitment** — HMAC-SHA256-truncated-128 verified before AEAD
  decryption to fail fast on a wrong passphrase without revealing which
  step failed.
- **Plausible deniability** — every file has two indistinguishable
  slots; supply a decoy passphrase to reveal a decoy plaintext under
  coercion. Sizes are randomized so an observer cannot tell which slot
  is "real".
- **Paranoid mode** — adds 1–4 blocks of randomized padding (on top of
  a non-block-aligned base) so the ciphertext size does not leak the
  plaintext length within a 4 KiB window.
- **Shamir Secret Sharing** — split a secret into N shares, any K of
  which reconstruct it. Shares are a fixed 4098 bytes regardless of
  secret length; threshold K and total N are not stored in any share,
  so an interceptor of a single share learns nothing about the
  quorum.
- **Uniform-timing decryption** — every chunk of every slot is
  processed regardless of whether the commit tag matched, closing the
  timing side-channel that would otherwise break plausible
  deniability.
- **Memory hygiene** — every secret buffer (passphrase, master key,
  PRK, commit key, per-chunk keys, padded plaintext, decrypted
  output, Shamir-reconstructed secret) is wrapped in `Zeroizing<…>`
  and wiped on drop. `mlockall(MCL_CURRENT | MCL_FUTURE)` locks the
  whole process against swap. `prctl(PR_SET_DUMPABLE, 0)` and
  `setrlimit(RLIMIT_CORE, 0)` disable core dumps.
- **Self-tests** — `fortis selftest` runs known-answer tests
  (Argon2id, HKDF-SHA256, HMAC-SHA256, AES-256-GCM) and round-trip /
  tamper-rejection tests before you trust the binary in a sensitive
  environment.

## Install

From source (requires Rust 1.74+):

```sh
git clone https://github.com/xbxbxb462-cpu/fortis.git
cd fortis
cargo install --path .
```

The binary is installed as `fortis` in your Cargo bin directory
(usually `~/.cargo/bin`).

For production use, grant the binary `CAP_IPC_LOCK` so it can lock
memory against swap without running as root:

```sh
sudo setcap cap_ipc_lock=ep $(which fortis)
```

Alternatively, raise the `memlock` rlimit in
`/etc/security/limits.conf`:

```
*  soft  memlock  unlimited
*  hard  memlock  unlimited
```

## Usage

### Encrypt a message (stdin → stdout, ASCII-armored)

```sh
echo "top secret" | fortis encrypt --kdf standard > message.frts.asc
```

You will be prompted for a passphrase (minimum 12 characters).

### Decrypt a message

```sh
fortis decrypt -i message.frts.asc -o plaintext.txt
```

### Encrypt a file (binary envelope, `.frts` extension)

```sh
fortis encrypt-file -i report.pdf
# → report.pdf.frts
```

### Decrypt a file

```sh
fortis decrypt-file -i report.pdf.frts -o report.pdf
```

### Encrypt with a decoy (plausible deniability)

```sh
fortis encrypt \
  --decoy decoy.txt \
  --decoy-pass-file decoy-pass.txt \
  --pass-file real-pass.txt \
  -i real.txt -o real.frts.asc
```

Under coercion, reveal `decoy-pass.txt` to "decrypt" `decoy.txt`. The
two slots are indistinguishable from ciphertext alone.

### Split a secret with Shamir (3-of-5)

```sh
fortis share-split -i master.key -k 3 -n 5 > shares.txt
```

Distribute each `=== FORTIS Share ===` block to a separate holder
over a separate channel.

### Reconstruct a secret

```sh
fortis share-combine -k 3 -s share1.txt -s share2.txt -s share3.txt -o master.key
```

The threshold `-k` is supplied by the caller; it is **not** stored in
any share.

### Passphrase sources

For non-interactive use, prefer file descriptors (never appear in
`/proc/PID/cmdline`):

```sh
fortis encrypt --pass-fd 3 3<passfile -i plain.txt -o cipher.frts
```

`--pass-file <path>` is also supported (the path appears in cmdline,
but the passphrase does not). The `FORTIS_PASS` environment variable
is supported as a CI/testing convenience **with a loud warning**: on
Linux it remains visible in `/proc/PID/environ` for the entire
process lifetime.

### Verify the binary

```sh
fortis hash
fortis selftest
```

`fortis hash` prints the SHA-256 of the running binary so you can
verify it out-of-band. `fortis selftest` runs the cryptographic
known-answer tests.

## Security notes

- **Threat model.** Fortis defends against ciphertext-only attackers,
  header tampering, commit-tag forgery, chunk compromise, nonce reuse,
  timing oracles, coercion (via the decoy layer), and memory forensics.
  It does **not** defend against a compromised OS or hardware
  implant — for that, use an air-gapped machine running Tails OS.
- **Memory locking is mandatory in release builds.** The
  `FORTIS_ALLOW_NO_MLOCK` environment variable is honored only in
  debug builds (with a loud warning). In release builds, the variable
  is rejected before `mlockall` runs.
- **KDF minimums are enforced.** Argon2id parameters are bounded to
  `[64 MiB, 256 MiB]` memory, `[3, 5]` iterations, and `4` parallelism
  lanes. Files encrypted with weaker parameters are rejected at
  decryption time.
- **No recursive encryption.** Re-encrypting an already-encrypted
  file is an operational footgun. `fortis encrypt` refuses input that
  begins with the `FRT7` magic unless you pass `--force`.
- **Constant-time operations.** Secret comparisons use
  `subtle::ConstantTimeEq`. GF(256) arithmetic (used by Shamir) is
  branchless.
- **Quantum adversaries.** AES-256 is Grover-resistant to 2^128.
- **Out of scope.** Cold boot attacks (reboot cold before/after
  sensitive operations), browser/OS 0-days, side channels beyond
  timing.

If you find a security issue, see [`SECURITY.md`](SECURITY.md) for
responsible disclosure.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Pull requests are welcome. Please run `cargo fmt`, `cargo clippy`, and
`cargo test` before submitting (the CI workflow does the same).
