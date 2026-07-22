# Sherd

A paranoid-grade, single-binary offline encryption tool. Sherd encrypts
messages and files with **AES-256-GCM** using a key derived from your
passphrase via **Argon2id** and **HKDF-SHA256**. It supports
**plausible deniability** through an indistinguishable decoy slot,
**Shamir Secret Sharing** over GF(256), a **paranoid mode** that
adds randomized padding to obscure plaintext length, and
**recipient-based (X25519) encryption** modeled on age. All secret
buffers — including plaintext — are zeroized on drop, the entire
process address space is locked against swap via `mlockall`, and core
dumps are disabled.

> Sherd targets Unix platforms (Linux, macOS, BSD). Windows is not
> supported; use WSL2 if you must run on Windows.

## Features

- **Symmetric encryption** — AES-256-GCM per-chunk streaming AEAD with
  cryptographically independent per-chunk keys derived via HKDF-Expand.
- **Recipient-based encryption (v2)** — encrypt to one or more X25519
  public keys (`sherd1…`) instead of a passphrase. Each recipient gets
  an independent stanza wrapping a random file key; any single
  recipient's identity (`sherd keygen`) decrypts. No Argon2id, so
  encrypt/decrypt are instant.
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
  output, Shamir-reconstructed secret, X25519 identity, file key) is
  wrapped in `Zeroizing<…>` and wiped on drop. `mlockall(MCL_CURRENT |
  MCL_FUTURE)` locks the whole process against swap.
  `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0)` disable
  core dumps.
- **Self-tests** — `sherd selftest` runs known-answer tests
  (Argon2id, HKDF-SHA256, HMAC-SHA256, AES-256-GCM) and round-trip /
  tamper-rejection tests before you trust the binary in a sensitive
  environment.

## Install

From source (requires Rust 1.74+):

```sh
git clone https://github.com/sherd/sherd.git
cd sherd
cargo install --path .
```

The binary is installed as `sherd` in your Cargo bin directory
(usually `~/.cargo/bin`).

For production use, grant the binary `CAP_IPC_LOCK` so it can lock
memory against swap without running as root:

```sh
sudo setcap cap_ipc_lock=ep $(which sherd)
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
echo "top secret" | sherd encrypt --kdf standard > message.shrd.asc
```

You will be prompted for a passphrase (minimum 12 characters).

### Decrypt a message

```sh
sherd decrypt -i message.shrd.asc -o plaintext.txt
```

### Encrypt a file (binary envelope, `.shrd` extension)

```sh
sherd encrypt-file -i report.pdf
# → report.pdf.shrd
```

### Decrypt a file

```sh
sherd decrypt-file -i report.pdf.shrd -o report.pdf
```

### Encrypt with a decoy (plausible deniability)

```sh
sherd encrypt \
  --decoy decoy.txt \
  --decoy-pass-file decoy-pass.txt \
  --pass-file real-pass.txt \
  -i real.txt -o real.shrd.asc
```

Under coercion, reveal `decoy-pass.txt` to "decrypt" `decoy.txt`. The
two slots are indistinguishable from ciphertext alone.

### Recipient-based encryption (X25519, age-style)

Generate an identity for each recipient. The identity file is secret;
the public key (printed to stderr and embedded as a `# public key:`
comment in the file) is what you share.

```sh
# Generate Alice's identity (written to alice.key with mode 0600).
sherd keygen -o alice.key
# → Public key: sherd1HVDKgCR/RXkQCN1iVr7mejRHHMdg/0nOKzOlP37OtUo=

# Print only the public key from an existing identity.
sherd keygen -y -i alice.key
# → sherd1HVDKgCR/RXkQCN1iVr7mejRHHMdg/0nOKzOlP37OtUo=
```

Encrypt to one or more recipients with `-r` (repeatable) or
`-R recipients.txt` (one `sherd1…` per line, `#` comments allowed).
No passphrase is prompted.

```sh
echo "for alice and bob" | sherd encrypt \
  -r sherd1HVDKgCR/RXkQCN1iVr7mejRHHMdg/0nOKzOlP37OtUo= \
  -r sherd1XqjsrbgszkY/XZ3LJku/PH1ZjyrqANYDQs05sP4aZG8= \
  -o recipients.shrd.asc
```

Decrypt with `-I identity.key` (repeatable to try multiple
identities). The CLI auto-detects v2 recipient envelopes from the
magic+version byte.

```sh
sherd decrypt -i recipients.shrd.asc -I alice.key -o alice.out
# or
sherd decrypt -i recipients.shrd.asc -I bob.key -o bob.out
```

Inspect either format without decrypting — `sherd inspect` reports
the version, mode (passphrase vs recipient), cipher, KDF params (v1)
or recipient count (v2), and per-slot / per-stanza metadata.

```sh
sherd inspect -i recipients.shrd.asc
```

### Comparison with age

Sherd's v2 recipient mode is inspired by [age](https://age-encryption.org)
and uses the same X25519 + HKDF-SHA256 + AEAD pattern for file-key
wrapping. Differences:

| Aspect | age | Sherd v2 |
|---|---|---|
| Recipient stanza | X25519 + HKDF + ChaCha20-Poly1305 | X25519 + HKDF-SHA256 + AES-256-GCM |
| Payload AEAD | ChaCha20-Poly1305 (single key) | AES-256-GCM with per-chunk HKDF-derived keys |
| Chunking | 64 KiB | 1 MiB (cap 256 MiB) |
| Padding | Random 0–65535 bytes via age_pad | Randomized length prefix + 32 B min pad + 0–8 KiB jitter + 1–4 × 4 KiB blocks |
| Identity format | `AGE-SECRET-KEY-1…` | `SHERD-SECRET-KEY-1…` |
| Recipient format | `age1…` (bech32) | `sherd1…` (base64) |
| Passphrase mode | scrypt | Argon2id + HMAC commit + decoy slot (plausible deniability) |
| Decoy / deniability | No | Yes (v1) |
| Shamir secret sharing | No | Yes |
| Memory hygiene | Best-effort | `mlockall` + per-buffer mlock + zeroize-on-drop + core-dump disabled |

Use Sherd v2 when you want age-style recipient encryption with the
option to fall back to Argon2id + plausible deniability for the same
payload, plus Shamir sharing and stronger memory hygiene. Use age when
you want a widely-deployed, audited, single-purpose tool.

### Split a secret with Shamir (3-of-5)

```sh
sherd share-split -i master.key -k 3 -n 5 > shares.txt
```

Distribute each `=== SHERD Share ===` block to a separate holder
over a separate channel.

### Reconstruct a secret

```sh
sherd share-combine -k 3 -s share1.txt -s share2.txt -s share3.txt -o master.key
```

The threshold `-k` is supplied by the caller; it is **not** stored in
any share.

### Passphrase sources

For non-interactive use, prefer file descriptors (never appear in
`/proc/PID/cmdline`):

```sh
sherd encrypt --pass-fd 3 3<passfile -i plain.txt -o cipher.shrd
```

`--pass-file <path>` is also supported (the path appears in cmdline,
but the passphrase does not). The `SHERD_PASS` environment variable
is supported as a CI/testing convenience **with a loud warning**: on
Linux it remains visible in `/proc/PID/environ` for the entire
process lifetime.

### Verify the binary

```sh
sherd hash
sherd selftest
```

`sherd hash` prints the SHA-256 of the running binary so you can
verify it out-of-band. `sherd selftest` runs the cryptographic
known-answer tests.

## Security notes

- **Threat model.** Sherd defends against ciphertext-only attackers,
  header tampering, commit-tag forgery, chunk compromise, nonce reuse,
  timing oracles, coercion (via the decoy layer), and memory forensics.
  It does **not** defend against a compromised OS or hardware
  implant — for that, use an air-gapped machine running Tails OS.
- **Memory locking is mandatory in release builds.** The
  `SHERD_ALLOW_NO_MLOCK` environment variable is honored only in
  debug builds (with a loud warning). In release builds, the variable
  is rejected before `mlockall` runs.
- **KDF minimums are enforced.** Argon2id parameters are bounded to
  `[64 MiB, 256 MiB]` memory, `[3, 5]` iterations, and `4` parallelism
  lanes. Files encrypted with weaker parameters are rejected at
  decryption time.
- **No recursive encryption.** Re-encrypting an already-encrypted
  file is an operational footgun. `sherd encrypt` refuses input that
  begins with the `SHR1` magic unless you pass `--force`.
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
