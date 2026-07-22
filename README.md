<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="branding/logo-dark.png">
    <img src="branding/logo.png" alt="sherd logo" width="140" />
  </picture>
</p>

<h1 align="center">sherd</h1>
<p align="center">
  <b>Offline, single-binary encryption for adversarial conditions.</b>
</p>

<p align="center">
  <a href="https://github.com/xbxbxb462-cpu/sherd/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/xbxbxb462-cpu/sherd/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/xbxbxb462-cpu/sherd/releases"><img alt="Release" src="https://img.shields.io/github/v/release/xbxbxb462-cpu/sherd?display_name=tag&sort=semver"></a>
  <a href="LICENSE-MIT"><img alt="License" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg"></a>
  <img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.74-orange.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20BSD-lightgrey.svg">
</p>

---

sherd is a command-line encryption tool built around one assumption: the
adversary is competent. It encrypts messages and files with
**AES-256-GCM** using keys derived through **Argon2id** and
**HKDF-SHA256**, or with **X25519 recipient keys** for asymmetric
exchange. It supports **plausible deniability** via an indistinguishable
decoy slot, **Shamir Secret Sharing** over GF(256), and a **paranoid
mode** that obscures plaintext length.

Every secret buffer is wrapped in `Zeroizing<…>` and wiped on drop.
The whole process address space is locked against swap with
`mlockall(MCL_CURRENT | MCL_FUTURE)`. Core dumps are disabled. Decryption
runs in uniform time across slots and chunks. There is no configuration
file, no network, no telemetry, no plugin loader.

> **Platform support.** Linux, macOS, BSD. Not Windows. On Windows use
> WSL2 - the security model depends on `mlockall`, `termios`, and Unix
> file permissions, none of which have trustworthy Win32 equivalents.

---

## Why sherd?

Most encryption tools optimize for convenience. sherd optimizes for the
case where the adversary is competent and motivated.

- **Memory is locked, not just zeroized.** `mlockall(MCL_CURRENT |
  MCL_FUTURE)` prevents the kernel from swapping any page of the process
  to disk. Core dumps are disabled via `setrlimit(RLIMIT_CORE, 0)` and
  `prctl(PR_SET_DUMPABLE, 0)`. A cold-reboot attacker finds nothing.
- **Plausible deniability is real, not theatrical.** Every
  passphrase-encrypted file has two indistinguishable slots. Under
  coercion you reveal the decoy passphrase; the adversary cannot prove
  a second slot exists. Both slots are valid AES-256-GCM ciphertexts
  with valid commit tags, padded to the same randomized length.
- **Decryption is uniform-timing.** Every chunk of every slot is
  processed regardless of whether the commit tag matched. A wrong
  passphrase takes the same wall-clock time as a correct one. This
  closes the timing oracle that would otherwise break plausible
  deniability.
- **Shamir shares leak nothing.** Shares are a fixed 4098 bytes
  regardless of secret length. The threshold K and total N are not
  stored in any share. An interceptor of one share cannot learn the
  quorum or the secret size.
- **No configuration surface.** No config file, no plugin loader, no
  network. A hostile environment variable cannot downgrade the KDF or
  disable padding. Every security-relevant parameter is hardcoded or
  specified explicitly on the command line.
- **Recipient mode for asymmetric exchange.** Encrypt to X25519 public
  keys (`sherd1...`). No passphrase, no Argon2id, instant encrypt and
  decrypt. Each recipient gets an independent stanza; any single
  recipient's identity decrypts.

For the full protocol specification, see [`docs/protocol.md`](docs/protocol.md).

---

## Table of contents

- [Quickstart](#quickstart)
- [Install](#install)
- [Usage](#usage)
  - [Passphrase encryption](#passphrase-encryption)
  - [Recipient encryption (X25519)](#recipient-encryption-x25519)
  - [Plausible deniability](#plausible-deniability)
  - [Shamir secret sharing](#shamir-secret-sharing)
  - [Inspect without decrypting](#inspect-without-decrypting)
- [Security model](#security-model)
- [File format](#file-format)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Quickstart

```sh
# from source (requires Rust 1.74+)
git clone https://github.com/xbxbxb462-cpu/sherd.git
cd sherd
cargo install --path .

# allow memory locking without root
sudo setcap cap_ipc_lock=ep "$(which sherd)"

# encrypt a message to a passphrase (stdin → stdout)
echo "top secret" | sherd encrypt > msg.shrd.asc

# decrypt
sherd decrypt -i msg.shrd.asc
```

For recipient-based encryption (no passphrase, just public keys):

```sh
sherd keygen -o alice.key        # writes SHERD-SECRET-KEY-1... (mode 0600)
sherd keygen -y -i alice.key     # prints: sherd1...

echo "for alice" | sherd encrypt -r sherd1... > for-alice.shrd.asc
sherd decrypt -I alice.key -i for-alice.shrd.asc
```

## Install

### Prebuilt binaries (recommended)

Download the archive for your platform from the
[latest release](https://github.com/xbxbxb462-cpu/sherd/releases/latest),
verify its checksum against the published `SHA256SUMS`, then install:

```sh
# example: Linux x86_64
curl -LO https://github.com/xbxbxb462-cpu/sherd/releases/latest/download/sherd-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/xbxbxb462-cpu/sherd/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf sherd-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 755 sherd-x86_64-unknown-linux-gnu /usr/local/bin/sherd
```

Or with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall sherd
```

### From source

Requires Rust 1.74 or newer.

```sh
git clone https://github.com/xbxbxb462-cpu/sherd.git
cd sherd
cargo install --path .
```

The binary lands in `~/.cargo/bin/sherd`.

### Memory locking

sherd refuses to run in release mode unless it can lock its address
space against swap. Pick one:

```sh
# option A: grant the capability once
sudo setcap cap_ipc_lock=ep "$(which sherd)"

# option B: raise the memlock rlimit for all users
echo '*  soft  memlock  unlimited' | sudo tee -a /etc/security/limits.conf
echo '*  hard  memlock  unlimited' | sudo tee -a /etc/security/limits.conf
# log out and back in
```

In debug builds, `SHERD_ALLOW_NO_MLOCK=1` is honored with a loud warning.
In release builds the variable is rejected.

### Verify the binary

```sh
sherd hash       # prints the SHA-256 of the running binary
sherd selftest   # runs Argon2id / HKDF / HMAC / AES-GCM known-answer tests
```

## Usage

sherd has nine subcommands. Run `sherd --help` for the full list, or
`sherd <command> --help` for details.

### Passphrase encryption

Encrypt to a passphrase. The passphrase is stretched through Argon2id
(memory 64–256 MiB, iterations 3–5, parallelism 4) and bound into a
commit tag verified before any plaintext is released.

```sh
# stdin → stdout, ASCII-armored
echo "top secret" | sherd encrypt --kdf standard > msg.shrd.asc

# file → file, binary
sherd encrypt-file -i report.pdf
# writes report.pdf.shrd (mode 0600)
```

Decrypt:

```sh
sherd decrypt -i msg.shrd.asc
sherd decrypt-file -i report.pdf.shrd -o report.pdf
```

KDF presets:

| preset | memory | iterations | lanes | use case |
|--------|-------:|-----------:|------:|----------|
| `standard` | 64 MiB | 3 | 4 | default, interactive |
| `paranoid` | 128 MiB | 4 | 4 | sensitive, adds length-jitter padding |
| `extreme` | 256 MiB | 5 | 4 | offline master keys |

Passphrase sources (in order of safety):

```sh
# file descriptor (never appears in /proc/PID/cmdline)
sherd encrypt --pass-fd 3 3<passfile -i plain.txt -o cipher.shrd

# file path (path appears in cmdline, passphrase does not)
sherd encrypt --pass-file passfile -i plain.txt -o cipher.shrd

# env var (CI convenience; visible in /proc/PID/environ on Linux)
SHERD_PASS=... sherd encrypt -i plain.txt -o cipher.shrd
```

### Recipient encryption (X25519)

Encrypt to one or more X25519 public keys. No passphrase, no Argon2id,
instant encrypt and decrypt. The file key is random per file; each
recipient gets an independent stanza wrapping that key with an ephemeral
X25519 + HKDF-SHA256 + AES-256-GCM.

```sh
# generate an identity (private key + public key comment)
sherd keygen -o alice.key
# Public key: sherd1HVDKgCR/RXkQCN1iVr7mejRHHMdg/0nOKzOlP37OtUo=

# print only the public key from an existing identity
sherd keygen -y -i alice.key

# encrypt to one recipient
echo "for alice" | sherd encrypt -r sherd1HVDKgCR... > for-alice.shrd.asc

# encrypt to multiple recipients (everyone can decrypt)
echo "for both" | sherd encrypt \
  -r sherd1HVDKgCR/RXkQCN1iVr7mejRHHMdg/0nOKzOlP37OtUo= \
  -r sherd1XqjsrbgszkY/XZ3LJku/PH1ZjyrqANYDQs05sP4aZG8= \
  > for-both.shrd.asc

# encrypt to recipients listed in a file (one per line, # comments OK)
echo "for the team" | sherd encrypt -R recipients.txt > team.shrd

# decrypt with any matching identity
sherd decrypt -I alice.key -i for-both.shrd.asc
```

Identity files contain one or more `SHERD-SECRET-KEY-1...` lines, one
per line. `#` lines are comments. You can pass `-I` multiple times to
try several identities.

### Plausible deniability

Every passphrase-encrypted file has two indistinguishable slots. If you
supply a decoy passphrase and decoy plaintext, the second slot carries
the decoy; under coercion you reveal the decoy passphrase and the
adversary cannot prove a second slot exists.

```sh
sherd encrypt \
  --decoy decoy.txt \
  --decoy-pass-file decoy-pass.txt \
  --pass-file real-pass.txt \
  -i real.txt -o real.shrd.asc
```

Both slots are padded to the same randomized target length, so the file
size does not reveal which slot is larger.

### Shamir secret sharing

Split a secret into N shares, any K of which reconstruct it. Shares are
a fixed 4098 bytes regardless of secret length. The threshold K and
total N are **not** stored in any share — an interceptor of one share
learns nothing about the quorum.

```sh
# 3-of-5 split
sherd share-split -i master.key -k 3 -n 5 > shares.txt

# distribute each === SHERD Share === block over a separate channel

# reconstruct with any 3
sherd share-combine -k 3 -s share1.txt -s share2.txt -s share3.txt -o master.key
```

The threshold `-k` is supplied by the caller at combine time. It is not
recovered from the shares.

### Inspect without decrypting

`sherd inspect` reports file metadata without running the KDF or
touching ciphertext:

```sh
sherd inspect -i file.shrd
```

Output includes: format version, mode (passphrase vs recipient), cipher,
KDF params (v1) or recipient count (v2), chunk count, ciphertext size,
per-slot / per-stanza sizes. Useful for triage before decryption.

### Shell completion

Generate completion scripts for bash, zsh, fish, or PowerShell:

```sh
# bash (add to ~/.bashrc)
sherd completion bash > ~/.local/share/bash-completion/completions/sherd

# zsh (add to ~/.zshrc)
sherd completion zsh > "${fpath[1]}/_sherd"

# fish
sherd completion fish > ~/.config/fish/completions/sherd.fish

# powershell
sherd completion powershell | Out-String | Invoke-Expression
```

## Security model

### What sherd defends against

- **Ciphertext-only attackers.** AES-256-GCM with per-chunk HKDF-derived
  keys; nonce reuse is structurally impossible (random `base_iv` per
  slot, chunk index XOR'd into the nonce).
- **Header tampering.** The fixed header is bound into the commit tag
  (HMAC-SHA256-truncated-128) and into every chunk's AEAD AAD.
- **Commit-tag forgery.** The commit tag also binds a SHA-256 of the
  first chunk's ciphertext, preventing the "invisible salamander"
  ciphertext-swap attack.
- **Chunk compromise.** Each chunk has its own HKDF-derived key; a
  broken chunk does not reveal neighboring chunks.
- **Timing oracles.** Every chunk of every slot is processed regardless
  of whether the commit tag matched. Wrong passphrases take the same
  wall-clock time as correct ones (modulo Argon2id variance).
- **Length oracles.** Output size is randomized: 4-byte length prefix
  (authenticated) + minimum 32-byte pad + uniform 0–8 KiB jitter +
  paranoid mode adds 1–4 × 4 KiB blocks. Decoy slots are padded to the
  same target length.
- **Coercion.** The decoy slot is indistinguishable from the real slot.
  Both are valid AES-256-GCM ciphertexts with valid commit tags.
- **Memory forensics.** `mlockall(MCL_CURRENT | MCL_FUTURE)` locks the
  whole address space. `prctl(PR_SET_DUMPABLE, 0)` and
  `setrlimit(RLIMIT_CORE, 0)` disable core dumps. Every secret buffer
  (passphrase, master key, PRK, commit key, per-chunk keys, padded
  plaintext, decrypted output, Shamir-reconstructed secret, X25519
  identity, file key) is wrapped in `Zeroizing<…>` and wiped on drop.
- **Recursive-encryption footgun.** `sherd encrypt` refuses input that
  begins with the `SHR1` magic unless you pass `--force`.
- **Path traversal.** Embedded filenames in `decrypt-file` are
  sanitized; output paths are checked against the input path.
- **File clobbering.** `decrypt-file` refuses to overwrite an existing
  output file unless `--force` is given.
- **TOCTOU on input.** Files are opened once, `fstat`'d on the fd, and
  read from the same fd.

### What sherd does not defend against

- **A compromised OS or hardware implant.** If the kernel is hostile,
  `mlockall` is a suggestion. Use an air-gapped machine running Tails
  for high-stakes operations.
- **Cold boot attacks.** Reboot cold before and after sensitive
  operations if this threat is in scope.
- **Browser or OS zero-days.** Out of scope.
- **Side channels beyond timing.** Power, EM, acoustic — out of scope.

### Quantum adversaries

AES-256 is Grover-resistant to 2^128 work. X25519 is not (quantum
adversary breaks ECDH). If quantum adversaries are in scope, use the
passphrase mode with a high-entropy passphrase and `--kdf extreme`.

For the full disclosure policy, see [`SECURITY.md`](SECURITY.md).

## File format

### v1 — passphrase

```
+-------------------+
| magic "SHR1"      |  4 bytes
| version = 1       |  1 byte
| flags             |  1 byte  (FLAG_PARANOID always set)
| cipher_id         |  1 byte  (AES-256-GCM)
| kdf_id            |  1 byte  (Argon2id)
| commit_id         |  1 byte  (HMAC-SHA256-trunc-128)
| kdf_mem_kib       |  4 bytes (u32 BE)
| kdf_iters         |  1 byte  (u8)
| kdf_par           |  1 byte  (u8)
| slot_count        |  1 byte  (always 2)
+-------------------+
| slot 0            |  salt[16] + iv[12] + commit_tag[16]
|                   |  + chunk_count[4] + ct_total_len[4]
|                   |  + ciphertext[ct_total_len]
+-------------------+
| slot 1            |  (same layout; real or decoy)
+-------------------+
```

### v2 — recipient

```
+-------------------+
| magic "SHR1"      |  4 bytes
| version = 2       |  1 byte
| recipient_count   |  1 byte  (1..=255)
| base_iv           |  12 bytes
| chunk_count       |  4 bytes (u32 BE)
| ct_total_len      |  4 bytes (u32 BE)
+-------------------+
| stanza 0          |  ephemeral_pub[32] + wrapped_key[48]
| ...               |
| stanza N-1        |  ephemeral_pub[32] + wrapped_key[48]
+-------------------+
| ciphertext        |  ct_total_len bytes
+-------------------+
```

Chunk size is 1 MiB; maximum ciphertext is 256 MiB (256 chunks). Each
chunk has an independent AES-256-GCM key derived via
`HKDF-Expand(file_key, "sherd-v1/chunk/{i}/{count}")`.

ASCII armor wraps either format as:

```
-----BEGIN SHERD MESSAGE-----
<base64, 64 chars per line>
-----END SHERD MESSAGE-----
```

## FAQ

**Why is memory locking mandatory?**

If the OS can swap your passphrase or master key to disk, it can be
recovered later by anyone with physical access. `mlockall` prevents
that. If you cannot grant `CAP_IPC_LOCK` or raise `RLIMIT_MEMLOCK`,
sherd refuses to run in release mode.

**Why is there no config file?**

Configuration files are an attack surface. A hostile config could
downgrade the KDF preset, disable padding, or change the cipher. Every
security-relevant parameter is either hardcoded (cipher, KDF algorithm)
or specified explicitly on the command line (KDF preset, decoy).

**Why two slots in passphrase mode?**

The second slot is the plausible-deniability channel. If you don't
supply a decoy, the second slot is a structurally identical dummy with
random ciphertext — an observer cannot tell whether a decoy exists.

**Can I encrypt to both a passphrase and a recipient?**

Not in one file. Use two files: one passphrase-encrypted, one
recipient-encrypted, with the same plaintext. Or encrypt the plaintext
to a recipient, then encrypt the recipient's identity file with a
passphrase.

**What happens if I lose my identity file?**

The file key is wrapped to your X25519 public key. Without the private
key, it cannot be recovered. There is no escrow, no recovery, no back door. Split the identity file with `sherd share-split` and distribute the shares if you need a recovery path.

**Has sherd been audited?**

Not yet. The design follows well-studied constructions (AES-256-GCM,
Argon2id per RFC 9106, HKDF per RFC 5869) implemented via the audited
RustCrypto crates, and every claim in the security model is covered by
`sherd selftest` known-answer tests. An independent third-party audit
is on the roadmap; until then, treat sherd as well-designed but
unaudited software and act accordingly for life-critical use.

## Contributing

Contributions are welcome. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request,
and note the rules that keep sherd small and auditable:

- No new dependencies without prior discussion in an issue.
- No configuration files, no network code, no telemetry — ever.
- Every security-relevant change must extend `sherd selftest`.
- `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` must pass.

Security issues must **not** be reported in public issues — see
[`SECURITY.md`](SECURITY.md) for the private disclosure process.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in sherd by you,
as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
