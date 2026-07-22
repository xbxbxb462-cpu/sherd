# Sherd protocol specification

Version 1.0.0. This document describes the wire format and cryptographic
construction used by Sherd. It is intended for auditors and implementers.

## Scope

Sherd has two envelope versions:

- **v1**: passphrase-based. Argon2id derives a master key, which is
  expanded into per-slot PRK, commit key, and per-chunk AEAD keys.
- **v2**: recipient-based. A random file key is wrapped per recipient
  via X25519 + HKDF + AES-256-GCM. No Argon2id.

Both versions share the chunk encryption scheme: 1 MiB chunks, each with
an independent AES-256-GCM key derived via HKDF-Expand.

## v1: passphrase envelope

### Fixed header (16 bytes)

| Offset | Length | Field | Notes |
|-------:|-------:|-------|-------|
| 0 | 4 | magic | `SHR1` = `0x53 0x48 0x52 0x31` |
| 4 | 1 | version | `0x01` |
| 5 | 1 | flags | bit 0 = decoy present, bit 1 = paranoid padding |
| 6 | 1 | cipher_id | `0x01` = AES-256-GCM |
| 7 | 1 | kdf_id | `0x01` = Argon2id |
| 8 | 1 | commit_id | `0x01` = HMAC-SHA256-truncated-128 |
| 9 | 4 | kdf_mem_kib | u32 BE, Argon2id memory cost in KiB |
| 13 | 1 | kdf_iters | u8, Argon2id iterations |
| 14 | 1 | kdf_par | u8, Argon2id parallelism |
| 15 | 1 | slot_count | always 2 (real + decoy-or-dummy) |

### Slot header (68 bytes per slot)

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 32 | salt (random per slot) |
| 32 | 12 | base_iv (random per slot) |
| 44 | 16 | commit_tag (HMAC-SHA256-trunc-128) |
| 60 | 4 | chunk_count (u32 BE) |
| 64 | 4 | ct_total_len (u32 BE) |

### Slot ciphertext

The ciphertext follows the slot header. It is the output of
`encrypt_stream` (see below) over the padded plaintext.

### Key derivation

1. `master_key = Argon2id(passphrase, salt, m=kdf_mem_kib KiB, t=kdf_iters, p=kdf_par, len=32)`
2. `prk = HKDF-Extract(salt=salt, ikm=master_key)`
3. `commit_key = HKDF-Expand(prk, info="sherd-v1/commit", len=32)`
4. Per chunk `i` of `chunk_count`:
   `chunk_key[i] = HKDF-Expand(prk, info="sherd-v1/chunk/{i}/{chunk_count}", len=32)`

### Chunk encryption

Plaintext is padded (see Padding below) then split into 1 MiB chunks.
Each chunk is encrypted with AES-256-GCM using:

- Key: `chunk_key[i]` (per-chunk, derived above)
- Nonce: `base_iv` with the last 4 bytes XOR'd by `chunk_index` (u32 BE)
- AAD: `fixed_header || salt || base_iv || u32be(i) || u32be(chunk_count)`

The AAD binds the chunk to its position and to the file header, preventing
chunk reordering or cross-file splicing.

### Commit tag

```
commit_tag = HMAC-SHA256(commit_key,
    "SHERD-v1-commit-tag\x00"
    || fixed_header
    || salt
    || base_iv
    || u32be(chunk_count)
    || u32be(ct_total_len)
    || sha256(first_chunk_ciphertext)
)[0..15]
```

The first-chunk hash binds the tag to actual ciphertext content,
preventing the "invisible salamander" attack where an attacker swaps
ciphertexts between files with identical metadata.

### Padding

Plaintext is padded to obscure its length:

```
padded = u32be(plaintext_len) || plaintext || random_pad
```

Where `random_pad` has length `max(32, uniform(0, 8192))` bytes. In
paranoid mode, an additional 1-4 blocks of 4096 bytes are appended.

The 4-byte length prefix is authenticated as the first bytes of the
first chunk's plaintext (covered by the AEAD tag).

### Decryption flow

1. Parse fixed header, validate magic/version/cipher/kdf.
2. Validate KDF params are within `[KDF_MEM_MIN, KDF_MEM_MAX]` etc.
3. For each slot (always 2, uniform timing):
   a. Run Argon2id(passphrase, salt) -> master_key.
   b. Derive PRK and commit_key via HKDF.
   c. Verify commit_tag in constant time. If mismatch, mark slot bad
      but continue to the next slot.
   d. Run `decrypt_stream` over all chunks regardless of commit result.
   e. If commit matched AND all AEAD tags verified, return unpadded plaintext.
4. If no slot matched, return uniform error "bad".

The uniform-timing property: both slots are always processed, and all
chunks within each slot are always decrypted, regardless of early
failures. This prevents timing-based slot-existence oracles.

## v2: recipient envelope

### Header (26 bytes)

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 4 | magic `SHR1` |
| 4 | 1 | version `0x02` |
| 5 | 1 | recipient_count (1-255) |
| 6 | 12 | base_iv (random) |
| 18 | 4 | chunk_count (u32 BE) |
| 22 | 4 | ct_total_len (u32 BE) |

### Stanzas

For each recipient, an 80-byte stanza:

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 32 | ephemeral_pub (X25519 public key) |
| 32 | 48 | wrapped_key (AES-256-GCM ciphertext + tag) |

### File key wrapping

For each recipient `R`:

1. Generate ephemeral X25519 keypair `(e_priv, e_pub)`.
2. `shared = X25519(e_priv, R)`
3. `salt = e_pub || R` (64 bytes)
4. `wrap_key = HKDF-Expand(HKDF-Extract(salt, shared), "sherd-v1/wrap-key", 32)`
5. `wrap_nonce = HKDF-Expand(HKDF-Extract(salt, shared), "sherd-v1/wrap-nonce", 12)`
6. `wrapped_key = AES-256-GCM(wrap_key, wrap_nonce, AAD=e_pub, plaintext=file_key)`

The AAD `e_pub` binds the wrapped key to its stanza, preventing stanza
swapping.

### Chunk encryption

Same as v1, except:

- The file key (32 random bytes) serves directly as the HKDF PRK.
- `chunk_key[i] = HKDF-Expand(file_key, "sherd-v1/chunk/{i}/{count}", 32)`
- The AAD is the 22-byte header (magic + version + recipient_count +
  base_iv + chunk_count). `ct_total_len` is NOT in the AAD because it
  is unknown at encryption time.

### Decryption flow

1. Parse header, validate magic/version.
2. For each stanza, for each identity:
   - `shared = X25519(identity_priv, stanza.ephemeral_pub)`
   - Derive wrap_key, wrap_nonce.
   - Try `AES-256-GCM` decrypt. If tag verifies, file_key recovered.
3. If no identity matched any stanza, return "bad".
4. Run `decrypt_stream` with the file_key.

No uniform-timing requirement across stanzas (the number of stanzas is
public and small).

## ASCII armor

Either version may be wrapped in ASCII armor:

```
-----BEGIN SHERD MESSAGE-----
<base64, 64 chars per line>
-----END SHERD MESSAGE-----
```

Labels: `SHERD MESSAGE`, `SHERD FILE`, `SHERD SHARE`. The decoder
validates the label against an allowlist to prevent confusion between
message and share blocks.

## Shamir secret sharing

Shares are a fixed 4098 bytes:

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 1 | format version |
| 1 | 1 | share index x (1-255, never 0) |
| 2 | 4096 | payload (padded secret + length + SHA-256 digest) |

The payload layout:

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 4 | secret_len (u32 BE) |
| 4 | secret_len | secret |
| 4 + secret_len | 4096 - 4 - secret_len - 32 | zero padding |
| 4096 - 32 | 32 | SHA-256(payload[0..4096-32]) |

The SHA-256 digest detects tampering even when exactly K shares are
provided (where the Lagrange consistency check does not run). K and N
are NOT stored in any share. The caller supplies K at combine time.

GF(256) arithmetic uses the reduction polynomial 0x11B. `gmul` is
branchless (bitmask-based). Share indices x are drawn uniformly from
[1, 255] without replacement.

## Constants

| Constant | Value |
|----------|-------|
| MAGIC | `SHR1` (`0x53 0x48 0x52 0x31`) |
| VERSION (v1) | `0x01` |
| VERSION_RECIPIENT (v2) | `0x02` |
| CHUNK_SIZE | 1 MiB (`1 << 20`) |
| MAX_CHUNKS | 256 |
| MAX_CT | ~256 MiB |
| SALT_LEN | 32 |
| IV_LEN | 12 |
| TAG_LEN | 16 |
| COMMIT_TAG_LEN | 16 |
| MIN_PASS | 12 |
| KDF_MEM_MIN | 64 MiB (65536 KiB) |
| KDF_MEM_MAX | 256 MiB (262144 KiB) |
| KDF_ITERS_MIN | 3 |
| KDF_ITERS_MAX | 5 |
| KDF_PAR_MIN | 4 |
| KDF_PAR_MAX | 4 |
| FILE_KEY_LEN | 32 |
| X25519_PUB_LEN | 32 |
| WRAPPED_KEY_LEN | 48 (32 + 16) |
| MAX_RECIPIENTS | 255 |
| SHARE_FORMAT_VERSION | 1 |
| SHARE_PAYLOAD_LEN | 4096 |
| SHARE_LEN | 4098 |

## Domain separation strings

- `sherd-v1/commit` - HKDF info for commit key derivation
- `sherd-v1/chunk/{i}/{count}` - HKDF info for per-chunk key derivation
- `sherd-v1/wrap-key` - HKDF info for recipient file-key wrapping
- `sherd-v1/wrap-nonce` - HKDF info for recipient wrap nonce
- `SHERD-v1-commit-tag\x00` - HMAC domain separator for commit tag
- `SHERD-v1-first-chunk-hash\x00` - SHA-256 domain separator for first-chunk hash

## Test vectors

The selftest module includes known-answer tests for:

- Argon2id (params: 1 MiB, 3 iters, 1 lane; salt and password in source)
- AES-256-GCM NIST TC1 (empty plaintext) and TC14 (16-byte plaintext)
- HKDF-SHA256 RFC 5869 Test Case 1
- HMAC-SHA256 RFC 4231 Test Case 1

Run `sherd selftest` to verify the binary matches these vectors.
