# Contributing to sherd

Thanks for your interest in improving sherd. This project values
smallness and auditability above features — please read this page
before opening a pull request.

## Ground rules

1. **No new dependencies without prior discussion.** Every crate in
   the dependency tree is attack surface. Open an issue first and
   explain why the dependency is unavoidable.
2. **No configuration files, no network code, no telemetry.** These
   are hard constraints of the security model, not preferences.
3. **Every security-relevant change must extend `sherd selftest`.**
   If your change touches key derivation, encryption, padding, timing
   behavior, or memory handling, add a known-answer test or a
   round-trip/tamper test to `src/selftest.rs`.
4. **Wire-format changes require a version bump.** Never change the
   meaning of existing bytes in the v1/v2 formats. Add a new version
   and document it in `docs/protocol.md`.
5. **Secrets stay wrapped.** Any new buffer that can contain a
   passphrase, key, or plaintext must be `Zeroizing<…>`.

## Before you submit

Run the full local gate:

```sh
cargo fmt --all -- --check
cargo clippy --release --all-targets -- -D warnings
cargo test --bin sherd
cargo test --test mlock_bypass
cargo build --release
SHERD_ALLOW_NO_MLOCK=1 cargo run -- selftest   # debug build only
```

## Pull request checklist

- [ ] One logical change per PR.
- [ ] Commit messages explain *why*, not just *what*.
- [ ] New behavior is covered by tests.
- [ ] `CHANGELOG.md` updated under an `[Unreleased]` heading.
- [ ] No changes to `branding/` assets without maintainer approval.

## Reporting bugs

Use the issue templates. For anything security-sensitive, do **not**
open a public issue — follow the private process in
[`SECURITY.md`](SECURITY.md).

## Code style

- Rust 2021 edition, MSRV 1.74. Do not raise the MSRV casually.
- `rustfmt` defaults; no custom formatting.
- Prefer explicit, boring code over clever code. Reviewability is a
  security property.

## License of contributions

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in sherd shall be dual licensed under
MIT OR Apache-2.0, without any additional terms or conditions.
