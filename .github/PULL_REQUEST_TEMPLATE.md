## Pull request checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --release --all-targets -- -D warnings` passes
- [ ] `cargo test --bin sherd` passes
- [ ] `cargo test --test mlock_bypass` passes
- [ ] No new dependency added without justification
- [ ] No secret material (keys, passphrases, KAT values) in commit messages or diffs
- [ ] If the wire format changed: version bump documented in CHANGELOG.md

## Description

What does this PR change and why?

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (format change, CLI flag removal, etc.)
- [ ] Documentation only
- [ ] Refactor (no behavior change)

## Security implications

If this touches crypto, memory handling, or the wire format, explain the
security implications. If none, write "None".

## Test plan

How did you verify this works? Reference any new tests added.
