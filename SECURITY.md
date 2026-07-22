# Security Policy

## Supported versions

Only the latest released version of sherd receives security updates.
If you are running an older version, upgrade before reporting an
issue.

## Reporting a vulnerability

**Please do not open public GitHub issues for security-related
problems.**

Instead, report vulnerabilities privately:

1. Open a new **GitHub Security Advisory** via the
   "Security" → "Advisories" → "Report a vulnerability" tab on the
   sherd repository, **or**
2. Email the maintainers directly at `security@sherd.invalid` (PGP
   key fingerprint published in the repository root as
   `SECURITY-PGP.asc` if available).

Please include the following in your report, where applicable:

- A description of the issue and its impact.
- The exact sherd version (`sherd --version`) and how it was built
  (`cargo build --release` flags, target platform, Rust toolchain
  version).
- A minimal reproducer (commands, input files, expected vs. actual
  behavior).
- Any mitiga