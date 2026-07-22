# Sherd security policy

## Reporting a vulnerability

Do NOT open a public GitHub issue for security problems.

Report vulnerabilities through GitHub's private vulnerability reporting:

1. Go to https://github.com/xbxbxb462-cpu/sherd/security/advisories/new
2. Fill in the template with:
   - Description of the issue
   - Steps to reproduce
   - Affected versions
   - Suggested fix (if any)

You will receive an acknowledgment within 72 hours. If the report is
accepted, a fix and advisory will be published under a CVE if the
severity warrants it.

## Threat model

Sherd defends against:

- Ciphertext-only attackers
- Header tampering and commit-tag forgery
- Chunk compromise (per-chunk keys)
- Nonce reuse (structurally impossible)
- Timing oracles (uniform-timing decrypt)
- Length oracles (randomized padding)
- Coercion (plausible deniability via decoy slot)
- Memory forensics (mlockall, zeroize-on-drop, core-dump disabled)
- Recursive-encryption footgun
- Path traversal and file clobberbing

Sherd does NOT defend against:

- A compromised OS or hardware implant
- Cold boot attacks
- Browser or OS zero-days
- Side channels beyond timing

For high-stakes operations, use an air-gapped machine running Tails.

## Supported versions

Only the latest release line receives security fixes.

## Disclosure timeline

- Day 0: Private report received
- Day 1-3: Acknowledgment and triage
- Day 3-30: Fix development, private branch
- Day 30: Coordinated public disclosure with release
- CVE requested if CVSS >= 4.0
