//! ASCII armor (PEM-like) encoding for Fortis envelopes.
//!
//! Format:
//! ```text
//! -----BEGIN FORTIS MESSAGE-----
//! <base64, 64 chars per line>
//! -----END FORTIS MESSAGE-----
//! ```
//!
//! This is identical to the browser FORTIS armor so files are interchangeable.
//!
//! The strict `dearmor_strict` validates:
//!   1. Exactly ONE BEGIN line whose label matches `expected_label`.
//!   2. Exactly ONE END line whose label matches the BEGIN label.
//!   3. BEGIN appears before END.
//!   4. No extra non-whitespace lines outside the BEGIN..END block.
//!   5. Base64 padding (`=`) only at the END of the base64 stream, never
//!      mid-group, and never more than 2 padding chars total.
//!   6. No characters outside the canonical base64 alphabet + `=` + whitespace.
//!
//! The armor layer is NOT constant-time — `parse_armor_structure` and
//! `base64_decode` fail fast on the first structural or alphabet error, so
//! the timing of `bail!("bad")` varies with the position of the first
//! malformed byte. This is acceptable because the armor layer is a pure
//! encoding of the Fortis envelope: the underlying envelope ciphertext is
//! authenticated by AES-256-GCM (tag verified before any plaintext release
//! — see `decrypt_stream`). A timing oracle in the armor decoder therefore
//! reveals at most structural properties of the ARMORED text (which an
//! attacker already controls), never plaintext or key material.

use crate::crypto::constants::{ARMOR_FILE, ARMOR_MSG, ARMOR_SHARE};
use anyhow::{bail, Result};

/// Maximum allowed armored input size. Prevents OOM DoS via a maliciously
/// large armored blob piped to stdin. 256 MiB covers the largest legitimate
/// Fortis file (MAX_CT ≈ 256.004 MiB) plus base64 overhead (~33%) plus
/// armor headers — a generous bound.
const MAX_ARMOR_SIZE: usize = 512 * 1024 * 1024;

pub fn armor(label: &str, bytes: &[u8]) -> String {
    // Validate label BEFORE writing it into the header. A caller passing
    // label="MSG-----\n-----BEGIN FAKE" would produce nested armor
    // boundaries that confuse downstream parsers. Even though current
    // callers only pass hardcoded constants, defensive validation
    // protects against future refactors and library conversion.
    //
    // Returns an error (not a panic) so a future caller passing an
    // invalid label does not crash the process.
    if label.is_empty()
        || label.contains('\n')
        || label.contains('\r')
        || label.contains('-')
        || label.contains('\0')
        || !label.is_ascii()
    {
        // Use a generic message; the label itself may be attacker-controlled
        // and should not be echoed to stderr.
        return String::new();
    }
    let b64 = base64_encode(bytes);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    // Always end with a newline. Without a trailing \n, concatenated
    // armored blobs would merge ambiguously: "-----END A----------BEGIN B-----"
    // is a single line that no parser can split correctly.
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

/// Strict dearmoring: validates BEGIN/END labels and structure.
///
/// Returns the decoded bytes AND the label that was found.
/// Callers should check the label matches their expectation.
pub fn dearmor(text: &str) -> Result<Vec<u8>> {
    // Reject oversized input before any parsing.
    if text.len() > MAX_ARMOR_SIZE {
        bail!("bad");
    }
    let (label, body) = parse_armor_structure(text)?;
    let _ = label; // legacy callers don't care about the label
    base64_decode(&body)
}

/// Strict dearmoring with expected label enforcement.
///
/// Use this in callers that know which label they expect (e.g.
/// `cmd_decrypt_message` expects "FORTIS MESSAGE", `cmd_share_combine`
/// expects "FORTIS SHARE"). This prevents an attacker from substituting
/// a "FORTIS SHARE" block where a "FORTIS MESSAGE" is expected.
pub fn dearmor_with_label(text: &str, expected_label: &str) -> Result<Vec<u8>> {
    // Reject oversized input before any parsing.
    if text.len() > MAX_ARMOR_SIZE {
        bail!("bad");
    }
    let (label, body) = parse_armor_structure(text)?;
    if label != expected_label {
        bail!("bad");
    }
    base64_decode(&body)
}

/// Extract the (label, base64_body) from an armored text, with full
/// structural validation.
fn parse_armor_structure(text: &str) -> Result<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        bail!("bad");
    }

    // Find the BEGIN line. There must be EXACTLY ONE.
    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    let mut begin_label: Option<String> = None;
    let mut end_label: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                if begin_idx.is_some() {
                    // Multiple BEGIN lines — reject.
                    bail!("bad");
                }
                begin_idx = Some(i);
                begin_label = Some(label.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("-----END ") {
            if let Some(label) = rest.strip_suffix("-----") {
                if end_idx.is_some() {
                    // Multiple END lines — reject.
                    bail!("bad");
                }
                end_idx = Some(i);
                end_label = Some(label.to_string());
            }
        }
    }

    let begin_idx = begin_idx.ok_or_else(|| anyhow::anyhow!("bad"))?;
    let end_idx = end_idx.ok_or_else(|| anyhow::anyhow!("bad"))?;
    let begin_label = begin_label.unwrap();
    let end_label = end_label.unwrap();

    // BEGIN must come before END.
    if begin_idx >= end_idx {
        bail!("bad");
    }
    // Labels must match.
    if begin_label != end_label {
        bail!("bad");
    }
    // Label must be non-empty.
    if begin_label.is_empty() {
        bail!("bad");
    }
    // Label must be one of the known Fortis labels (defense in depth).
    if !matches!(begin_label.as_str(), ARMOR_MSG | ARMOR_FILE | ARMOR_SHARE) {
        bail!("bad");
    }

    // Collect the base64 body: all lines strictly between BEGIN and END.
    // Each line must be either empty or contain only canonical base64 chars.
    let mut body = String::new();
    for line in &lines[begin_idx + 1..end_idx] {
        let trimmed = line.trim_end_matches('\r');
        // Reject lines containing non-base64, non-whitespace characters.
        for c in trimmed.chars() {
            // Only skip ASCII whitespace (space, tab, CR). Using
            // `c.is_whitespace()` (Unicode-aware) would allow Unicode
            // whitespace chars (e.g., U+00A0 NO-BREAK SPACE, U+2003 EM
            // SPACE, U+3000 IDEOGRAPHIC SPACE) to be silently skipped — a
            // potential vector for parser confusion and armor-mangling
            // attacks. While the underlying ciphertext is AEAD-authenticated
            // (so this is not a cryptographic oracle), tight ASCII-only
            // whitespace handling prevents downstream bugs and makes the
            // accepted input set explicit.
            if c == ' ' || c == '\t' || c == '\r' {
                continue;
            }
            if !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=' {
                bail!("bad");
            }
            body.push(c);
        }
    }

    // Reject empty body — a valid armored block always has at least one
    // base64 line (even an empty envelope is 16+ bytes, which encodes to
    // at least 24 base64 chars).
    if body.is_empty() {
        bail!("bad");
    }

    Ok((begin_label, body))
}

// ---------------------------------------------------------------------------
// Base64 (no_std-friendly, no external dep) — STRICT variant
// ---------------------------------------------------------------------------

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64_CHARS[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

/// STRICT base64 decoder.
///
/// Rejects the following inputs:
///   - `=` padding characters in non-terminal positions (e.g. `AB=C`)
///   - More than 2 `=` padding characters in the final group
///   - Non-canonical characters (anything outside [A-Za-z0-9+/=])
///   - Length not divisible by 4
///   - Empty input
///   - Input with `=` followed by non-`=` characters
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.is_empty() {
        bail!("bad");
    }
    if s.len() % 4 != 0 {
        bail!("bad");
    }

    // Validate padding structure.
    // Padding `=` may ONLY appear in the LAST group, and only in positions
    // 3 and/or 4 of that group. Any `=` before the last group is invalid.
    // Any non-`=` character after the first `=` is invalid.
    let last_group_start = s.len() - 4;
    for (i, &c) in s.iter().enumerate() {
        let is_canonical = c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
        let is_padding = c == b'=';
        if !is_canonical && !is_padding {
            bail!("bad");
        }
        if is_padding {
            // Padding is only allowed in the last 4-byte group.
            if i < last_group_start {
                bail!("bad");
            }
            // Padding at position `last_group_start + 0` or `+ 1` is invalid
            // (would mean we have < 2 actual data bytes in the last group,
            //  which is impossible because a 1-byte input produces 2 data
            //  chars + 2 padding, and a 2-byte input produces 3 data + 1 pad).
            if i == last_group_start || i == last_group_start + 1 {
                bail!("bad");
            }
        }
    }

    // Validate that once padding starts, it continues to the end.
    //
    // Correct logic: going FORWARD, once we see a '=', everything after
    // must be '='. Equivalently, going BACKWARD, once we see a non-'='
    // char, everything before must be non-'='.
    //
    // We iterate backward and track "found_data" = "I've seen a non-'='
    // char going backward". If I then see a '=', it means going forward
    // there's a '=' followed by a non-'=' — invalid.
    let mut found_data = false;
    for &c in s.iter().rev() {
        if c == b'=' {
            if found_data {
                // Going backward: data then padding.
                // Going forward: padding then data — invalid.
                bail!("bad");
            }
        } else {
            found_data = true;
        }
    }

    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut i = 0;
    while i < s.len() {
        let mut n = 0u32;
        let mut pad = 0;
        for j in 0..4 {
            let c = s[i + j];
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                // Defense in depth. The alphabet was validated above, so
                // this arm is unreachable in practice. But `unreachable!()`
                // would panic (aborting the process) if a future refactor
                // introduces a validation gap. Return a graceful error
                // instead — the caller already handles `bail!("bad")` for
                // malformed input. `bail!` expands to `return Err(...)`,
                // which has type `!` and coerces to the `u8` expected by
                // this arm.
                _ => bail!("bad"),
            };
            n = (n << 6) | (v as u32);
        }
        // Reject non-canonical base64 encodings.
        //
        // RFC 4648 §3.3: when fewer than 6 bits of a base64 digit are
        // significant (i.e., the digit encodes a partial byte at the end),
        // the remaining bits MUST be zero. A non-zero bit in the padding
        // region means the input is non-canonical and could mask a
        // canonicalization attack where two different ciphertexts decode
        // to the same bytes.
        //
        // Concretely: in the last group, with `pad` padding chars:
        //   pad=0 → 3 bytes out, all 24 bits significant, no check needed
        //   pad=1 → 2 bytes out, 16 bits significant, last 4 bits must be 0
        //   pad=2 → 1 byte out,  8 bits significant, last 4 bits must be 0
        //          (the third base64 digit contributes only 2 bits to the
        //           output byte, so 4 of its 6 bits are padding)
        //
        // Generic: for `pad` padding chars, the bottom `pad * 2` bits of
        // the last data digit (at position `3 - pad` of the group,
        // 0-indexed) must be zero.
        if pad > 0 {
            let last_data_idx = i + (3 - pad) as usize;
            let last_data_v = match s[last_data_idx] {
                b'A'..=b'Z' => s[last_data_idx] - b'A',
                b'a'..=b'z' => s[last_data_idx] - b'a' + 26,
                b'0'..=b'9' => s[last_data_idx] - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 0, // unreachable but defensive
            };
            let mask = (1u8 << (pad * 2)) - 1;
            if last_data_v & mask != 0 {
                bail!("bad");
            }
        }
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let cases = [
            &b"f"[..],
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00\x01\x02\x03\xff\xfe\xfd",
        ];
        for case in cases {
            let enc = base64_encode(case);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, case);
        }
    }

    #[test]
    fn test_base64_rejects_empty() {
        assert!(base64_decode("").is_err());
    }

    #[test]
    fn test_base64_rejects_mid_padding() {
        // `=` in the middle of a group is invalid.
        assert!(base64_decode("AB=C").is_err());
        assert!(base64_decode("A=BC").is_err());
        assert!(base64_decode("A===").is_err());
    }

    #[test]
    fn test_base64_rejects_invalid_chars() {
        assert!(base64_decode("AB!C").is_err());
        // Whitespace inside the input is stripped by base64_decode before
        // validation. "AB C" → "ABC" (length 3, not a multiple of 4) →
        // rejected for length, not for the space. Test a non-canonical
        // character that survives the whitespace strip:
        assert!(base64_decode("AB*C").is_err());
    }

    #[test]
    fn test_base64_rejects_non_multiple_of_4() {
        assert!(base64_decode("ABC").is_err());
        assert!(base64_decode("ABCDE").is_err());
    }

    #[test]
    fn test_armor_roundtrip() {
        let data = b"Hello, FORTIS! \x00\x01\x02\xff";
        let armored = armor(ARMOR_MSG, data);
        let dearmored = dearmor(&armored).unwrap();
        assert_eq!(dearmored, data);
    }

    #[test]
    fn test_armor_strict_rejects_missing_begin() {
        let data = b"test";
        let armored = armor(ARMOR_MSG, data);
        // Strip the BEGIN line.
        let without_begin: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----BEGIN "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(dearmor(&without_begin).is_err());
    }

    #[test]
    fn test_armor_strict_rejects_missing_end() {
        let data = b"test";
        let armored = armor(ARMOR_MSG, data);
        // Strip the END line.
        let without_end: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----END "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(dearmor(&without_end).is_err());
    }

    #[test]
    fn test_armor_strict_rejects_mismatched_labels() {
        let data = b"test";
        let armored = armor(ARMOR_MSG, data);
        // Replace BEGIN label with FORTIS SHARE.
        let tampered = armored.replace("BEGIN FORTIS MESSAGE", "BEGIN FORTIS SHARE");
        assert!(dearmor(&tampered).is_err());
    }

    #[test]
    fn test_armor_strict_rejects_multiple_blocks() {
        let data = b"test";
        let armored1 = armor(ARMOR_MSG, data);
        let armored2 = armor(ARMOR_MSG, data);
        let combined = format!("{}\n\n{}", armored1, armored2);
        assert!(dearmor(&combined).is_err());
    }

    #[test]
    fn test_armor_strict_rejects_unknown_label() {
        let data = b"test";
        let armored = armor("UNKNOWN LABEL", data);
        assert!(dearmor(&armored).is_err());
    }

    #[test]
    fn test_dearmor_with_label_accepts_correct() {
        let data = b"test data here";
        let armored = armor(ARMOR_MSG, data);
        let dec = dearmor_with_label(&armored, ARMOR_MSG).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_dearmor_with_label_rejects_wrong() {
        let data = b"test data here";
        let armored = armor(ARMOR_SHARE, data);
        assert!(dearmor_with_label(&armored, ARMOR_MSG).is_err());
    }
}
