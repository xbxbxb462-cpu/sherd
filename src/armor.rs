//! ASCII armor: `-----BEGIN <LABEL>-----` / base64 body / `-----END <LABEL>-----`.
//!
//! Strict dearmoring: one BEGIN, one END, matching labels, canonical base64
//! only. Not constant-time; the armor layer only wraps the AEAD-authenticated
//! envelope, so timing leaks structure of caller-controlled input, not
//! plaintext.

use anyhow::{bail, Result};
use crate::crypto::constants::{ARMOR_FILE, ARMOR_MSG, ARMOR_SHARE};

/// Max armored input size. Caps OOM exposure from a huge blob piped to
/// stdin. 512 MiB covers MAX_CT plus base64 overhead.
const MAX_ARMOR_SIZE: usize = 512 * 1024 * 1024;

pub fn armor(label: &str, bytes: &[u8]) -> String {
    // Reject the label up front. A label like "MSG-----\n-----BEGIN FAKE"
    // could inject nested armor boundaries.
    if label.is_empty()
        || label.contains('\n')
        || label.contains('\r')
        || label.contains('-')
        || label.contains('\0')
        || !label.is_ascii()
    {
        return String::new();
    }
    let b64 = base64_encode(bytes);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    // Trailing newline keeps concatenated blobs parseable.
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

/// Strict dearmoring. Returns decoded bytes; label is discarded.
pub fn dearmor(text: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_ARMOR_SIZE {
        bail!("bad");
    }
    let (label, body) = parse_armor_structure(text)?;
    let _ = label; // discarded; use dearmor_with_label to enforce it
    base64_decode(&body)
}

/// Strict dearmoring, enforcing the expected label.
pub fn dearmor_with_label(text: &str, expected_label: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_ARMOR_SIZE {
        bail!("bad");
    }
    let (label, body) = parse_armor_structure(text)?;
    if label != expected_label {
        bail!("bad");
    }
    base64_decode(&body)
}

/// Parse label and base64 body out of an armored text.
fn parse_armor_structure(text: &str) -> Result<(String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        bail!("bad");
    }

    // Find the single BEGIN line.
    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    let mut begin_label: Option<String> = None;
    let mut end_label: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                if begin_idx.is_some() {
                    // Duplicate BEGIN line.
                    bail!("bad");
                }
                begin_idx = Some(i);
                begin_label = Some(label.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("-----END ") {
            if let Some(label) = rest.strip_suffix("-----") {
                if end_idx.is_some() {
                    // Duplicate END line.
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

    if begin_idx >= end_idx {
        bail!("bad");
    }
    if begin_label != end_label {
        bail!("bad");
    }
    if begin_label.is_empty() {
        bail!("bad");
    }
    // Label must be a known Sherd label.
    if !matches!(
        begin_label.as_str(),
        ARMOR_MSG | ARMOR_FILE | ARMOR_SHARE
    ) {
        bail!("bad");
    }

    // Collect the base64 body from lines between BEGIN and END.
    let mut body = String::new();
    for line in &lines[begin_idx + 1..end_idx] {
        let trimmed = line.trim_end_matches('\r');
        for c in trimmed.chars() {
            // ASCII whitespace only; reject Unicode whitespace.
            if c == ' ' || c == '\t' || c == '\r' {
                continue;
            }
            if !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=' {
                bail!("bad");
            }
            body.push(c);
        }
    }

    if body.is_empty() {
        bail!("bad");
    }

    Ok((begin_label, body))
}

// ---------------------------------------------------------------------------
// Base64 (strict, no external dep)
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

/// Strict base64 decoder. Rejects non-canonical alphabet, mid-stream
/// padding, bad length, and empty input.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.is_empty() {
        bail!("bad");
    }
    if s.len() % 4 != 0 {
        bail!("bad");
    }

    // Padding only in the last group, positions 2 and 3.
    let last_group_start = s.len() - 4;
    for (i, &c) in s.iter().enumerate() {
        let is_canonical = c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
        let is_padding = c == b'=';
        if !is_canonical && !is_padding {
            bail!("bad");
        }
        if is_padding {
            if i < last_group_start {
                bail!("bad");
            }
            if i == last_group_start || i == last_group_start + 1 {
                bail!("bad");
            }
        }
    }

    // Padding must be contiguous: walking backward, a '=' seen after any
    // data byte means pad-then-data going forward, which is invalid.
    let mut found_data = false;
    for &c in s.iter().rev() {
        if c == b'=' {
            if found_data {
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
                // Unreachable: alphabet was validated above. Bail, don't panic.
                _ => bail!("bad"),
            };
            n = (n << 6) | (v as u32);
        }
        // Reject non-canonical encodings: per RFC 4648, the low bits of
        // the last data digit that fall in padding must be zero.
        if pad > 0 {
            let last_data_idx = i + (3 - pad) as usize;
            let last_data_v = match s[last_data_idx] {
                b'A'..=b'Z' => s[last_data_idx] - b'A',
                b'a'..=b'z' => s[last_data_idx] - b'a' + 26,
                b'0'..=b'9' => s[last_data_idx] - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 0, // unreachable: alphabet validated above
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
        // validation. "AB C" becomes "ABC", length 3, not a multiple of 4,
        // rejected for length not the space. Test a non-canonical character
        // that survives the whitespace strip:
        assert!(base64_decode("AB*C").is_err());
    }

    #[test]
    fn test_base64_rejects_non_multiple_of_4() {
        assert!(base64_decode("ABC").is_err());
        assert!(base64_decode("ABCDE").is_err());
    }

    #[test]
    fn test_armor_roundtrip() {
        let data = b"Hello, SHERD! \x00\x01\x02\xff";
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
        // Replace BEGIN label with SHERD SHARE.
        let tampered = armored.replace("BEGIN SHERD MESSAGE", "BEGIN SHERD SHARE");
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
