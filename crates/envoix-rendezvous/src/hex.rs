//! Lowercase-hex parsing and formatting for fixed-size byte arrays.
//!
//! Capability and session-id strings on the wire are always 32 lowercase
//! hex characters per design §3.1. This module is the single place that
//! handles that encoding.

use std::fmt;

/// Parse exactly 32 lowercase hex characters into 16 bytes.
///
/// Returns `None` on length, charset, or case mismatch. Uppercase `A-F` is
/// rejected because the design pins lowercase to make string comparison
/// straightforward downstream.
pub(crate) fn parse_hex_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Write `bytes` as lowercase hex into a formatter.
pub(crate) fn fmt_hex_lower(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for b in bytes {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        let input = "0123456789abcdef0123456789abcdef";
        let bytes = parse_hex_16(input).expect("valid");
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[15], 0xef);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_hex_16("").is_none());
        assert!(parse_hex_16("ab").is_none());
        assert!(parse_hex_16(&"0".repeat(31)).is_none());
        assert!(parse_hex_16(&"0".repeat(33)).is_none());
    }

    #[test]
    fn parse_rejects_uppercase() {
        // Lowercase pinned by design §3.1.
        assert!(parse_hex_16("0123456789ABCDEF0123456789abcdef").is_none());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(parse_hex_16("0123456789abcdef0123456789abcdeg").is_none());
        assert!(parse_hex_16("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }
}
