//! Bearer-capability handling: parsing, hashing, redaction.
//!
//! Design pointers:
//! - §3.1 — capability format (32 lowercase hex chars, 128 bits).
//! - §3.1 — BLAKE3 at intake, constant-time compare on the hash.
//! - §4.7 — `Debug` / `Display` emit redaction so a stray
//!   `tracing::debug!(?cap)` cannot leak.

use std::fmt;

use crate::hex::{fmt_hex_lower, parse_hex_16};
use crate::Error;

const HASH_LEN: usize = 32;
const HASH_REF_HEX_CHARS: usize = 8;

/// Raw bearer capability. 128 bits of secret material.
///
/// `Debug` and `Display` are redacted at the type level; the contained
/// bytes are accessible only via [`Capability::hash`].
pub struct Capability {
    bytes: [u8; 16],
}

impl Capability {
    /// Parse a 32-character lowercase hex string into a capability.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        match parse_hex_16(s) {
            Some(bytes) => Ok(Self { bytes }),
            None => Err(Error::InvalidRequest(
                "capability must be 32 lowercase hex characters".into(),
            )),
        }
    }

    /// BLAKE3 hash of the capability bytes. Suitable for at-rest storage.
    pub fn hash(&self) -> CapabilityHash {
        let h = blake3::hash(&self.bytes);
        CapabilityHash { bytes: *h.as_bytes() }
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Capability(<redacted>)")
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// BLAKE3 hash of a capability. Equality is constant-time.
#[derive(Clone)]
pub struct CapabilityHash {
    bytes: [u8; HASH_LEN],
}

impl PartialEq for CapabilityHash {
    /// Constant-time XOR-accumulate over all 32 bytes.
    ///
    /// Design §3.1 allows "`subtle::ConstantTimeEq` or equivalent". The hand
    /// rolled form is equivalent: the loop unconditionally touches every
    /// byte and the `|=` prevents short-circuit optimisation. We never
    /// accept a hash from the network — only re-hashed bearers — so a
    /// hypothetical timing leak of the hash itself would not yield the
    /// underlying capability.
    fn eq(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;
        for i in 0..HASH_LEN {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        diff == 0
    }
}

impl Eq for CapabilityHash {}

impl fmt::Debug for CapabilityHash {
    /// `CapHashRef(deadbeef)` — first 8 hex chars only per design §4.7.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapHashRef(")?;
        fmt_hex_lower(&self.bytes[..HASH_REF_HEX_CHARS / 2], f)?;
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HEX_A: &str = "0123456789abcdef0123456789abcdef";
    const VALID_HEX_B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn from_hex_accepts_valid() {
        assert!(Capability::from_hex(VALID_HEX_A).is_ok());
    }

    #[test]
    fn from_hex_rejects_invalid() {
        for bad in [
            "",
            "short",
            "0123456789abcdef0123456789abcdeg",       // non-hex 'g'
            "0123456789ABCDEF0123456789abcdef",       // uppercase
            "0123456789abcdef0123456789abcdef00",     // too long
        ] {
            assert!(
                matches!(Capability::from_hex(bad), Err(Error::InvalidRequest(_))),
                "expected InvalidRequest for {:?}",
                bad
            );
        }
    }

    #[test]
    fn debug_redacts() {
        let cap = Capability::from_hex(VALID_HEX_A).unwrap();
        let s = format!("{:?}", cap);
        assert!(s.contains("redacted"), "got: {}", s);
        // Make sure no hex prefix of the secret leaks.
        assert!(!s.contains("0123"), "got: {}", s);
    }

    #[test]
    fn display_redacts() {
        let cap = Capability::from_hex(VALID_HEX_A).unwrap();
        assert_eq!(format!("{}", cap), "<redacted>");
    }

    #[test]
    fn hash_is_deterministic() {
        let a1 = Capability::from_hex(VALID_HEX_A).unwrap().hash();
        let a2 = Capability::from_hex(VALID_HEX_A).unwrap().hash();
        assert_eq!(a1, a2);
    }

    #[test]
    fn distinct_capabilities_hash_differently() {
        let a = Capability::from_hex(VALID_HEX_A).unwrap().hash();
        let b = Capability::from_hex(VALID_HEX_B).unwrap().hash();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_debug_emits_short_ref_only() {
        let h = Capability::from_hex(VALID_HEX_A).unwrap().hash();
        let s = format!("{:?}", h);
        // Format: CapHashRef(xxxxxxxx) — exactly 8 hex chars.
        assert!(s.starts_with("CapHashRef("));
        assert!(s.ends_with(')'));
        let inner = &s["CapHashRef(".len()..s.len() - 1];
        assert_eq!(inner.len(), 8);
        assert!(inner.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
