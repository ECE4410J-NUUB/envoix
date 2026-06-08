//! Bearer-capability handling: parsing, hashing, redaction, role wrappers.
//!
//! Design pointers:
//! - §3.1 — capability format (32 lowercase hex chars, 128 bits).
//! - §3.1 — BLAKE3 at intake, constant-time compare on the hash.
//! - §4.7 — `Debug` / `Display` emit `<redacted>` so a stray
//!   `tracing::debug!(?cap)` cannot leak.

use std::fmt;

use crate::Error;

/// Raw bearer capability. 128 bits of secret material.
///
/// `Debug` and `Display` are redacted at the type level. The contained
/// bytes are accessible only via [`Capability::hash`].
pub struct Capability {
    _bytes: [u8; 16],
}

impl Capability {
    /// Parse a 32-character lowercase hex string into a capability.
    ///
    /// Returns [`Error::InvalidRequest`] on length, charset, or case mismatch.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let _ = s;
        todo!()
    }

    /// BLAKE3 hash of the capability bytes. Suitable for at-rest storage.
    pub fn hash(&self) -> CapabilityHash {
        todo!()
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
    _bytes: [u8; 32],
}

impl PartialEq for CapabilityHash {
    fn eq(&self, other: &Self) -> bool {
        let _ = other;
        todo!()
    }
}

impl Eq for CapabilityHash {}

impl fmt::Debug for CapabilityHash {
    /// Emits only the first 8 hex chars (`cap_hash_ref`) per design §4.7.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        todo!()
    }
}

/// Wrapper marking a capability as authorising the receiver role.
pub struct ReceiverCap(pub Capability);

/// Wrapper marking a capability as authorising the sender role.
pub struct SenderCap(pub Capability);
