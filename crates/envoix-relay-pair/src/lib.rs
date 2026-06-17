//! SPAKE2-based relay pairing: hand a custom relay's master key + port range
//! to a client over an untrusted channel.
//!
//! A relay owner and their client share a short, typeable code (the SPAKE2
//! password). SPAKE2 turns it into a strong shared key `K` that an observer
//! cannot derive (offline guessing is impossible; online guessing is one
//! attempt per connection, so the verifier caps attempts). The relay then
//! seals its credentials under a key derived from `K`, so confidentiality
//! comes from `K` itself - no transport encryption or channel binding needed
//! (cf. `envoix-auth`, which rides QUIC and binds to its TLS exporter).
//!
//! Pure logic, no sockets: the relay-server performs the actual I/O.
//!
//! Part 1 (this module): the sealed bundle. Later parts add the SPAKE2
//! handshake, key confirmation, and the wire driver.

mod bundle;

pub use bundle::{RelayProvision, open, open_provision, seal, seal_provision};

/// Errors from the pairing protocol.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("entropy source unavailable")]
    Entropy,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("sealed bundle is malformed or truncated")]
    Malformed,
    #[error("decryption failed: wrong pairing code or tampered data")]
    Decrypt,
    #[error("bundle is not valid JSON: {0}")]
    BadJson(String),
}
