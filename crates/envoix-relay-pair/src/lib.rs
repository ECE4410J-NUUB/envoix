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
//! Parts: the sealed bundle (`bundle`) and the SPAKE2 handshake + key
//! confirmation (`handshake`). A later part adds the wire driver that runs the
//! exchange over a transport.

mod bundle;
mod handshake;

pub use bundle::{RelayProvision, open, open_provision, seal, seal_provision};
pub use handshake::{
    Confirm, PakeResponse, PakeStart, Paired, client_start, relay_respond, ClientConfirming,
    ClientPending, RelayConfirming,
};

/// Errors from the pairing protocol.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("entropy source unavailable")]
    Entropy,
    #[error("sealed bundle is malformed or truncated")]
    Malformed,
    #[error("decryption failed: wrong pairing code or tampered data")]
    Decrypt,
    #[error("bundle is not valid JSON: {0}")]
    BadJson(String),
    #[error("SPAKE2 failed: {0}")]
    Spake2(String),
    #[error("key confirmation failed: wrong pairing code or tampered handshake")]
    Confirm,
    #[error("malformed handshake message: {0}")]
    BadMessage(String),
}
