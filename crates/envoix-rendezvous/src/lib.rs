//! Rendezvous session registry — pure logic, no HTTP.
//!
//! See `docs/rendezvous-design.md` for the contract this crate implements.
//! Module split per design §2:
//!
//! - [`capabilities`] — bearer-capability newtype, BLAKE3 hashing, redaction.
//! - [`state`] — session record, candidate, in-memory registry, TTL.
//! - [`error`] — the typed error taxonomy from design §3.4.

pub mod capabilities;
pub mod error;
pub mod state;

pub use capabilities::{Capability, CapabilityHash, ReceiverCap, SenderCap};
pub use error::{Error, Result};
pub use state::{
    Candidate, CandidatePublish, CandidateKind, PeerMetadata, Session, SessionId,
    SessionRegistry, SessionState, Transport,
};
