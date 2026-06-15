//! Rendezvous session registry: pure logic, no HTTP.
//!
//! Module split:
//!
//! - [`capabilities`] - bearer-capability newtype, BLAKE3 hashing, redaction.
//! - [`state`] - session record, candidate, in-memory registry, TTL.
//! - [`error`] - the typed error taxonomy.

pub mod capabilities;
pub mod error;
pub mod state;

mod hex;

pub use capabilities::{Capability, CapabilityHash};
pub use error::{Error, Result};
pub use state::{
    Candidate, CandidateKind, CandidatePublish, PeerMetadata, PollResult, RegistryConfig,
    RegistryStats, SessionId, SessionRegistry, SessionRole, Transport,
};
