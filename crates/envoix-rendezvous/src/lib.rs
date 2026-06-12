//! Rendezvous session registry — pure logic, no HTTP.
//!
//! See `docs/rendezvous-design.md` for the contract this crate implements.
//! Module split per design §2:
//!
//! - [`capabilities`] — bearer-capability newtype, BLAKE3 hashing, redaction.
//! - [`state`] — session record, candidate, in-memory registry, TTL.
//! - [`error`] — the typed error taxonomy from design §3.4.
//! - [`probe`] / [`probe_token`] — reflexive UDP discovery frames and
//!   session-bound probe tokens (`docs/reflexive-discovery-design.md`).

pub mod capabilities;
pub mod error;
pub mod probe;
pub mod probe_token;
pub mod state;

mod hex;

pub use capabilities::{Capability, CapabilityHash};
pub use error::{Error, Result};
pub use probe::{
    PROBE_MAGIC, PROBE_REQUEST_LEN, PROBE_TXID_LEN, PROBE_VERSION, ProbeReply, ProbeRequest,
};
pub use probe_token::{PROBE_TOKEN_LEN, ProbeRole, ProbeTokenKey};
pub use state::{
    Candidate, CandidateKind, CandidatePublish, PeerMetadata, PollResult, RegistryConfig,
    RegistryStats, SessionId, SessionRegistry, Transport,
};
