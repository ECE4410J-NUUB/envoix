//! Session record, candidate types, and the in-memory registry.
//!
//! Design pointers:
//! - §3.2 — session lifecycle (Pending → Joined → removed).
//! - §3.3 — `PeerMetadata` vs. `Candidate`, tagged-union `kind`.
//! - §4.4 — TTL refresh on access, sweep task, opportunistic expiry on read.
//! - §4.5 — outer `RwLock<HashMap<…>>` for the registry; per-session inner
//!   locking is an implementation detail of [`SessionRegistry`].
//! - §4.5 — two clocks: wall-clock `SystemTime` on the wire, monotonic
//!   `tokio::time::Instant` for TTL math.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::capabilities::CapabilityHash;
use crate::Error;

/// Session id. 32 lowercase hex chars on the wire, 16 raw bytes in memory.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SessionId {
    _bytes: [u8; 16],
}

impl SessionId {
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let _ = s;
        todo!()
    }
}

/// One reachable network endpoint a peer claims.
///
/// `sequence` and `published_at` are server-assigned; clients submit the
/// remaining fields via [`CandidatePublish`].
pub struct Candidate {
    pub kind: CandidateKind,
    pub transport: Transport,
    pub addr: SocketAddr,
    pub priority: i32,
    pub sequence: u64,
    pub published_at: SystemTime,
}

/// Client-supplied subset of a [`Candidate`]. Server fills in `sequence`
/// and `published_at` on intake.
pub struct CandidatePublish {
    pub kind: CandidateKind,
    pub transport: Transport,
    pub addr: SocketAddr,
    pub priority: i32,
}

/// Tagged-union discriminant. v1 carries only `Host` and `Ipv6Global`;
/// see design §3.3 for the rationale and the future-kind path.
pub enum CandidateKind {
    Host,
    Ipv6Global,
}

pub enum Transport {
    Quic,
}

pub struct PeerMetadata {
    pub observed_http_addr: Option<SocketAddr>,
    pub protocol_versions: Vec<u32>,
    pub strategies: Vec<String>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

pub enum SessionState {
    Pending,
    Joined,
}

/// A live session. `expires_at_wall` is for wire serialisation only;
/// `expires_at_mono` drives TTL math.
pub struct Session {
    pub id: SessionId,
    pub receiver_cap_hash: CapabilityHash,
    pub sender_cap_hash: CapabilityHash,
    pub state: SessionState,
    pub created_at: SystemTime,
    pub expires_at_wall: SystemTime,
    pub expires_at_mono: Instant,
    pub receiver_metadata: Option<PeerMetadata>,
    pub sender_metadata: Option<PeerMetadata>,
    pub receiver_candidates: Vec<Candidate>,
    pub sender_candidates: Vec<Candidate>,
    pub next_sequence: u64,
}

/// In-memory session registry.
pub struct SessionRegistry {
    _sessions: RwLock<HashMap<SessionId, Session>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        todo!()
    }

    pub async fn register(
        &self,
        id: SessionId,
        receiver_cap_hash: CapabilityHash,
        sender_cap_hash: CapabilityHash,
        metadata: PeerMetadata,
        ttl_seconds: u32,
    ) -> Result<(), Error> {
        let _ = (id, receiver_cap_hash, sender_cap_hash, metadata, ttl_seconds);
        todo!()
    }

    pub async fn join(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        metadata: PeerMetadata,
    ) -> Result<(), Error> {
        let _ = (id, presented_hash, metadata);
        todo!()
    }

    /// Publish a candidate. Returns the stored [`Candidate`] (with
    /// server-assigned `sequence` and `published_at`). A duplicate
    /// `(kind, transport, addr)` is a no-op per design §3.3.
    pub async fn publish_candidate(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        candidate: CandidatePublish,
    ) -> Result<Candidate, Error> {
        let _ = (id, presented_hash, candidate);
        todo!()
    }

    /// Return candidates the *other* peer has published with
    /// `sequence > since`. Empty vec if none.
    pub async fn poll_candidates(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        since: u64,
    ) -> Result<Vec<Candidate>, Error> {
        let _ = (id, presented_hash, since);
        todo!()
    }

    /// Close the session. Requires the receiver capability.
    pub async fn close(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
    ) -> Result<(), Error> {
        let _ = (id, presented_hash);
        todo!()
    }

    /// Background-sweep entry point. Removes expired sessions.
    pub async fn sweep_expired(&self) {
        todo!()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
