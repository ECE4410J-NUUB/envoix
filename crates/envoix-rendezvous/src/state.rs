//! Session record, candidate types, and the in-memory registry.
//!
//! Design pointers:
//! - §3.2 — session lifecycle (Pending → Joined → removed) and tombstone
//!   retention for distinguishing `session_expired` from `session_closed`.
//! - §3.3 — `PeerMetadata` vs. `Candidate`, tagged-union `kind`, duplicate
//!   publish is a no-op.
//! - §4.4 — TTL refresh on every authenticated request; sweep backstop;
//!   opportunistic expiry on read.
//! - §4.5 — outer `RwLock<HashMap<…>>` + per-session inner `Mutex`.
//! - §4.5 — two clocks: wall-clock `SystemTime` on the wire, monotonic
//!   `tokio::time::Instant` for TTL math.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use crate::capabilities::CapabilityHash;
use crate::hex::{fmt_hex_lower, parse_hex};
use crate::Error;

const SESSION_ID_REF_HEX_CHARS: usize = 8;

// ── Public wire-shaped types ─────────────────────────────────────────────

/// Session id. 32 lowercase hex chars on the wire, 16 raw bytes in memory.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SessionId {
    bytes: [u8; 16],
}

impl SessionId {
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        match parse_hex::<16>(s) {
            Some(bytes) => Ok(Self { bytes }),
            None => Err(Error::InvalidRequest(
                "session_id must be 32 lowercase hex characters".into(),
            )),
        }
    }
}

impl fmt::Debug for SessionId {
    /// `SessionRef(deadbeef)` — first 8 hex chars only per design §4.7.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRef(")?;
        fmt_hex_lower(&self.bytes[..SESSION_ID_REF_HEX_CHARS / 2], f)?;
        f.write_str(")")
    }
}

impl fmt::Display for SessionId {
    /// Full 32 lowercase hex chars. URL paths only — do **not** log via
    /// `Display`; use `Debug` for the redacted ref.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex_lower(&self.bytes, f)
    }
}

/// One reachable network endpoint a peer claims. `sequence` and
/// `published_at` are server-assigned.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub transport: Transport,
    pub addr: SocketAddr,
    pub priority: i32,
    pub sequence: u64,
    pub published_at: SystemTime,
}

/// Client-supplied subset of a [`Candidate`]. Server fills in `sequence`
/// and `published_at`.
pub struct CandidatePublish {
    pub kind: CandidateKind,
    pub transport: Transport,
    pub addr: SocketAddr,
    pub priority: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateKind {
    Host,
    Ipv6Global,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Quic,
}

#[derive(Clone)]
pub struct PeerMetadata {
    pub observed_http_addr: Option<SocketAddr>,
    pub protocol_versions: Vec<u32>,
    pub strategies: Vec<String>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

// ── Internal storage types (not in the public re-exports) ────────────────

#[derive(Clone, Copy, Eq, PartialEq)]
enum SessionState {
    Pending,
    Joined,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TombstoneReason {
    Expired,
    Closed,
}

/// Immutable session header. Cap hashes and ttl are set at register and
/// never change; the API layer can authenticate without touching `inner`.
struct Session {
    receiver_cap_hash: CapabilityHash,
    sender_cap_hash: CapabilityHash,
    ttl: Duration,
    inner: Mutex<SessionInner>,
}

struct SessionInner {
    state: SessionState,
    expires_at_mono: Instant,
    // Metadata is populated by register/join but currently unread —
    // PR 3 will surface it via the candidate-poll response and /stats.
    #[allow(dead_code)]
    receiver_metadata: PeerMetadata,
    #[allow(dead_code)]
    sender_metadata: Option<PeerMetadata>,
    receiver_candidates: Vec<Candidate>,
    sender_candidates: Vec<Candidate>,
    next_sequence: u64,
}

struct Tombstone {
    reason: TombstoneReason,
    forget_at: Instant,
}

enum SessionSlot {
    Live(Session),
    Tombstoned(Tombstone),
}

#[derive(Clone, Copy)]
enum AuthRole {
    Receiver,
    Sender,
}

// ── Configuration ────────────────────────────────────────────────────────

/// Registry tuning knobs sourced from `--max-sessions` / `--max-candidates`
/// / `--default-ttl-seconds` / `--max-ttl-seconds` (design §4.9).
#[derive(Clone, Copy)]
pub struct RegistryConfig {
    pub max_sessions: usize,
    pub max_candidates_per_session: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_candidates_per_session: 32,
            default_ttl: Duration::from_secs(300),
            max_ttl: Duration::from_secs(1800),
        }
    }
}

// ── Registry ─────────────────────────────────────────────────────────────

/// In-memory session registry.
pub struct SessionRegistry {
    slots: RwLock<HashMap<SessionId, SessionSlot>>,
    config: RegistryConfig,
}

impl SessionRegistry {
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            slots: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Register a new pending session. Receiver supplies metadata at this
    /// point; sender metadata arrives at [`join`](Self::join).
    ///
    /// Returns the effective wall-clock expiry (requested TTL clamped to
    /// `max_ttl`) for the API layer to serialise into the response.
    pub async fn register(
        &self,
        id: SessionId,
        receiver_cap_hash: CapabilityHash,
        sender_cap_hash: CapabilityHash,
        metadata: PeerMetadata,
        ttl: Option<Duration>,
    ) -> Result<SystemTime, Error> {
        // Hash-level distinctness is the strongest check available at this
        // layer; raw-string distinctness (id vs cap hex) is the API layer's
        // responsibility (it sees the unparsed strings).
        if receiver_cap_hash == sender_cap_hash {
            return Err(Error::InvalidRequest(
                "receiver_cap and sender_cap must differ".into(),
            ));
        }

        let ttl = ttl.unwrap_or(self.config.default_ttl).min(self.config.max_ttl);
        let now_mono = Instant::now();

        let mut slots = self.slots.write().await;

        // Tombstones occupy a slot until their forget_at fires — preventing an
        // attacker from rapid-cycling register/close to bypass the cap.
        if slots.len() >= self.config.max_sessions {
            return Err(Error::CapacityExceeded);
        }
        if slots.contains_key(&id) {
            return Err(Error::Conflict(format!(
                "session id {} already exists",
                id
            )));
        }

        slots.insert(
            id,
            SessionSlot::Live(Session {
                receiver_cap_hash,
                sender_cap_hash,
                ttl,
                inner: Mutex::new(SessionInner {
                    state: SessionState::Pending,
                    expires_at_mono: now_mono + ttl,
                    receiver_metadata: metadata,
                    sender_metadata: None,
                    receiver_candidates: Vec::new(),
                    sender_candidates: Vec::new(),
                    next_sequence: 1,
                }),
            }),
        );
        Ok(SystemTime::now() + ttl)
    }

    /// Sender joins the session. Idempotent: a second join from the same
    /// sender refreshes metadata and TTL without changing state.
    pub async fn join(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        metadata: PeerMetadata,
    ) -> Result<(), Error> {
        let slots = self.slots.read().await;
        let session = match slots.get(id) {
            None => return Err(Error::SessionNotFound),
            Some(SessionSlot::Tombstoned(t)) => return Err(tombstone_error(t.reason)),
            Some(SessionSlot::Live(s)) => s,
        };

        if presented_hash != &session.sender_cap_hash {
            return Err(Error::Unauthorized);
        }

        let mut inner = session.inner.lock().await;
        if inner.expires_at_mono <= Instant::now() {
            return Err(Error::SessionExpired);
        }

        inner.state = SessionState::Joined;
        inner.sender_metadata = Some(metadata);
        inner.expires_at_mono = Instant::now() + session.ttl;
        Ok(())
    }

    /// Publish a candidate from whichever peer presented `presented_hash`.
    /// A duplicate `(kind, transport, addr)` returns the existing record
    /// unchanged (design §3.3).
    pub async fn publish_candidate(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        candidate: CandidatePublish,
    ) -> Result<Candidate, Error> {
        let slots = self.slots.read().await;
        let session = match slots.get(id) {
            None => return Err(Error::SessionNotFound),
            Some(SessionSlot::Tombstoned(t)) => return Err(tombstone_error(t.reason)),
            Some(SessionSlot::Live(s)) => s,
        };

        let role = role_for_hash(session, presented_hash)?;

        let mut inner = session.inner.lock().await;
        if inner.expires_at_mono <= Instant::now() {
            return Err(Error::SessionExpired);
        }

        // Dedup + cap check via an immutable borrow scoped tightly so the
        // later mutable borrows (next_sequence, bucket.push) can coexist.
        {
            let bucket = match role {
                AuthRole::Receiver => &inner.receiver_candidates,
                AuthRole::Sender => &inner.sender_candidates,
            };
            if let Some(existing) = bucket.iter().find(|c| {
                c.kind == candidate.kind
                    && c.transport == candidate.transport
                    && c.addr == candidate.addr
            }) {
                return Ok(existing.clone());
            }
            if bucket.len() >= self.config.max_candidates_per_session {
                return Err(Error::InvalidRequest(format!(
                    "candidate cap ({}) reached for this session",
                    self.config.max_candidates_per_session
                )));
            }
        }

        let seq = inner.next_sequence;
        inner.next_sequence += 1;
        let stored = Candidate {
            kind: candidate.kind,
            transport: candidate.transport,
            addr: candidate.addr,
            priority: candidate.priority,
            sequence: seq,
            published_at: SystemTime::now(),
        };
        let bucket = match role {
            AuthRole::Receiver => &mut inner.receiver_candidates,
            AuthRole::Sender => &mut inner.sender_candidates,
        };
        bucket.push(stored.clone());

        inner.expires_at_mono = Instant::now() + session.ttl;
        Ok(stored)
    }

    /// Return *the other peer's* candidates with `sequence > since`. Empty
    /// vec is normal — the caller decides when to retry (short-poll).
    pub async fn poll_candidates(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
        since: u64,
    ) -> Result<Vec<Candidate>, Error> {
        let slots = self.slots.read().await;
        let session = match slots.get(id) {
            None => return Err(Error::SessionNotFound),
            Some(SessionSlot::Tombstoned(t)) => return Err(tombstone_error(t.reason)),
            Some(SessionSlot::Live(s)) => s,
        };

        let role = role_for_hash(session, presented_hash)?;

        let mut inner = session.inner.lock().await;
        if inner.expires_at_mono <= Instant::now() {
            return Err(Error::SessionExpired);
        }

        let bucket = match role {
            AuthRole::Receiver => &inner.sender_candidates,
            AuthRole::Sender => &inner.receiver_candidates,
        };
        let result: Vec<Candidate> = bucket.iter().filter(|c| c.sequence > since).cloned().collect();

        inner.expires_at_mono = Instant::now() + session.ttl;
        Ok(result)
    }

    /// Receiver-only. Replaces the slot with a `Closed` tombstone that
    /// lives for one `default_ttl` cycle so polls see `session_closed`.
    pub async fn close(
        &self,
        id: &SessionId,
        presented_hash: &CapabilityHash,
    ) -> Result<(), Error> {
        let mut slots = self.slots.write().await;
        let auth_err = match slots.get(id) {
            None => Some(Error::SessionNotFound),
            Some(SessionSlot::Tombstoned(t)) => Some(tombstone_error(t.reason)),
            Some(SessionSlot::Live(s)) => {
                if presented_hash != &s.receiver_cap_hash {
                    Some(Error::Unauthorized)
                } else {
                    None
                }
            }
        };
        if let Some(e) = auth_err {
            return Err(e);
        }
        slots.insert(
            id.clone(),
            SessionSlot::Tombstoned(Tombstone {
                reason: TombstoneReason::Closed,
                forget_at: Instant::now() + self.config.default_ttl,
            }),
        );
        Ok(())
    }

    /// Periodic sweep: live sessions past their TTL become `Expired`
    /// tombstones; tombstones past their `forget_at` are removed.
    pub async fn sweep_expired(&self) {
        let now = Instant::now();
        let mut slots = self.slots.write().await;
        let mut to_tombstone: Vec<SessionId> = Vec::new();
        let mut to_remove: Vec<SessionId> = Vec::new();

        for (id, slot) in slots.iter() {
            match slot {
                SessionSlot::Live(s) => {
                    // try_lock so an in-flight request doesn't deadlock the
                    // sweep; the request itself runs opportunistic expiry.
                    if let Ok(inner) = s.inner.try_lock() {
                        if inner.expires_at_mono <= now {
                            to_tombstone.push(id.clone());
                        }
                    }
                }
                SessionSlot::Tombstoned(t) => {
                    if t.forget_at <= now {
                        to_remove.push(id.clone());
                    }
                }
            }
        }

        let tombstone_forget = now + self.config.default_ttl;
        for id in to_tombstone {
            slots.insert(
                id,
                SessionSlot::Tombstoned(Tombstone {
                    reason: TombstoneReason::Expired,
                    forget_at: tombstone_forget,
                }),
            );
        }
        for id in to_remove {
            slots.remove(&id);
        }
    }
}

fn role_for_hash(session: &Session, presented: &CapabilityHash) -> Result<AuthRole, Error> {
    if presented == &session.receiver_cap_hash {
        Ok(AuthRole::Receiver)
    } else if presented == &session.sender_cap_hash {
        Ok(AuthRole::Sender)
    } else {
        Err(Error::Unauthorized)
    }
}

fn tombstone_error(reason: TombstoneReason) -> Error {
    match reason {
        TombstoneReason::Expired => Error::SessionExpired,
        TombstoneReason::Closed => Error::SessionClosed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;

    // ── helpers ──────────────────────────────────────────────────────────

    fn hex_of(c: char) -> String {
        debug_assert!(c.is_ascii_hexdigit() && !c.is_ascii_uppercase(), "must be lowercase hex");
        std::iter::repeat(c).take(32).collect()
    }

    fn make_id(c: char) -> SessionId {
        SessionId::from_hex(&hex_of(c)).unwrap()
    }

    fn make_hash(c: char) -> CapabilityHash {
        Capability::from_hex(&hex_of(c)).unwrap().hash()
    }

    fn make_metadata() -> PeerMetadata {
        PeerMetadata {
            observed_http_addr: None,
            protocol_versions: vec![1],
            strategies: vec![],
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }

    fn make_candidate(addr: &str) -> CandidatePublish {
        CandidatePublish {
            kind: CandidateKind::Host,
            transport: Transport::Quic,
            addr: addr.parse().unwrap(),
            priority: 100,
        }
    }

    fn fresh_registry() -> SessionRegistry {
        SessionRegistry::new(RegistryConfig::default())
    }

    async fn register_default(reg: &SessionRegistry, id: &SessionId) {
        reg.register(
            id.clone(),
            make_hash('a'),
            make_hash('b'),
            make_metadata(),
            None,
        )
        .await
        .expect("register");
    }

    // ── SessionId unit tests (kept from previous step) ───────────────────

    const VALID_HEX: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn session_id_from_hex_accepts_valid() {
        assert!(SessionId::from_hex(VALID_HEX).is_ok());
    }

    #[test]
    fn session_id_from_hex_rejects_invalid() {
        assert!(matches!(
            SessionId::from_hex("short"),
            Err(Error::InvalidRequest(_))
        ));
        assert!(matches!(
            SessionId::from_hex("0123456789ABCDEF0123456789abcdef"),
            Err(Error::InvalidRequest(_))
        ));
    }

    #[test]
    fn session_id_debug_emits_short_ref_only() {
        let id = SessionId::from_hex(VALID_HEX).unwrap();
        let s = format!("{:?}", id);
        assert_eq!(s, "SessionRef(01234567)");
    }

    #[test]
    fn session_id_display_emits_full_hex() {
        let id = SessionId::from_hex(VALID_HEX).unwrap();
        assert_eq!(format!("{}", id), VALID_HEX);
    }

    #[test]
    fn registry_config_defaults_match_design() {
        let c = RegistryConfig::default();
        assert_eq!(c.max_sessions, 10_000);
        assert_eq!(c.max_candidates_per_session, 32);
        assert_eq!(c.default_ttl, Duration::from_secs(300));
        assert_eq!(c.max_ttl, Duration::from_secs(1800));
    }

    // ── registry tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn full_round_trip() {
        let reg = fresh_registry();
        let id = make_id('1');
        let recv = make_hash('a');
        let sender = make_hash('b');

        reg.register(id.clone(), recv.clone(), sender.clone(), make_metadata(), None)
            .await
            .unwrap();
        reg.join(&id, &sender, make_metadata()).await.unwrap();

        let recv_cand = reg
            .publish_candidate(&id, &recv, make_candidate("10.0.0.1:9000"))
            .await
            .unwrap();
        let sender_cand = reg
            .publish_candidate(&id, &sender, make_candidate("10.0.0.2:9000"))
            .await
            .unwrap();

        // Each side sees only the OTHER's candidates.
        let seen_by_sender = reg.poll_candidates(&id, &sender, 0).await.unwrap();
        assert_eq!(seen_by_sender.len(), 1);
        assert_eq!(seen_by_sender[0].sequence, recv_cand.sequence);

        let seen_by_recv = reg.poll_candidates(&id, &recv, 0).await.unwrap();
        assert_eq!(seen_by_recv.len(), 1);
        assert_eq!(seen_by_recv[0].sequence, sender_cand.sequence);

        reg.close(&id, &recv).await.unwrap();
        assert!(matches!(
            reg.poll_candidates(&id, &recv, 0).await,
            Err(Error::SessionClosed)
        ));
    }

    #[tokio::test]
    async fn register_rejects_equal_caps() {
        let reg = fresh_registry();
        let id = make_id('1');
        let same = make_hash('a');
        let err = reg
            .register(id, same.clone(), same, make_metadata(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn register_conflict_on_duplicate_id() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        let err = reg
            .register(id, make_hash('a'), make_hash('b'), make_metadata(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
    }

    #[tokio::test]
    async fn register_capacity_exceeded() {
        let small_cfg = RegistryConfig {
            max_sessions: 2,
            ..RegistryConfig::default()
        };
        let reg = SessionRegistry::new(small_cfg);
        register_default(&reg, &make_id('1')).await;
        register_default(&reg, &make_id('2')).await;
        let err = reg
            .register(make_id('3'), make_hash('a'), make_hash('b'), make_metadata(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::CapacityExceeded));
    }

    #[tokio::test]
    async fn join_unauthorized_with_wrong_cap() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        // 'c' is a valid hex digit distinct from receiver 'a' and sender 'b'.
        let err = reg
            .join(&id, &make_hash('c'), make_metadata())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[tokio::test]
    async fn join_unknown_session() {
        let reg = fresh_registry();
        let err = reg
            .join(&make_id('1'), &make_hash('b'), make_metadata())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SessionNotFound));
    }

    #[tokio::test]
    async fn close_rejects_sender_cap() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        let err = reg.close(&id, &make_hash('b')).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[tokio::test]
    async fn duplicate_publish_is_noop() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        let recv = make_hash('a');

        let first = reg
            .publish_candidate(&id, &recv, make_candidate("10.0.0.1:9000"))
            .await
            .unwrap();
        // Same (kind, transport, addr) — even with different priority.
        let dup = CandidatePublish {
            priority: 200,
            ..make_candidate("10.0.0.1:9000")
        };
        let second = reg.publish_candidate(&id, &recv, dup).await.unwrap();
        assert_eq!(first.sequence, second.sequence);
        assert_eq!(first.priority, second.priority); // existing priority kept

        let seen = reg.poll_candidates(&id, &make_hash('b'), 0).await.unwrap();
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn publish_enforces_candidate_cap() {
        let cfg = RegistryConfig {
            max_candidates_per_session: 2,
            ..RegistryConfig::default()
        };
        let reg = SessionRegistry::new(cfg);
        let id = make_id('1');
        register_default(&reg, &id).await;
        let recv = make_hash('a');

        reg.publish_candidate(&id, &recv, make_candidate("10.0.0.1:9000"))
            .await
            .unwrap();
        reg.publish_candidate(&id, &recv, make_candidate("10.0.0.2:9000"))
            .await
            .unwrap();
        let err = reg
            .publish_candidate(&id, &recv, make_candidate("10.0.0.3:9000"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn poll_since_filters() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        let recv = make_hash('a');
        let sender = make_hash('b');

        let c1 = reg
            .publish_candidate(&id, &recv, make_candidate("10.0.0.1:9000"))
            .await
            .unwrap();
        let c2 = reg
            .publish_candidate(&id, &recv, make_candidate("10.0.0.2:9000"))
            .await
            .unwrap();

        let all = reg.poll_candidates(&id, &sender, 0).await.unwrap();
        assert_eq!(all.len(), 2);

        let after_c1 = reg.poll_candidates(&id, &sender, c1.sequence).await.unwrap();
        assert_eq!(after_c1.len(), 1);
        assert_eq!(after_c1[0].sequence, c2.sequence);

        let after_c2 = reg.poll_candidates(&id, &sender, c2.sequence).await.unwrap();
        assert!(after_c2.is_empty());
    }

    #[tokio::test]
    async fn poll_empty_returns_immediately() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        let result = reg.poll_candidates(&id, &make_hash('b'), 0).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn closed_then_accessed_returns_session_closed() {
        let reg = fresh_registry();
        let id = make_id('1');
        register_default(&reg, &id).await;
        reg.close(&id, &make_hash('a')).await.unwrap();
        assert!(matches!(
            reg.join(&id, &make_hash('b'), make_metadata()).await,
            Err(Error::SessionClosed)
        ));
    }

    #[tokio::test]
    async fn unknown_session_returns_not_found_not_expired() {
        let reg = fresh_registry();
        let err = reg
            .poll_candidates(&make_id('c'), &make_hash('a'), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SessionNotFound));
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_expiry_distinct_from_not_found() {
        let cfg = RegistryConfig {
            default_ttl: Duration::from_secs(10),
            ..RegistryConfig::default()
        };
        let reg = SessionRegistry::new(cfg);
        let id = make_id('1');
        register_default(&reg, &id).await;

        tokio::time::advance(Duration::from_secs(11)).await;

        let err = reg
            .poll_candidates(&id, &make_hash('a'), 0)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SessionExpired));
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_refreshes_on_authenticated_access() {
        let cfg = RegistryConfig {
            default_ttl: Duration::from_secs(10),
            ..RegistryConfig::default()
        };
        let reg = SessionRegistry::new(cfg);
        let id = make_id('1');
        register_default(&reg, &id).await;

        // Step forward but not past TTL, then poll → refreshes.
        tokio::time::advance(Duration::from_secs(8)).await;
        reg.poll_candidates(&id, &make_hash('a'), 0).await.unwrap();

        // Another 8s — still alive because of refresh.
        tokio::time::advance(Duration::from_secs(8)).await;
        let result = reg.poll_candidates(&id, &make_hash('a'), 0).await;
        assert!(result.is_ok(), "got {:?}", result);
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_tombstones_expired_then_forgets() {
        let cfg = RegistryConfig {
            default_ttl: Duration::from_secs(10),
            ..RegistryConfig::default()
        };
        let reg = SessionRegistry::new(cfg);
        let id = make_id('1');
        register_default(&reg, &id).await;

        tokio::time::advance(Duration::from_secs(11)).await;
        reg.sweep_expired().await;
        // Tombstone visible — distinct error from not-found.
        assert!(matches!(
            reg.poll_candidates(&id, &make_hash('a'), 0).await,
            Err(Error::SessionExpired)
        ));

        // After tombstone forget_at, the slot is gone entirely.
        tokio::time::advance(Duration::from_secs(11)).await;
        reg.sweep_expired().await;
        assert!(matches!(
            reg.poll_candidates(&id, &make_hash('a'), 0).await,
            Err(Error::SessionNotFound)
        ));
    }
}
