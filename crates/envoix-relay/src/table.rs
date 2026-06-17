//! In-memory forwarding table: pairs two peers of a session by their
//! observed addresses and decides where each datagram is forwarded.
//!
//! Each session has a slot per role holding that peer's most recently seen
//! source address. A valid datagram records the sender's address in its
//! slot (so a NAT rebind is followed for free) and is forwarded to the
//! other role's slot. An idle sweep evicts pairs with no traffic within the
//! timeout; a per-session byte cap cuts a pair off mid-stream; a
//! session-count cap bounds memory.
//!
//! Pure logic, no sockets: [`on_datagram`](RelayTable::on_datagram)
//! returns where to forward; the binary performs the actual send. The
//! monthly quota (cross-session, persisted) lives in [`crate::quota`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::token::{RelayRole, RelaySessionId};

#[derive(Clone, Copy)]
pub struct RelayConfig {
    pub max_sessions: usize,
    pub max_bytes_per_session: u64,
    pub idle_timeout: Duration,
}

impl Default for RelayConfig {
    /// Conservative "guest on a personal VPS" defaults.
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_bytes_per_session: 1_288_490_188, // ~1.2 GiB
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// What the binary should do with a datagram.
/// A peer's observed source address and the local relay port it arrived on.
/// The local port matters when the relay listens on a range: a reply must
/// leave the same port the peer is talking to, or its NAT drops it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    pub addr: SocketAddr,
    pub local_port: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ForwardOutcome {
    /// Forward the bare payload to this peer, out of its `local_port`.
    Forward(PeerEndpoint),
    /// The other peer has not sent yet - drop (it will retransmit).
    PeerUnknown,
    /// This pair exceeded `max_bytes_per_session` and was removed - drop.
    SessionCutOff,
    /// A new session past `max_sessions` - drop.
    CapacityExceeded,
}

struct RelayPair {
    receiver: Option<PeerEndpoint>,
    sender: Option<PeerEndpoint>,
    bytes_forwarded: u64,
    last_activity: Instant,
}

impl RelayPair {
    fn new(now: Instant) -> Self {
        Self {
            receiver: None,
            sender: None,
            bytes_forwarded: 0,
            last_activity: now,
        }
    }

    fn slot(&mut self, role: RelayRole) -> &mut Option<PeerEndpoint> {
        match role {
            RelayRole::Receiver => &mut self.receiver,
            RelayRole::Sender => &mut self.sender,
        }
    }

    fn peer(&self, role: RelayRole) -> Option<PeerEndpoint> {
        match role.peer() {
            RelayRole::Receiver => self.receiver,
            RelayRole::Sender => self.sender,
        }
    }
}

#[derive(Default)]
struct Counters {
    pairs_created_total: AtomicU64,
    datagrams_forwarded_total: AtomicU64,
    bytes_forwarded_total: AtomicU64,
    session_cap_cutoff_total: AtomicU64,
    rejected_capacity_total: AtomicU64,
}

/// Point-in-time stats (the binary merges these with the monthly quota
/// counter for the `relay` stats block).
pub struct RelayTableStats {
    pub active_pairs: u64,
    pub pairs_created_total: u64,
    pub datagrams_forwarded_total: u64,
    pub bytes_forwarded_total: u64,
    pub session_cap_cutoff_total: u64,
    pub rejected_capacity_total: u64,
}

pub struct RelayTable {
    pairs: RwLock<HashMap<RelaySessionId, RelayPair>>,
    config: RelayConfig,
    counters: Counters,
}

impl RelayTable {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            pairs: RwLock::new(HashMap::new()),
            config,
            counters: Counters::default(),
        }
    }

    /// Record a validated datagram and decide where to forward it.
    /// `payload_len` is the bare payload (what would cross the wire).
    pub async fn on_datagram(
        &self,
        session: RelaySessionId,
        role: RelayRole,
        from: SocketAddr,
        local_port: u16,
        payload_len: usize,
    ) -> ForwardOutcome {
        let now = Instant::now();
        let mut pairs = self.pairs.write().await;

        // Capacity check must precede insertion so the cap is a hard bound.
        if !pairs.contains_key(&session) && pairs.len() >= self.config.max_sessions {
            self.counters
                .rejected_capacity_total
                .fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::CapacityExceeded;
        }

        let is_new = !pairs.contains_key(&session);
        let pair = pairs.entry(session).or_insert_with(|| RelayPair::new(now));
        if is_new {
            self.counters
                .pairs_created_total
                .fetch_add(1, Ordering::Relaxed);
        }

        *pair.slot(role) = Some(PeerEndpoint {
            addr: from,
            local_port,
        });
        pair.last_activity = now;
        pair.bytes_forwarded = pair.bytes_forwarded.saturating_add(payload_len as u64);
        let over_cap = pair.bytes_forwarded > self.config.max_bytes_per_session;
        let peer = pair.peer(role);

        if over_cap {
            pairs.remove(&session);
            self.counters
                .session_cap_cutoff_total
                .fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::SessionCutOff;
        }

        match peer {
            Some(endpoint) => {
                self.counters
                    .datagrams_forwarded_total
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .bytes_forwarded_total
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
                ForwardOutcome::Forward(endpoint)
            }
            None => ForwardOutcome::PeerUnknown,
        }
    }

    /// Evict pairs idle longer than the configured timeout.
    pub async fn sweep_idle(&self) {
        let now = Instant::now();
        let timeout = self.config.idle_timeout;
        let mut pairs = self.pairs.write().await;
        pairs.retain(|_, p| now.duration_since(p.last_activity) < timeout);
    }

    pub async fn stats(&self) -> RelayTableStats {
        let active = self.pairs.read().await.len() as u64;
        RelayTableStats {
            active_pairs: active,
            pairs_created_total: self.counters.pairs_created_total.load(Ordering::Relaxed),
            datagrams_forwarded_total: self
                .counters
                .datagrams_forwarded_total
                .load(Ordering::Relaxed),
            bytes_forwarded_total: self.counters.bytes_forwarded_total.load(Ordering::Relaxed),
            session_cap_cutoff_total: self
                .counters
                .session_cap_cutoff_total
                .load(Ordering::Relaxed),
            rejected_capacity_total: self
                .counters
                .rejected_capacity_total
                .load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u8) -> RelaySessionId {
        RelaySessionId::from_bytes([n; 16])
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn table() -> RelayTable {
        RelayTable::new(RelayConfig::default())
    }

    /// Default local port for tests that don't exercise the port range.
    const P: u16 = 9104;

    fn fwd(a: SocketAddr, local_port: u16) -> ForwardOutcome {
        ForwardOutcome::Forward(PeerEndpoint { addr: a, local_port })
    }

    #[tokio::test]
    async fn pairs_two_peers_and_cross_forwards() {
        let t = table();
        let s = sid(1);
        let a = addr("1.2.3.4:5000"); // receiver
        let b = addr("9.8.7.6:6000"); // sender

        // Receiver sends first - sender unknown, drop.
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, P, 100).await,
            ForwardOutcome::PeerUnknown
        );
        // Sender sends - now receiver is known, forward to receiver.
        assert_eq!(
            t.on_datagram(s, RelayRole::Sender, b, P, 100).await,
            fwd(a, P)
        );
        // Receiver again - forward to sender.
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, P, 100).await,
            fwd(b, P)
        );
    }

    #[tokio::test]
    async fn forwards_out_each_peer_local_port() {
        // Peers arrive on DIFFERENT relay ports (a port range): each peer's
        // reply must leave the port that peer is talking to.
        let t = table();
        let s = sid(1);
        let a = addr("1.2.3.4:5000"); // receiver, on relay port 9101
        let b = addr("9.8.7.6:6000"); // sender, on relay port 9103

        t.on_datagram(s, RelayRole::Receiver, a, 9101, 100).await;
        // Sender's datagram forwards to the receiver, out the receiver's 9101.
        assert_eq!(
            t.on_datagram(s, RelayRole::Sender, b, 9103, 100).await,
            fwd(a, 9101)
        );
        // Receiver's datagram forwards to the sender, out the sender's 9103.
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, 9101, 100).await,
            fwd(b, 9103)
        );
    }

    #[tokio::test]
    async fn nat_rebind_updates_slot() {
        let t = table();
        let s = sid(1);
        let a1 = addr("1.2.3.4:5000");
        let a2 = addr("1.2.3.4:7777"); // receiver remapped
        let b = addr("9.8.7.6:6000");

        t.on_datagram(s, RelayRole::Receiver, a1, P, 100).await;
        t.on_datagram(s, RelayRole::Sender, b, P, 100).await;
        // Receiver reappears from a new address; sender's next packet must
        // now forward to the new address.
        t.on_datagram(s, RelayRole::Receiver, a2, P, 100).await;
        assert_eq!(
            t.on_datagram(s, RelayRole::Sender, b, P, 100).await,
            fwd(a2, P)
        );
    }

    #[tokio::test]
    async fn per_session_cap_cuts_off() {
        let cfg = RelayConfig {
            max_bytes_per_session: 1000,
            ..RelayConfig::default()
        };
        let t = RelayTable::new(cfg);
        let s = sid(1);
        let a = addr("1.2.3.4:5000");
        let b = addr("9.8.7.6:6000");
        t.on_datagram(s, RelayRole::Sender, b, P, 0).await; // register sender

        // 600 + 600 = 1200 > 1000 -> second one cuts off.
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, P, 600).await,
            fwd(b, P)
        );
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, P, 600).await,
            ForwardOutcome::SessionCutOff
        );
        // Pair was removed: a fresh datagram starts a new pair (peer
        // unknown again).
        assert_eq!(
            t.on_datagram(s, RelayRole::Receiver, a, P, 10).await,
            ForwardOutcome::PeerUnknown
        );
    }

    #[tokio::test]
    async fn capacity_cap_rejects_new_sessions() {
        let cfg = RelayConfig {
            max_sessions: 2,
            ..RelayConfig::default()
        };
        let t = RelayTable::new(cfg);
        t.on_datagram(sid(1), RelayRole::Receiver, addr("1.1.1.1:1"), P, 10)
            .await;
        t.on_datagram(sid(2), RelayRole::Receiver, addr("2.2.2.2:2"), P, 10)
            .await;
        assert_eq!(
            t.on_datagram(sid(3), RelayRole::Receiver, addr("3.3.3.3:3"), P, 10)
                .await,
            ForwardOutcome::CapacityExceeded
        );
        // Existing sessions still work.
        assert_eq!(
            t.on_datagram(sid(1), RelayRole::Receiver, addr("1.1.1.1:1"), P, 10)
                .await,
            ForwardOutcome::PeerUnknown
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sweep_evicts() {
        let cfg = RelayConfig {
            idle_timeout: Duration::from_secs(10),
            ..RelayConfig::default()
        };
        let t = RelayTable::new(cfg);
        let s = sid(1);
        t.on_datagram(s, RelayRole::Receiver, addr("1.2.3.4:5000"), P, 100)
            .await;
        assert_eq!(t.stats().await.active_pairs, 1);

        tokio::time::advance(Duration::from_secs(11)).await;
        t.sweep_idle().await;
        assert_eq!(t.stats().await.active_pairs, 0);
    }

    #[tokio::test]
    async fn counters_track_activity() {
        let t = table();
        let s = sid(1);
        let a = addr("1.2.3.4:5000");
        let b = addr("9.8.7.6:6000");
        t.on_datagram(s, RelayRole::Sender, b, P, 0).await;
        t.on_datagram(s, RelayRole::Receiver, a, P, 500).await; // forwards to b
        t.on_datagram(s, RelayRole::Sender, b, P, 300).await; // forwards to a

        let st = t.stats().await;
        assert_eq!(st.pairs_created_total, 1);
        assert_eq!(st.datagrams_forwarded_total, 2);
        assert_eq!(st.bytes_forwarded_total, 800);
        assert_eq!(st.active_pairs, 1);
    }
}
