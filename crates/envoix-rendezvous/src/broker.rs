//! The room registry: match two peers by room id, then blindly relay bytes.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;

use crate::RendezvousError;
use crate::peer::PeerConn;
use crate::protocol::{Join, Paired, Role};

/// How long a first peer waits in a room for its partner.
const DEFAULT_ROOM_TTL: Duration = Duration::from_secs(300);
/// Hard cap on a single relay session, so a stalled peer can't pin resources.
const RELAY_TTL: Duration = Duration::from_secs(120);
/// Cap on the wait for a peer's first control frame (its Join). A peer that
/// connects and opens a stream but never sends Join is not in any room, so the
/// room TTL cannot reclaim it - without this it would pin a connection slot.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Grace period to wait for peers to close after relaying, so buffered data is
/// delivered before the transports are dropped.
const CLOSE_GRACE: Duration = Duration::from_secs(10);
/// Reject a join whose room id is longer than this; room ids are short codes.
const MAX_ROOM_ID_LEN: usize = 128;
/// Cap on concurrently waiting (unpaired) rooms, to bound memory under abuse.
const MAX_WAITING_ROOMS: usize = 4096;

/// A peer parked in a room, waiting for a partner. `ready` lets the matching
/// peer's task signal this peer's task to return once it has taken over.
struct Waiter {
    conn: PeerConn,
    ready: oneshot::Sender<()>,
    id: u64,
}

/// Matches peers into rooms. Cheap to share behind an `Arc` across connections.
pub struct RoomRegistry {
    waiting: Mutex<HashMap<String, Waiter>>,
    ttl: Duration,
    /// Monotonic id stamped on each parked waiter, so a timed-out waiter only
    /// removes its own map entry, never a newer waiter that reused the room id.
    next_id: AtomicU64,
}

impl RoomRegistry {
    /// A registry with the default room time-to-live.
    pub fn new() -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            ttl: DEFAULT_ROOM_TTL,
            next_id: AtomicU64::new(0),
        }
    }

    /// A registry with a custom room time-to-live (mostly for tests).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            ttl,
            next_id: AtomicU64::new(0),
        }
    }

    /// Serve one peer connection: read its [`Join`], then either park it as the
    /// first peer of a room or, if a peer already waits there, pair the two and
    /// relay between them. The first peer's task returns once the second takes
    /// over the relay; the second peer's task drives it.
    pub async fn serve(&self, mut conn: PeerConn) -> Result<(), RendezvousError> {
        let Join { room_id } = tokio::time::timeout(JOIN_TIMEOUT, conn.read_control())
            .await
            .map_err(|_| RendezvousError::Rejected("no join received within timeout"))??;
        if room_id.is_empty() || room_id.len() > MAX_ROOM_ID_LEN {
            return Err(RendezvousError::Rejected("room id length out of range"));
        }
        tracing::debug!(room = %room_id, "join");

        // Decide under the lock (no await held), then act once it's released, so
        // two peers arriving at once can't both park and miss each other.
        enum Decision {
            Matched(Waiter, PeerConn),
            Parked(oneshot::Receiver<()>, u64),
            Rejected(&'static str),
        }
        let decision = {
            let mut waiting = self.waiting.lock().expect("registry mutex");
            match waiting.remove(&room_id) {
                Some(first) => Decision::Matched(first, conn),
                None if waiting.len() >= MAX_WAITING_ROOMS => {
                    Decision::Rejected("too many waiting rooms")
                }
                None => {
                    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                    let (ready_tx, ready_rx) = oneshot::channel();
                    waiting.insert(
                        room_id.clone(),
                        Waiter {
                            conn,
                            ready: ready_tx,
                            id,
                        },
                    );
                    tracing::debug!(room = %room_id, id, "parked (waiting for partner)");
                    Decision::Parked(ready_rx, id)
                }
            }
        };

        match decision {
            // We are the second peer; release the first's task and run the relay.
            Decision::Matched(first, conn) => {
                tracing::debug!(room = %room_id, "matched two peers");
                let _ = first.ready.send(());
                run_pair(first.conn, conn).await
            }
            // We are the first peer; wait for a partner, or expire.
            Decision::Parked(ready_rx, id) => {
                match tokio::time::timeout(self.ttl, ready_rx).await {
                    Ok(_) => Ok(()),
                    Err(_) => {
                        // Only drop our own waiter: a concurrent match + re-park can
                        // have replaced us with a newer waiter under the same room id.
                        let mut waiting = self.waiting.lock().expect("registry mutex");
                        if waiting.get(&room_id).is_some_and(|w| w.id == id) {
                            waiting.remove(&room_id);
                        }
                        tracing::debug!(room = %room_id, id, "expired (no partner within ttl)");
                        Err(RendezvousError::Expired)
                    }
                }
            }
            Decision::Rejected(reason) => {
                tracing::debug!(room = %room_id, reason, "rejected");
                Err(RendezvousError::Rejected(reason))
            }
        }
    }
}

impl Default for RoomRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Tell each peer its role, then relay raw bytes both ways until both sides
/// close (or the relay deadline elapses). The keep-alive handles are held for
/// the whole relay so the transports stay open.
async fn run_pair(initiator: PeerConn, responder: PeerConn) -> Result<(), RendezvousError> {
    let (mut iw, mut ir, i_close) = initiator.into_parts();
    let (mut rw, mut rr, r_close) = responder.into_parts();

    crate::io::write_framed(
        &mut iw,
        &Paired {
            role: Role::Initiator,
        },
    )
    .await?;
    crate::io::write_framed(
        &mut rw,
        &Paired {
            role: Role::Responder,
        },
    )
    .await?;

    // Blind relay: the SPAKE2 + sealed-descriptor traffic flows through
    // opaquely. When one side finishes (EOF), propagate it as a clean shutdown
    // of the other side's writer so the peer drains all data, rather than seeing
    // the connection torn down mid-read.
    let _ = tokio::time::timeout(RELAY_TTL, async {
        tokio::join!(
            async {
                let _ = tokio::io::copy(&mut ir, &mut rw).await;
                let _ = rw.shutdown().await;
            },
            async {
                let _ = tokio::io::copy(&mut rr, &mut iw).await;
                let _ = iw.shutdown().await;
            },
        )
    })
    .await;

    // Keep both transports open until the peers close them (after draining), so
    // their last buffered bytes are delivered before we drop the connections.
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        tokio::join!(i_close.wait_closed(), r_close.wait_closed())
    })
    .await;
    Ok(())
}
