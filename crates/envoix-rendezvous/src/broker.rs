//! The room registry: match two peers by room id, then blindly relay bytes.

use std::collections::HashMap;
use std::sync::Mutex;
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
}

/// Matches peers into rooms. Cheap to share behind an `Arc` across connections.
pub struct RoomRegistry {
    waiting: Mutex<HashMap<String, Waiter>>,
    ttl: Duration,
}

impl RoomRegistry {
    /// A registry with the default room time-to-live.
    pub fn new() -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            ttl: DEFAULT_ROOM_TTL,
        }
    }

    /// A registry with a custom room time-to-live (mostly for tests).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Serve one peer connection: read its [`Join`], then either park it as the
    /// first peer of a room or, if a peer already waits there, pair the two and
    /// relay between them. The first peer's task returns once the second takes
    /// over the relay; the second peer's task drives it.
    pub async fn serve(&self, mut conn: PeerConn) -> Result<(), RendezvousError> {
        let Join { room_id } = conn.read_control().await?;
        if room_id.is_empty() || room_id.len() > MAX_ROOM_ID_LEN {
            return Err(RendezvousError::Rejected("room id length out of range"));
        }

        // Decide under the lock (no await held), then act once it's released, so
        // two peers arriving at once can't both park and miss each other.
        enum Decision {
            Matched(Waiter, PeerConn),
            Parked(oneshot::Receiver<()>),
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
                    let (ready_tx, ready_rx) = oneshot::channel();
                    waiting.insert(
                        room_id.clone(),
                        Waiter {
                            conn,
                            ready: ready_tx,
                        },
                    );
                    Decision::Parked(ready_rx)
                }
            }
        };

        match decision {
            // We are the second peer; release the first's task and run the relay.
            Decision::Matched(first, conn) => {
                let _ = first.ready.send(());
                run_pair(first.conn, conn).await
            }
            // We are the first peer; wait for a partner, or expire.
            Decision::Parked(ready_rx) => match tokio::time::timeout(self.ttl, ready_rx).await {
                Ok(_) => Ok(()),
                Err(_) => {
                    self.waiting
                        .lock()
                        .expect("registry mutex")
                        .remove(&room_id);
                    Err(RendezvousError::Expired)
                }
            },
            Decision::Rejected(reason) => Err(RendezvousError::Rejected(reason)),
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
