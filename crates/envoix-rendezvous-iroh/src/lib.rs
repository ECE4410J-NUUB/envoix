//! iroh transport for the room rendezvous: an iroh endpoint accepts pairing
//! connections, wraps each as a [`PeerConn`], and serves it through the
//! [`RoomRegistry`]. Clients reach the broker by its (hard-coded) endpoint id.
//!
//! The broker crate (`envoix-rendezvous`) stays transport-agnostic; this is the
//! only place that knows about iroh.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, Incoming, RecvStream, RelayMode, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, RelayMap, RelayUrl, SecretKey, TransportAddr};

use envoix_rendezvous::{
    CloseWaiter, Join, Paired, PeerConn, Role, RoomRegistry, read_framed, write_framed,
};

mod code;
pub use code::{generate_code, split_code};

/// BLAKE3 KDF context separating the data-plane token from any other use of K.
const DATA_TOKEN_CONTEXT: &str = "envoix rendezvous data-plane token v1";

/// AEAD associated data binding a sealed descriptor to the sender's role, so a
/// relay cannot reflect one peer's ciphertext back as the other's.
const INITIATOR_SEAL_AAD: &[u8] = b"envoix-pairing seal initiator v1";
const RESPONDER_SEAL_AAD: &[u8] = b"envoix-pairing seal responder v1";

/// Cap on the post-exchange graceful close, so a misbehaving peer or broker
/// cannot hang the pairing after the descriptors are already exchanged.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Outcome of a successful room pairing.
pub struct RoomPairing<T> {
    /// The peer's payload (for Envoix, its iroh `PeerDescriptor` to dial).
    pub peer: T,
    /// A strong shared token derived from the SPAKE2 key, so the existing
    /// data-plane pairing (`envoix-auth` SPAKE2 over the iroh connection) can
    /// run unchanged - both peers derive the same one.
    pub token: String,
}

/// Lets the broker wait for an iroh peer to close before dropping the relay.
struct IrohClose(Connection);

impl CloseWaiter for IrohClose {
    fn wait_closed(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            self.0.closed().await;
        })
    }
}

/// ALPN for the rendezvous protocol (distinct from the data-plane `envoix/1`).
pub const RENDEZVOUS_ALPN: &[u8] = b"envoix-rendezvous/1";

/// Bind an iroh endpoint that speaks the rendezvous ALPN. Pass
/// [`RelayMode::Disabled`] for LAN/direct, or a custom relay mode (see
/// [`relay_mode_from_url`]) for WAN reachability through a relay.
pub async fn build_endpoint(
    bind: SocketAddr,
    secret_key: SecretKey,
    relay: RelayMode,
) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(relay)
        .clear_address_lookup()
        .alpns(vec![RENDEZVOUS_ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr(bind)
        .context("invalid bind address")?
        .bind()
        .await
        .context("failed to bind iroh endpoint")
}

/// Build a [`RelayMode`] from an optional relay URL: `None` disables relays
/// (LAN/direct only); `Some(url)` routes through that single custom relay so
/// peers behind NAT can reach the broker and each other.
pub fn relay_mode_from_url(url: Option<&str>) -> Result<RelayMode> {
    match url {
        None => Ok(RelayMode::Disabled),
        Some(url) => {
            let url: RelayUrl = url.parse().context("invalid relay url")?;
            Ok(RelayMode::Custom(RelayMap::from(url)))
        }
    }
}

/// The endpoint's connectable address (id + direct socket addresses).
pub fn endpoint_addr(endpoint: &Endpoint) -> EndpointAddr {
    EndpointAddr::from_parts(
        endpoint.id(),
        endpoint.addr().ip_addrs().copied().map(TransportAddr::Ip),
    )
}

/// Cap on connections served at once, so a flood cannot exhaust the broker.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Accept pairing connections forever, serving each through `registry`, up to
/// MAX_CONCURRENT_CONNECTIONS at a time (excess incoming connections are dropped).
pub async fn serve_endpoint(endpoint: Endpoint, registry: Arc<RoomRegistry>) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tracing::warn!("rendezvous connection limit reached; dropping incoming");
            continue;
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_incoming(incoming, &registry).await {
                tracing::debug!(%error, "rendezvous connection ended");
            }
        });
    }
    Ok(())
}

async fn serve_incoming(incoming: Incoming, registry: &RoomRegistry) -> Result<()> {
    let connection = incoming.await?;
    let (send, recv) = connection.accept_bi().await?;
    // The Connection is the close-waiter: the broker keeps it open until the
    // peer closes, then drops it.
    let conn = PeerConn::new(send, recv, IrohClose(connection));
    registry.serve(conn).await?;
    Ok(())
}

/// A peer's live session with the broker after joining a room. The caller drives
/// the end-to-end pairing over `send`/`recv`; `connection` keeps the streams
/// alive and must be held for the duration.
pub struct BrokerSession {
    pub connection: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub role: Role,
}

/// Connect to the broker, open the pairing stream, join `room_id`, and return
/// the streams + assigned role to drive the pairing over.
pub async fn join_room(
    endpoint: &Endpoint,
    broker: EndpointAddr,
    room_id: &str,
) -> Result<BrokerSession> {
    let connection = endpoint.connect(broker, RENDEZVOUS_ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_framed(
        &mut send,
        &Join {
            room_id: room_id.to_string(),
        },
    )
    .await?;
    let paired: Paired = read_framed(&mut recv).await?;
    Ok(BrokerSession {
        connection,
        send,
        recv,
        role: paired.role,
    })
}

/// Pair with a peer in `room_id` over the broker: run SPAKE2 with `password`,
/// then swap payloads sealed under the derived key. Returns the peer's payload
/// (for Envoix, each side passes its iroh `PeerDescriptor`, so the result is the
/// address to dial). The broker only relays ciphertext - it can neither read
/// nor forge the exchanged payload.
pub async fn pair_in_room<T>(
    endpoint: &Endpoint,
    broker: EndpointAddr,
    room_id: &str,
    password: &str,
    mine: &T,
) -> Result<RoomPairing<T>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let session = join_room(endpoint, broker, room_id).await?;
    drive_pairing(session, password, mine).await
}

/// Drive the end-to-end pairing over an already-joined [`BrokerSession`]: run
/// SPAKE2 with `password`, then swap payloads sealed under the derived key.
/// Split from [`pair_in_room`] so a caller can time-box just this phase - with a
/// live partner it completes in milliseconds, so a stall means the broker
/// matched us with a stale/dead peer and the caller should re-join.
pub async fn drive_pairing<T>(
    session: BrokerSession,
    password: &str,
    mine: &T,
) -> Result<RoomPairing<T>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    use envoix_pairing::{
        Confirm, PakeResponse, PakeStart, initiator_start, open_json, responder_respond, seal_json,
    };

    let BrokerSession {
        connection,
        mut send,
        mut recv,
        role,
    } = session;

    let key = match role {
        Role::Initiator => {
            let (pending, start) = initiator_start(password)?;
            write_framed(&mut send, &start).await?;
            let response: PakeResponse = read_framed(&mut recv).await?;
            let (confirming, confirm) = pending.finish(&response)?;
            write_framed(&mut send, &confirm).await?;
            let responder_confirm: Confirm = read_framed(&mut recv).await?;
            confirming.verify(&responder_confirm)?
        }
        Role::Responder => {
            let start: PakeStart = read_framed(&mut recv).await?;
            let (confirming, response) = responder_respond(password, &start)?;
            write_framed(&mut send, &response).await?;
            let initiator_confirm: Confirm = read_framed(&mut recv).await?;
            let (key, confirm) = confirming.verify(&initiator_confirm)?;
            write_framed(&mut send, &confirm).await?;
            key
        }
    };

    // Bind each sealed descriptor to the sender's role (AEAD aad); we seal with
    // our role and open with the peer's, so a reflected ciphertext fails to open.
    let (my_aad, peer_aad): (&[u8], &[u8]) = match role {
        Role::Initiator => (INITIATOR_SEAL_AAD, RESPONDER_SEAL_AAD),
        Role::Responder => (RESPONDER_SEAL_AAD, INITIATOR_SEAL_AAD),
    };
    write_framed(&mut send, &seal_json(key.key(), my_aad, mine)?).await?;
    let sealed: Vec<u8> = read_framed(&mut recv).await?;
    let peer: T = open_json(key.key(), peer_aad, &sealed)?;

    // Derive a strong data-plane token from K (both peers get the same one).
    let token = hex(&blake3::derive_key(DATA_TOKEN_CONTEXT, key.key()));

    // Graceful close: finish + wait for the broker to ack our FIN (so it is
    // delivered through the relay), then drain our recv to EOF before dropping.
    // Bounded by CLOSE_TIMEOUT so a stalled peer cannot hang a done pairing.
    let _ = send.finish();
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        let _ = send.stopped().await;
        let _ = recv.read_to_end(1024).await;
    })
    .await;
    drop(connection);

    Ok(RoomPairing { peer, token })
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
