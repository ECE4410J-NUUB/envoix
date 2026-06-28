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
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};

use envoix_rendezvous::{
    CloseWaiter, Join, Paired, PeerConn, Role, RoomRegistry, read_framed, write_framed,
};

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

/// Bind an iroh endpoint that speaks the rendezvous ALPN. Relay is disabled for
/// now (LAN/direct, matching the current client build); flip to a relay mode
/// for WAN reachability.
pub async fn build_endpoint(bind: SocketAddr, secret_key: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![RENDEZVOUS_ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr(bind)
        .context("invalid bind address")?
        .bind()
        .await
        .context("failed to bind iroh endpoint")
}

/// The endpoint's connectable address (id + direct socket addresses).
pub fn endpoint_addr(endpoint: &Endpoint) -> EndpointAddr {
    EndpointAddr::from_parts(
        endpoint.id(),
        endpoint.addr().ip_addrs().copied().map(TransportAddr::Ip),
    )
}

/// Accept pairing connections forever, serving each through `registry`.
pub async fn serve_endpoint(endpoint: Endpoint, registry: Arc<RoomRegistry>) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
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
    write_framed(&mut send, &Join { room_id: room_id.to_string() }).await?;
    let paired: Paired = read_framed(&mut recv).await?;
    Ok(BrokerSession { connection, send, recv, role: paired.role })
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
) -> Result<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    use envoix_pairing::{
        Confirm, PakeResponse, PakeStart, initiator_start, open_json, responder_respond, seal_json,
    };

    let BrokerSession { connection, mut send, mut recv, role } =
        join_room(endpoint, broker, room_id).await?;

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

    write_framed(&mut send, &seal_json(key.key(), mine)?).await?;
    let sealed: Vec<u8> = read_framed(&mut recv).await?;
    let peer: T = open_json(key.key(), &sealed)?;

    // Graceful close: finish + wait for the broker to ack our FIN (so it is
    // delivered through the relay), then drain our recv to EOF before dropping.
    // No more data is expected after the descriptor, so a tiny cap is fine.
    let _ = send.finish();
    let _ = send.stopped().await;
    let _ = recv.read_to_end(1024).await;
    drop(connection);

    Ok(peer)
}
