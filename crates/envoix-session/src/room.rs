//! Room rendezvous transfer: pair two peers via the rendezvous broker using a
//! short code, then transfer over iroh with the existing data plane.
//!
//! The rendezvous only finds + authenticates the peers and exchanges their iroh
//! addresses; the file transfer itself is the unchanged `send_file_manual` /
//! `receive_one_authenticated` path, authenticated with a token derived from the
//! pairing key (so the data-plane SPAKE2 still runs and is channel-bound).

use std::path::PathBuf;
use std::time::Duration;

use envoix_error::CoreError;
use envoix_rendezvous_iroh::{RoomPairing, build_endpoint, drive_pairing, join_room, split_code};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use crate::{
    BindAddrs, BoundEndpoint, EventSink, PairingConfig, SessionConfig, SessionError,
    TransferCancelToken, TransferSummary, bind_iroh_endpoint_with_relay,
    receive_with_auth_retries_with_cancel, send_file_to_endpoint_addr_with_cancel,
};

/// An ephemeral iroh endpoint used only to reach the rendezvous broker, routed
/// through `relay` (a relay URL) when set so it can reach a NATed broker.
async fn rendezvous_endpoint(relay: &Option<String>) -> Result<Endpoint, SessionError> {
    build_endpoint(
        "0.0.0.0:0".parse().expect("valid addr"),
        SecretKey::generate(),
        crate::endpoint::relay_mode(relay)?,
    )
    .await
    .map_err(|error| CoreError::Transport(error.to_string()))
}

/// Wait until `bound` has learned an address to advertise, then return its full
/// endpoint addr. When a relay is configured we wait for the relay home to
/// register (not just any direct addr): direct addrs are learned instantly from
/// local sockets, but the relay home takes a round-trip, so returning on the
/// first direct addr would exchange a descriptor with no relay home - leaving a
/// peer that cannot reach us directly (true CGNAT) unable to dial us at all.
async fn ready_endpoint_addr(bound: &BoundEndpoint, want_relay: bool) -> EndpointAddr {
    for _ in 0..100 {
        let addr = bound.endpoint_addr();
        let ready = if want_relay {
            addr.relay_urls().next().is_some()
        } else {
            !addr.is_empty()
        };
        if ready {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Fell through the wait. If a relay was configured but its home never
    // registered (relay unreachable), we advertise a direct-only descriptor.
    // Warn rather than error: the peer may still reach us directly - but if it
    // needs the relay, the data-plane dial will fail later, so make it visible.
    let addr = bound.endpoint_addr();
    if want_relay && addr.relay_urls().next().is_none() {
        tracing::warn!(
            "relay configured but its home did not register in time; advertising a \
             direct-only address - a peer that cannot reach us directly may fail to connect"
        );
    }
    addr
}

/// Pair in a room, re-joining if the broker matched us with a stale dead peer.
/// `join_room` blocks until the broker matches us, so it never cuts an honest
/// wait short. Once matched, the SPAKE2 exchange with a live partner takes
/// milliseconds, so if it stalls past `EXCHANGE_TIMEOUT` the partner is a dead
/// peer left by an earlier run (iroh has not yet noticed its connection is gone).
/// We drop it and re-join - that failed match already consumed the dead peer, so
/// the next join reaches a live partner (or parks to wait for one).
async fn pair_in_room_retrying<T>(
    rdz: &Endpoint,
    broker: &EndpointAddr,
    room_id: &str,
    password: &str,
    mine: &T,
) -> Result<RoomPairing<T>, SessionError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    const ATTEMPTS: usize = 4;
    const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);
    let mut last: Option<SessionError> = None;
    for _ in 0..ATTEMPTS {
        let session = join_room(rdz, broker.clone(), room_id)
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        match tokio::time::timeout(EXCHANGE_TIMEOUT, drive_pairing(session, password, mine)).await {
            Ok(Ok(pairing)) => return Ok(pairing),
            Ok(Err(error)) => last = Some(CoreError::Transport(error.to_string())),
            Err(_) => last = Some(CoreError::Transport("rendezvous pairing stalled".into())),
        }
    }
    Err(last.expect("at least one attempt failed"))
}

/// Run the room pairing but abandon it - closing the rendezvous endpoint - if
/// cancellation is requested. `join_room` blocks until the broker matches a
/// partner (up to the room TTL) and that wait does not otherwise watch the
/// cancel token, so a Ctrl-C while waiting for a partner would hang; this lets
/// it exit promptly and cleanly instead. `rdz` is also closed on a pairing
/// error so it never drops without a graceful close.
async fn pair_or_cancel<T>(
    rdz: &Endpoint,
    broker: &EndpointAddr,
    room_id: &str,
    password: &str,
    mine: &T,
    cancel: &TransferCancelToken,
) -> Result<RoomPairing<T>, SessionError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let result = tokio::select! {
        result = pair_in_room_retrying(rdz, broker, room_id, password, mine) => result,
        _ = cancel.cancelled() => Err(CoreError::Transfer(crate::USER_INTERRUPT_MESSAGE.into())),
    };
    if result.is_err() {
        rdz.close().await;
    }
    result
}

/// Override the pairing config with the token derived from the room pairing.
fn with_room_token(config: SessionConfig, token: String) -> SessionConfig {
    SessionConfig {
        pairing: PairingConfig::Spake2SharedToken { token },
        ..config
    }
}

/// Receive a file by pairing in a room: bind the data endpoint, exchange its
/// descriptor with the sender over the broker (SPAKE2 with `code`), then accept
/// the transfer using the token derived from the pairing.
pub async fn receive_file_via_room(
    broker: EndpointAddr,
    code: &str,
    listen_addrs: impl Into<BindAddrs>,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    receive_file_via_room_with_cancel(
        broker,
        code,
        listen_addrs,
        output_dir,
        config,
        events,
        TransferCancelToken::new(),
    )
    .await
}

/// Like [`receive_file_via_room`], stopping on cancellation.
pub async fn receive_file_via_room_with_cancel(
    broker: EndpointAddr,
    code: &str,
    listen_addrs: impl Into<BindAddrs>,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let (room_id, password) = split_code(code);
    let bound = bind_iroh_endpoint_with_relay(
        listen_addrs,
        &config.identity,
        &config.relay,
        config.relay_only,
    )
    .await?;
    let my_addr = ready_endpoint_addr(&bound, config.relay.is_some()).await;

    let rdz = rendezvous_endpoint(&config.relay).await?;
    let pairing = match pair_or_cancel(&rdz, &broker, room_id, password, &my_addr, &cancel).await {
        Ok(pairing) => pairing,
        Err(error) => {
            // Pairing was cancelled or failed; close our data listener too so it
            // does not drop without a graceful close.
            bound.local_endpoint.close().await;
            return Err(error);
        }
    };
    // The rendezvous endpoint is only needed for the broker handshake; close it
    // so it does not linger (and log) while the data transfer runs.
    rdz.close().await;

    // Accept with retries: a stray or wrong-token dial must not kill the
    // transfer before the legitimate sender connects.
    receive_with_auth_retries_with_cancel(
        bound,
        output_dir,
        with_room_token(config, pairing.token),
        events,
        cancel,
    )
    .await
}

/// Send a file by pairing in a room: exchange descriptors with the receiver over
/// the broker (SPAKE2 with `code`), then dial the receiver and send using the
/// token derived from the pairing.
pub async fn send_file_via_room(
    broker: EndpointAddr,
    code: &str,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    send_file_via_room_with_cancel(
        broker,
        code,
        file_path,
        resume,
        config,
        events,
        TransferCancelToken::new(),
    )
    .await
}

/// Like [`send_file_via_room`], stopping on cancellation.
pub async fn send_file_via_room_with_cancel(
    broker: EndpointAddr,
    code: &str,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let (room_id, password) = split_code(code);
    let rdz = rendezvous_endpoint(&config.relay).await?;
    // The receiver ignores the sender's payload (the sender only dials), so any
    // valid endpoint address works as a placeholder.
    let placeholder = rdz.addr();

    let pairing = pair_or_cancel(&rdz, &broker, room_id, password, &placeholder, &cancel).await?;
    // The rendezvous endpoint is only needed for the broker handshake; close it
    // so it does not linger (and log) while the data transfer runs.
    rdz.close().await;

    send_file_to_endpoint_addr_with_cancel(
        pairing.peer,
        file_path,
        resume,
        with_room_token(config, pairing.token),
        events,
        cancel,
    )
    .await
}
