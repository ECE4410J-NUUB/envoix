//! Room rendezvous transfer: pair two peers via the rendezvous broker using a
//! short code, then transfer over iroh with the existing data plane.
//!
//! The rendezvous only finds + authenticates the peers and exchanges their iroh
//! addresses; the file transfer itself is the unchanged `send_file_manual` /
//! `receive_one_authenticated` path, authenticated with a token derived from the
//! pairing key (so the data-plane SPAKE2 still runs and is channel-bound).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use envoix_error::CoreError;
use envoix_rendezvous_iroh::{build_endpoint, pair_in_room, split_code};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use crate::{
    BoundEndpoint, EventSink, PairingConfig, SessionConfig, SessionError, TransferSummary,
    bind_iroh_endpoint_with_relay, receive_with_auth_retries, send_file_to_endpoint_addr,
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

/// Wait until `bound` has learned at least one address - a direct addr, or its
/// relay home when a relay is configured - then return its full endpoint addr.
/// The addr carries the relay home, so a NATed peer can be dialed via the relay.
async fn ready_endpoint_addr(bound: &BoundEndpoint) -> EndpointAddr {
    for _ in 0..100 {
        let addr = bound.endpoint_addr();
        if !addr.is_empty() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bound.endpoint_addr()
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
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let (room_id, password) = split_code(code);
    let bound = bind_iroh_endpoint_with_relay(listen_addr, &config.identity, &config.relay).await?;
    let my_addr = ready_endpoint_addr(&bound).await;

    let rdz = rendezvous_endpoint(&config.relay).await?;
    let pairing = pair_in_room(&rdz, broker, room_id, password, &my_addr)
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;

    // Accept with retries: a stray or wrong-token dial must not kill the
    // transfer before the legitimate sender connects.
    receive_with_auth_retries(
        bound,
        output_dir,
        with_room_token(config, pairing.token),
        events,
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
    let (room_id, password) = split_code(code);
    let rdz = rendezvous_endpoint(&config.relay).await?;
    // The receiver ignores the sender's payload (the sender only dials), so any
    // valid endpoint address works as a placeholder.
    let placeholder = rdz.addr();

    let pairing = pair_in_room(&rdz, broker, room_id, password, &placeholder)
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;

    send_file_to_endpoint_addr(
        pairing.peer,
        file_path,
        resume,
        with_room_token(config, pairing.token),
        events,
    )
    .await
}
