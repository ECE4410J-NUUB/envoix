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
use envoix_protocol::PeerDescriptor;
use envoix_rendezvous_iroh::{build_endpoint, pair_in_room, split_code};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use crate::{
    BoundEndpoint, EventSink, PairingConfig, SessionConfig, SessionError, TransferSummary,
    bind_iroh_endpoint, receive_with_auth_retries, send_file_manual,
};

/// An ephemeral iroh endpoint used only to reach the rendezvous broker.
async fn rendezvous_endpoint() -> Result<Endpoint, SessionError> {
    build_endpoint(
        "0.0.0.0:0".parse().expect("valid addr"),
        SecretKey::generate(),
    )
    .await
    .map_err(|error| CoreError::Transport(error.to_string()))
}

/// Wait until `bound` has a direct address, then return its descriptor.
async fn ready_descriptor(bound: &BoundEndpoint) -> Result<PeerDescriptor, SessionError> {
    for _ in 0..100 {
        if !bound.direct_addrs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bound.peer_descriptor()
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
    let bound = bind_iroh_endpoint(listen_addr, &config.identity).await?;
    let my_descriptor = ready_descriptor(&bound).await?;

    let rdz = rendezvous_endpoint().await?;
    let pairing = pair_in_room(&rdz, broker, room_id, password, &my_descriptor)
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
    let rdz = rendezvous_endpoint().await?;
    // The receiver ignores the sender's payload (the sender only dials), so send
    // a placeholder instead of waiting for this endpoint to learn an address.
    let placeholder = PeerDescriptor::new(
        rdz.id().to_string(),
        vec!["0.0.0.0:0".parse::<SocketAddr>().expect("valid addr")],
    )?;

    let pairing = pair_in_room(&rdz, broker, room_id, password, &placeholder)
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;

    send_file_manual(
        pairing.peer,
        file_path,
        resume,
        with_room_token(config, pairing.token),
        events,
    )
    .await
}
