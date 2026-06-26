//! Session orchestration for transfer setup and concrete iroh wiring.

mod connection;
mod endpoint;
mod identity;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub use envoix_auth::{PairingConfig, authenticate_receiver, authenticate_sender};
use envoix_error::CoreError;
use envoix_protocol::{FrameConnection, PeerDescriptor};
pub use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferEvent, TransferSummary,
};
pub use envoix_types::TransferDirection;
use iroh::{Endpoint, EndpointAddr};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;

use connection::IrohFrameConnection;
pub use endpoint::BoundEndpoint;
use endpoint::{
    build_accept_endpoint, build_advertising_accept_endpoint, build_dial_endpoint,
    peer_addr_from_descriptor,
};
pub use identity::IdentityConfig;

const ALPN: &[u8] = b"envoix/1";
const MAX_AUTH_FAILURES: u32 = 50;
const MDNS_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Error type returned by session orchestration.
pub type SessionError = CoreError;

/// Runtime options used when wiring transports into the transfer engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Maximum chunk payload size sent by the transfer engine.
    pub chunk_size: usize,
    /// Pairing authentication required before any transfer frame.
    pub pairing: PairingConfig,
    /// iroh endpoint identity policy.
    pub identity: IdentityConfig,
}

/// Bind an iroh endpoint (listen addr) that can accept one incoming connection.
pub async fn bind_iroh_endpoint(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        local_endpoint: build_accept_endpoint(listen_addr, identity).await?,
    })
}

/// Bind an iroh endpoint (listen addr) and advertise it through iroh mDNS address lookup.
pub async fn bind_iroh_endpoint_enable_mdns(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        local_endpoint: build_advertising_accept_endpoint(listen_addr, identity).await?,
    })
}

/// Sends one file to a manually supplied peer descriptor.
pub async fn send_file_manual(
    peer: PeerDescriptor,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let local_endpoint = build_dial_endpoint(&config.identity).await?;
    let mut connection = dial(local_endpoint.clone(), &peer).await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        local_endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .send_file(&mut connection, file_path, resume, events.as_ref())
        .await;
    let _ = connection.close().await;
    local_endpoint.close().await;
    result
}

/// Sends one file to the first mDNS-discovered iroh endpoint that authenticates.
pub async fn send_file_enable_mdns(
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let local_endpoint = build_dial_endpoint(&config.identity).await?;
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .build(local_endpoint.id())
        .map_err(|error| CoreError::Discovery(error.to_string()))?;
    local_endpoint
        .address_lookup()
        .map_err(|error| CoreError::Discovery(error.to_string()))?
        .add(mdns.clone());

    let mut discoveries = mdns.subscribe().await;
    let deadline = tokio::time::Instant::now() + MDNS_DISCOVERY_TIMEOUT;
    let mut last_error = None;
    let mut events = events;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let Some(event) = tokio::time::timeout_at(deadline, discoveries.next())
            .await
            .map_err(|_| {
                CoreError::Discovery(format!(
                    "no iroh mDNS peers discovered within {} seconds",
                    MDNS_DISCOVERY_TIMEOUT.as_secs()
                ))
            })?
        else {
            break;
        };

        let DiscoveryEvent::Discovered {
            endpoint_info: discovered_peer,
            ..
        } = event
        else {
            continue;
        };
        if discovered_peer.endpoint_id == local_endpoint.id() {
            continue;
        }
        let peer_addr = discovered_peer.to_endpoint_addr();

        match send_file_to_peer_addr(
            local_endpoint.clone(),
            peer_addr,
            file_path.clone(),
            resume,
            config.clone(),
            events,
        )
        .await
        {
            Ok(summary) => {
                local_endpoint.close().await;
                return Ok(summary);
            }
            Err(error) => {
                last_error = Some(error);
                events = Box::new(NoopEventSink);
            }
        }
    }

    local_endpoint.close().await;
    Err(last_error.unwrap_or_else(|| {
        CoreError::Discovery(format!(
            "no iroh mDNS peers discovered within {} seconds",
            MDNS_DISCOVERY_TIMEOUT.as_secs()
        ))
    }))
}

/// Receives one file and reports the concrete peer descriptor before accepting.
pub async fn receive_file_with_bound_peer<F>(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    on_bound_peer: F,
) -> Result<TransferSummary, SessionError>
where
    F: FnOnce(PeerDescriptor) + Send,
{
    let bound_endpoint = bind_iroh_endpoint(listen_addr, &config.identity).await?;
    let peer = bound_endpoint.peer_descriptor()?;
    on_bound_peer(peer);
    receive_one_authenticated(bound_endpoint, output_dir, config, events).await
}

/// Receives one file on an already-bound endpoint.
pub async fn receive_one_authenticated(
    bound_endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = bound_endpoint.accept().await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_receiver(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        bound_endpoint.local_endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .receive_file(&mut connection, output_dir, events.as_ref())
        .await;
    let _ = connection.close().await;
    bound_endpoint.local_endpoint.close().await;
    result
}

/// Receives one file, ignoring failed pairing attempts until one peer authenticates.
pub async fn receive_with_auth_retries(
    bound_endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = accept_authenticated_with_retries(&bound_endpoint, &config).await?;
    let engine = TransferEngine::new(config.chunk_size);
    let result = engine
        .receive_file(&mut connection, output_dir, events.as_ref())
        .await;
    let _ = connection.close().await;
    bound_endpoint.local_endpoint.close().await;
    result
}

async fn accept_authenticated_with_retries(
    bound_endpoint: &BoundEndpoint,
    config: &SessionConfig,
) -> Result<IrohFrameConnection, SessionError> {
    let mut failures = 0_u32;
    loop {
        let mut connection = bound_endpoint.accept().await?;
        match authenticate_receiver(&mut connection, &config.pairing).await {
            Ok(()) => return Ok(connection),
            Err(_) => {
                let _ = connection.close().await;
                failures += 1;
                if failures >= MAX_AUTH_FAILURES {
                    return Err(CoreError::Protocol(format!(
                        "too many failed pairing attempts (threshold: {MAX_AUTH_FAILURES})"
                    )));
                }
            }
        }
    }
}

async fn dial(
    local_endpoint: Endpoint,
    peer: &PeerDescriptor,
) -> Result<IrohFrameConnection, SessionError> {
    let peer_addr = peer_addr_from_descriptor(peer)?;
    dial_peer_addr(local_endpoint, peer_addr).await
}

async fn dial_peer_addr(
    local_endpoint: Endpoint,
    peer_addr: EndpointAddr,
) -> Result<IrohFrameConnection, SessionError> {
    let connection = local_endpoint
        .connect(peer_addr, ALPN)
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    Ok(IrohFrameConnection {
        _local_endpoint: local_endpoint,
        connection,
        send,
        recv,
    })
}

async fn send_file_to_peer_addr(
    local_endpoint: Endpoint,
    peer_addr: EndpointAddr,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = dial_peer_addr(local_endpoint, peer_addr).await?;
    let engine = TransferEngine::new(config.chunk_size);
    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        return Err(error);
    }
    let result = engine
        .send_file(&mut connection, file_path, resume, events.as_ref())
        .await;
    let _ = connection.close().await;
    result
}
