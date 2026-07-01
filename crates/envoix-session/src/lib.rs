//! Session orchestration for transfer setup and concrete iroh wiring.

mod connection;
mod endpoint;
mod identity;
mod room;

use std::path::PathBuf;
use std::time::Duration;

pub use envoix_auth::{PairingConfig, authenticate_receiver, authenticate_sender};
use envoix_error::CoreError;
use envoix_protocol::{FrameConnection, PeerDescriptor};
pub use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferCancelToken, TransferEvent,
    TransferSummary, USER_INTERRUPT_MESSAGE,
};
pub use envoix_types::TransferDirection;
use iroh::{Endpoint, EndpointAddr};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;

use connection::IrohFrameConnection;
pub use endpoint::{BindAddrs, BoundEndpoint, parse_broker_addr};
use endpoint::{
    build_accept_endpoint, build_advertising_accept_endpoint, build_dial_endpoint,
    peer_addr_from_descriptor,
};
pub use identity::IdentityConfig;
pub use room::{
    receive_file_via_room, receive_file_via_room_with_cancel, send_file_via_room,
    send_file_via_room_with_cancel,
};

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
    /// Optional relay URL for WAN/NAT reachability. `None` keeps endpoints
    /// LAN/direct only (unchanged behavior); `Some(url)` routes through a relay.
    pub relay: Option<String>,
}

/// Bind an iroh endpoint (listen addr) that can accept one incoming connection.
pub async fn bind_iroh_endpoint(
    listen_addrs: impl Into<BindAddrs>,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    bind_iroh_endpoint_with_relay(listen_addrs, identity, &None).await
}

/// Like [`bind_iroh_endpoint`], but routes through `relay` (a relay URL) when
/// set, so the bound endpoint stays reachable from behind NAT.
pub(crate) async fn bind_iroh_endpoint_with_relay(
    listen_addrs: impl Into<BindAddrs>,
    identity: &IdentityConfig,
    relay: &Option<String>,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        local_endpoint: build_accept_endpoint(listen_addrs.into(), identity, relay).await?,
    })
}

/// Bind an iroh endpoint (listen addr) and advertise it through iroh mDNS address lookup.
pub async fn bind_iroh_endpoint_enable_mdns(
    listen_addrs: impl Into<BindAddrs>,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        local_endpoint: build_advertising_accept_endpoint(listen_addrs.into(), identity, &None)
            .await?,
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
    let cancel = TransferCancelToken::new();
    send_file_manual_with_cancel(peer, file_path, resume, config, events, cancel).await
}

/// Sends one file to a manually supplied peer descriptor, stopping on cancellation.
pub async fn send_file_manual_with_cancel(
    peer: PeerDescriptor,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let local_endpoint = build_dial_endpoint(&config.identity, &config.relay).await?;
    let mut connection = dial(local_endpoint.clone(), &peer).await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        local_endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .send_file_with_cancel(&mut connection, file_path, resume, events.as_ref(), &cancel)
        .await;
    let _ = connection.close().await;
    local_endpoint.close().await;
    result
}

/// Sends one file to a peer addressed by its full iroh `EndpointAddr` (which may
/// carry a relay home), dialing through the configured relay when set.
pub async fn send_file_to_endpoint_addr(
    peer_addr: EndpointAddr,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    send_file_to_endpoint_addr_with_cancel(
        peer_addr,
        file_path,
        resume,
        config,
        events,
        TransferCancelToken::new(),
    )
    .await
}

/// Like [`send_file_to_endpoint_addr`], stopping the data transfer on cancellation.
pub async fn send_file_to_endpoint_addr_with_cancel(
    peer_addr: EndpointAddr,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let local_endpoint = build_dial_endpoint(&config.identity, &config.relay).await?;
    let mut connection = match dial_peer_addr(local_endpoint.clone(), peer_addr).await {
        Ok(connection) => connection,
        Err(error) => {
            local_endpoint.close().await;
            return Err(error);
        }
    };
    let engine = TransferEngine::new(config.chunk_size);
    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        local_endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .send_file_with_cancel(&mut connection, file_path, resume, events.as_ref(), &cancel)
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
    let cancel = TransferCancelToken::new();
    send_file_enable_mdns_with_cancel(file_path, resume, config, events, cancel).await
}

/// Sends one file to the first mDNS-discovered iroh endpoint, stopping on cancellation.
pub async fn send_file_enable_mdns_with_cancel(
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let local_endpoint = build_dial_endpoint(&config.identity, &config.relay).await?;
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

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let event = tokio::select! {
            result = tokio::time::timeout_at(deadline, discoveries.next()) => {
                result.map_err(|_| {
                    CoreError::Discovery(format!(
                        "no iroh mDNS peers discovered within {} seconds",
                        MDNS_DISCOVERY_TIMEOUT.as_secs()
                    ))
                })?
            }
            () = cancel.cancelled() => {
                local_endpoint.close().await;
                return Err(interrupted_error());
            }
        };

        let Some(event) = event else {
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
            events.as_ref(),
            &cancel,
        )
        .await
        {
            Ok(summary) => {
                local_endpoint.close().await;
                return Ok(summary);
            }
            Err(error) => {
                events.on_event(TransferEvent::Failed {
                    direction: TransferDirection::Send,
                    reason: error.to_string(),
                });
                if cancel.is_cancelled() {
                    local_endpoint.close().await;
                    return Err(error);
                }
                last_error = Some(error);
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
    listen_addrs: impl Into<BindAddrs>,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    on_bound_peer: F,
) -> Result<TransferSummary, SessionError>
where
    F: FnOnce(PeerDescriptor) + Send,
{
    let cancel = TransferCancelToken::new();
    receive_file_with_bound_peer_with_cancel(
        listen_addrs,
        output_dir,
        config,
        events,
        on_bound_peer,
        cancel,
    )
    .await
}

/// Receives one file and stops while waiting or transferring if cancelled.
pub async fn receive_file_with_bound_peer_with_cancel<F>(
    listen_addrs: impl Into<BindAddrs>,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    on_bound_peer: F,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError>
where
    F: FnOnce(PeerDescriptor) + Send,
{
    let bound_endpoint =
        bind_iroh_endpoint_with_relay(listen_addrs, &config.identity, &config.relay).await?;
    let peer = bound_endpoint.peer_descriptor()?;
    on_bound_peer(peer);
    receive_one_authenticated_with_cancel(bound_endpoint, output_dir, config, events, cancel).await
}

/// Receives one file on an already-bound endpoint.
pub async fn receive_one_authenticated(
    bound_endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let cancel = TransferCancelToken::new();
    receive_one_authenticated_with_cancel(bound_endpoint, output_dir, config, events, cancel).await
}

/// Receives one file on an already-bound endpoint, stopping on cancellation.
pub async fn receive_one_authenticated_with_cancel(
    bound_endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let mut connection = match accept_or_cancel(&bound_endpoint, &cancel).await {
        Ok(connection) => connection,
        Err(error) => {
            bound_endpoint.local_endpoint.close().await;
            return Err(error);
        }
    };
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_receiver(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        bound_endpoint.local_endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .receive_file_with_cancel(&mut connection, output_dir, events.as_ref(), &cancel)
        .await;
    close_after_receive(&mut connection, &result).await;
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
    let cancel = TransferCancelToken::new();
    receive_with_auth_retries_with_cancel(bound_endpoint, output_dir, config, events, cancel).await
}

/// Receives one file with pairing retries, stopping on cancellation.
pub async fn receive_with_auth_retries_with_cancel(
    bound_endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    cancel: TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let engine = TransferEngine::new(config.chunk_size);

    let result = loop {
        let mut connection =
            match accept_authenticated_with_retries(&bound_endpoint, &config, &cancel).await {
                Ok(connection) => connection,
                Err(error) => break Err(error),
            };
        let attempt = engine
            .receive_file_with_cancel(
                &mut connection,
                output_dir.clone(),
                events.as_ref(),
                &cancel,
            )
            .await;
        close_after_receive(&mut connection, &attempt).await;

        match attempt {
            Ok(summary) => break Ok(summary),
            Err(error) if cancel.is_cancelled() => break Err(error),
            Err(error) => {
                events.on_event(TransferEvent::Failed {
                    direction: TransferDirection::Receive,
                    reason: error.to_string(),
                });
            }
        }
    };

    bound_endpoint.local_endpoint.close().await;
    result
}

/// Close the data connection after a receive. On success the receiver sent the
/// last frame (`CompleteAck`), so it waits for the sender to close - closing
/// first would race that close against the sender reading the ack. On failure
/// it closes actively, since there is no ack in flight to protect.
async fn close_after_receive(
    connection: &mut IrohFrameConnection,
    result: &Result<TransferSummary, SessionError>,
) {
    match result {
        Ok(_) => connection.await_peer_close().await,
        Err(_) => {
            let _ = connection.close().await;
        }
    }
}

async fn accept_authenticated_with_retries(
    bound_endpoint: &BoundEndpoint,
    config: &SessionConfig,
    cancel: &TransferCancelToken,
) -> Result<IrohFrameConnection, SessionError> {
    let mut failures = 0_u32;
    loop {
        let mut connection = accept_or_cancel(bound_endpoint, cancel).await?;
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
    events: &dyn EventSink,
    cancel: &TransferCancelToken,
) -> Result<TransferSummary, SessionError> {
    let mut connection = dial_peer_addr(local_endpoint, peer_addr).await?;
    let engine = TransferEngine::new(config.chunk_size);
    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        return Err(error);
    }
    let result = engine
        .send_file_with_cancel(&mut connection, file_path, resume, events, cancel)
        .await;
    let _ = connection.close().await;
    result
}

async fn accept_or_cancel(
    bound_endpoint: &BoundEndpoint,
    cancel: &TransferCancelToken,
) -> Result<IrohFrameConnection, SessionError> {
    tokio::select! {
        result = bound_endpoint.accept() => result,
        () = cancel.cancelled() => Err(interrupted_error()),
    }
}

fn interrupted_error() -> SessionError {
    CoreError::Transfer(USER_INTERRUPT_MESSAGE.into())
}
