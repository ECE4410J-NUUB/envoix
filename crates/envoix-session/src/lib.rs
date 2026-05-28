//! Session orchestration for transfer setup and concrete implementation wiring.

use std::net::SocketAddr;
use std::path::PathBuf;

pub use envoix_auth::PairingConfig;
use envoix_auth::{authenticate_receiver, authenticate_sender};
use envoix_error::CoreError;
use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferEvent, TransferSummary,
};
use envoix_transport::{ConnectionCandidate, TransportDialer, TransportListener};
use envoix_transport_quic::{QuicDialer, QuicListener};
pub use envoix_types::TransferDirection;

/// Error type returned by session orchestration.
pub type SessionError = CoreError;

/// Runtime options used when wiring transports into the transfer engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Maximum chunk payload size sent by the transfer engine.
    pub chunk_size: usize,
    /// Pairing authentication required before any transfer frame.
    pub pairing: PairingConfig,
}

/// Sends one file to a manually supplied peer address.
pub async fn send_file_manual(
    peer_addr: SocketAddr,
    file_path: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let dialer = QuicDialer;
    let mut connection = dialer
        .dial(ConnectionCandidate::Quic { addr: peer_addr })
        .await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_sender(&mut *connection, &config.pairing).await {
        let _ = connection.close().await;
        return Err(error);
    }
    let summary = engine
        .send_file(&mut *connection, file_path, events.as_ref())
        .await?;
    let _ = connection.close().await;
    Ok(summary)
}

/// Receives one file and reports the concrete bound address before accepting.
pub async fn receive_file_with_bound_addr<F>(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    on_bound_addr: F,
) -> Result<TransferSummary, SessionError>
where
    F: FnOnce(SocketAddr) + Send,
{
    let listener = QuicListener::bind(listen_addr)?;
    on_bound_addr(listener.local_addr()?);
    let mut connection = listener.accept().await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_receiver(&mut *connection, &config.pairing).await {
        let _ = connection.close().await;
        return Err(error);
    }
    let summary = engine
        .receive_file(&mut *connection, output_dir, events.as_ref())
        .await?;
    let _ = connection.close().await;
    Ok(summary)
}
