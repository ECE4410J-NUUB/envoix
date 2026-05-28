//! Session orchestration for transfer setup and concrete implementation wiring.

use std::net::SocketAddr;
use std::path::PathBuf;

use envoix_error::CoreError;
use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferEvent, TransferSummary,
};
use envoix_transport::{ConnectionCandidate, TransportDialer, TransportListener};
use envoix_transport_quic::{QuicDialer, QuicListener};
use envoix_transport_tcp::{TcpIpv6Dialer, TcpIpv6Listener};
pub use envoix_types::TransferDirection;

/// Error type returned by session orchestration.
pub type SessionError = CoreError;

/// Runtime options used when wiring transports into the transfer engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Maximum chunk payload size sent by the transfer engine.
    pub chunk_size: usize,
    /// Transport used for the peer connection.
    pub protocol: TransportProtocol,
}

/// Transport selected for a send or receive session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    /// QUIC over UDP. This is the default for new sessions.
    Quic,
    /// Plain TCP fallback.
    Tcp,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            protocol: TransportProtocol::Quic,
        }
    }
}

/// Sends one file to a manually supplied peer address.
pub async fn send_file_manual_ipv6(
    peer_addr: SocketAddr,
    file_path: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = match config.protocol {
        TransportProtocol::Quic => {
            let dialer = QuicDialer;
            dialer
                .dial(ConnectionCandidate::Quic { addr: peer_addr })
                .await?
        }
        TransportProtocol::Tcp => {
            let dialer = TcpIpv6Dialer;
            dialer
                .dial(ConnectionCandidate::Tcp { addr: peer_addr })
                .await?
        }
    };
    let engine = TransferEngine::new(config.chunk_size);

    let summary = engine
        .send_file(&mut *connection, file_path, events.as_ref())
        .await?;
    let _ = connection.close().await;
    Ok(summary)
}

/// Receives one file on a manually supplied listen address.
pub async fn receive_file_ipv6(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = match config.protocol {
        TransportProtocol::Quic => {
            let listener = QuicListener::bind(listen_addr)?;
            listener.accept().await?
        }
        TransportProtocol::Tcp => {
            let listener = TcpIpv6Listener::bind(listen_addr).await?;
            listener.accept().await?
        }
    };
    let engine = TransferEngine::new(config.chunk_size);

    let summary = engine
        .receive_file(&mut *connection, output_dir, events.as_ref())
        .await?;
    let _ = connection.close().await;
    Ok(summary)
}
