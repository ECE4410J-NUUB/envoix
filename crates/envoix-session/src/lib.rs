//! Session orchestration for transfer setup and concrete implementation wiring.

use std::net::SocketAddr;
use std::path::PathBuf;

use envoix_crypto::InsecureNoopCryptoProvider;
use envoix_discovery::{DiscoveryProvider, ManualPeerDiscovery};
use envoix_error::CoreError;
use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferEvent, TransferSummary,
};
use envoix_transport::{TransportDialer, TransportListener};
use envoix_transport_tcp::{TcpIpv6Dialer, TcpIpv6Listener};
pub use envoix_types::TransferDirection;

pub type SessionError = CoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    pub chunk_size: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

pub async fn send_file_manual_ipv6(
    peer_addr: SocketAddr,
    file_path: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let discovery = ManualPeerDiscovery::new(peer_addr);
    let candidate =
        discovery.discover()?.into_iter().next().ok_or_else(|| {
            CoreError::Discovery("manual discovery returned no candidates".into())
        })?;

    let dialer = TcpIpv6Dialer;
    let mut connection = dialer.dial(candidate).await?;
    let engine = TransferEngine::new(InsecureNoopCryptoProvider, config.chunk_size);

    engine
        .send_file(&mut *connection, file_path, events.as_ref())
        .await
}

pub async fn receive_file_ipv6(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let listener = TcpIpv6Listener::bind(listen_addr).await?;
    let mut connection = listener.accept().await?;
    let engine = TransferEngine::new(InsecureNoopCryptoProvider, config.chunk_size);

    engine
        .receive_file(&mut *connection, output_dir, events.as_ref())
        .await
}
