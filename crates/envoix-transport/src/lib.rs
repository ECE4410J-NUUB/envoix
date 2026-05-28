//! Abstract transport traits and connection candidates.

use std::net::SocketAddr;

use async_trait::async_trait;
use envoix_error::CoreError;
use envoix_protocol::Frame;

/// Error type returned by transport implementations.
pub type TransportError = CoreError;

/// Address and transport type selected for a connection attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConnectionCandidate {
    /// QUIC connection to the given socket address.
    Quic { addr: SocketAddr },
}

/// A bidirectional frame stream used by the transfer state machine.
#[async_trait]
pub trait FrameConnection: Send {
    /// Sends one protocol frame.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError>;

    /// Receives one protocol frame.
    async fn recv_frame(&mut self) -> Result<Frame, TransportError>;

    /// Exports 32 bytes of transport channel-binding material.
    fn export_keying_material(
        &self,
        _label: &[u8],
        _context: &[u8],
    ) -> Result<[u8; 32], TransportError> {
        Err(CoreError::Transport(
            "transport channel binding is unavailable".into(),
        ))
    }

    /// Closes the underlying transport connection.
    async fn close(&mut self) -> Result<(), TransportError>;
}

/// Connects to a remote peer using one concrete transport.
#[async_trait]
pub trait TransportDialer: Send + Sync {
    /// Dials the supplied transport candidate.
    async fn dial(
        &self,
        candidate: ConnectionCandidate,
    ) -> Result<Box<dyn FrameConnection>, TransportError>;
}

/// Accepts inbound connections for one concrete transport.
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// Accepts one inbound frame connection.
    async fn accept(&self) -> Result<Box<dyn FrameConnection>, TransportError>;
}
