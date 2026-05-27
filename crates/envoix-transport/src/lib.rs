//! Abstract transport traits and connection candidates.

use std::net::SocketAddr;

use async_trait::async_trait;
use envoix_error::CoreError;
use envoix_protocol::Frame;

pub type TransportError = CoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConnectionCandidate {
    TcpIpv6 { addr: SocketAddr },
}

#[async_trait]
pub trait FrameConnection: Send {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError>;

    async fn recv_frame(&mut self) -> Result<Frame, TransportError>;

    async fn close(&mut self) -> Result<(), TransportError>;
}

#[async_trait]
pub trait TransportDialer: Send + Sync {
    async fn dial(
        &self,
        candidate: ConnectionCandidate,
    ) -> Result<Box<dyn FrameConnection>, TransportError>;
}

#[async_trait]
pub trait TransportListener: Send + Sync {
    async fn accept(&self) -> Result<Box<dyn FrameConnection>, TransportError>;
}
