//! TCP transport implementation.

use std::net::SocketAddr;

use async_trait::async_trait;
use envoix_error::CoreError;
use envoix_protocol::{Frame, read_frame, write_frame};
use envoix_transport::{
    ConnectionCandidate, FrameConnection, TransportDialer, TransportError, TransportListener,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpIpv6Dialer;

#[async_trait]
impl TransportDialer for TcpIpv6Dialer {
    async fn dial(
        &self,
        candidate: ConnectionCandidate,
    ) -> Result<Box<dyn FrameConnection>, TransportError> {
        let ConnectionCandidate::TcpIpv6 { addr } = candidate;
        let stream = TcpStream::connect(addr).await?;
        Ok(Box::new(TcpFrameConnection::new(stream)))
    }
}

#[derive(Debug)]
pub struct TcpIpv6Listener {
    listener: TcpListener,
}

impl TcpIpv6Listener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(CoreError::from)
    }
}

#[async_trait]
impl TransportListener for TcpIpv6Listener {
    async fn accept(&self) -> Result<Box<dyn FrameConnection>, TransportError> {
        let (stream, _) = self.listener.accept().await?;
        Ok(Box::new(TcpFrameConnection::new(stream)))
    }
}

#[derive(Debug)]
struct TcpFrameConnection {
    stream: TcpStream,
}

impl TcpFrameConnection {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl FrameConnection for TcpFrameConnection {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        write_frame(&mut self.stream, &frame).await
    }

    async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
        read_frame(&mut self.stream).await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoix_protocol::{Frame, Ready};

    #[tokio::test]
    async fn tcp_transport_exchanges_frames_over_ipv6() {
        assert_tcp_transport_exchanges_frames("[::1]:0".parse().unwrap()).await;
    }

    #[tokio::test]
    async fn tcp_transport_exchanges_frames_over_ipv4() {
        assert_tcp_transport_exchanges_frames("127.0.0.1:0".parse().unwrap()).await;
    }

    async fn assert_tcp_transport_exchanges_frames(bind_addr: SocketAddr) {
        let listener = TcpIpv6Listener::bind(bind_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let receiver = tokio::spawn(async move {
            let mut connection = listener.accept().await.unwrap();
            assert_eq!(connection.recv_frame().await.unwrap(), Frame::Ready(Ready));
            connection.send_frame(Frame::Ready(Ready)).await.unwrap();
        });

        let dialer = TcpIpv6Dialer;
        let mut connection = dialer
            .dial(ConnectionCandidate::TcpIpv6 { addr })
            .await
            .unwrap();

        connection.send_frame(Frame::Ready(Ready)).await.unwrap();
        assert_eq!(connection.recv_frame().await.unwrap(), Frame::Ready(Ready));

        receiver.await.unwrap();
    }
}
