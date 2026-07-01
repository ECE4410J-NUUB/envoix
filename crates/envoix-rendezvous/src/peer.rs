//! A peer's connection to the broker, owned as boxed `AsyncWrite`/`AsyncRead`
//! halves plus a [`CloseWaiter`]. After relaying, the broker waits on the
//! close-waiter so each transport stays open until the peer has closed it -
//! i.e. drained all relayed data - rather than being torn down mid-read.

use std::future::Future;
use std::pin::Pin;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::RendezvousError;
use crate::io::{read_framed, write_framed};

type BoxWriter = Box<dyn AsyncWrite + Send + Unpin>;
type BoxReader = Box<dyn AsyncRead + Send + Unpin>;

/// Resolves once the peer has closed its side of the transport (so everything
/// the broker relayed has been delivered). For iroh this awaits
/// `Connection::closed`; an in-memory duplex needs nothing, so `()` is ready
/// immediately.
pub trait CloseWaiter: Send {
    fn wait_closed(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

impl CloseWaiter for () {
    fn wait_closed(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::ready(()))
    }
}

/// One peer's framed, bidirectional link to the broker.
pub struct PeerConn {
    writer: BoxWriter,
    reader: BoxReader,
    close: Box<dyn CloseWaiter>,
}

impl PeerConn {
    /// Build a peer connection from write/read halves and a close-waiter.
    pub fn new(
        writer: impl AsyncWrite + Send + Unpin + 'static,
        reader: impl AsyncRead + Send + Unpin + 'static,
        close: impl CloseWaiter + 'static,
    ) -> Self {
        Self {
            writer: Box::new(writer),
            reader: Box::new(reader),
            close: Box::new(close),
        }
    }

    /// Read one length-prefixed control frame.
    pub async fn read_control<T: DeserializeOwned>(&mut self) -> Result<T, RendezvousError> {
        read_framed(&mut self.reader).await
    }

    /// Write one length-prefixed control frame.
    pub async fn write_control<T: Serialize>(&mut self, value: &T) -> Result<(), RendezvousError> {
        write_framed(&mut self.writer, value).await
    }

    /// Split into the raw halves (plus close-waiter) for byte relaying.
    pub(crate) fn into_parts(self) -> (BoxWriter, BoxReader, Box<dyn CloseWaiter>) {
        (self.writer, self.reader, self.close)
    }
}
