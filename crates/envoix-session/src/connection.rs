use std::time::Duration;

use envoix_error::CoreError;
use envoix_protocol::{
    Frame, FrameConnection, ProtocolError, flush_frame_writer, read_frame, write_chunk_frame,
    write_frame,
};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, TransportAddr};
use tokio::task::JoinHandle;

const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on how long the side that sent the final frame waits for the peer to
/// close before closing itself, so a peer that never closes cannot hang us.
const PEER_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the background logger samples the selected data path.
const PATH_LOG_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) struct IrohFrameConnection {
    pub(crate) _local_endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
    /// Logs the data path (direct/relay) as soon as one is selected and again on
    /// every change, so the path is visible *during* the transfer rather than
    /// only at the end. Aborted when the connection is dropped.
    path_logger: JoinHandle<()>,
}

/// Description of the currently selected data path, or `None` if none is selected
/// yet (still establishing) or the connection is closing.
fn selected_path_desc(connection: &Connection) -> Option<String> {
    for path in connection.paths().iter() {
        if path.is_selected() {
            return Some(match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("direct ({addr})"),
                TransportAddr::Relay(url) => format!("relay ({url})"),
                other => format!("{other:?}"),
            });
        }
    }
    None
}

/// Spawn a task that logs the selected data path on first selection and on every
/// change (e.g. a relay->direct upgrade after holepunching). Under the "envoix"
/// target so the CLI's default filter shows it at info without a flag.
fn spawn_path_logger(connection: Connection) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = String::new();
        loop {
            if let Some(path) = selected_path_desc(&connection)
                && path != last
            {
                tracing::info!(target: "envoix", "data path: {path}");
                last = path;
            }
            tokio::time::sleep(PATH_LOG_INTERVAL).await;
        }
    })
}

impl IrohFrameConnection {
    /// Wrap an established iroh connection + bidirectional stream, starting the
    /// background data-path logger for its lifetime.
    pub(crate) fn new(
        local_endpoint: Endpoint,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        let path_logger = spawn_path_logger(connection.clone());
        Self {
            _local_endpoint: local_endpoint,
            connection,
            send,
            recv,
            path_logger,
        }
    }

    /// Close as the side that sent the *final* frame: finish our stream, then
    /// wait (bounded) for the peer to close the connection instead of closing
    /// first.
    ///
    /// The last frame of a transfer is the receiver's `CompleteAck`. Closing
    /// right after sending it races our `CONNECTION_CLOSE` against the peer
    /// reading that frame - QUIC may drop still-unread stream data on close, so
    /// the ack is lost and an otherwise-complete transfer looks failed. Letting
    /// the peer (which reads the ack) initiate the close keeps the stream open
    /// long enough for the ack to be delivered. Bounded so a peer that never
    /// closes cannot hang us; if it elapses we close ourselves.
    pub(crate) async fn await_peer_close(&mut self) {
        let _ = self.send.finish();
        if tokio::time::timeout(PEER_CLOSE_TIMEOUT, self.connection.closed())
            .await
            .is_err()
        {
            self.connection.close(VarInt::from_u32(0), b"done");
        }
    }
}

#[async_trait::async_trait]
impl FrameConnection for IrohFrameConnection {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        write_frame(&mut self.send, &frame).await?;
        flush_frame_writer(&mut self.send).await
    }

    async fn send_chunk(
        &mut self,
        transfer_id: &envoix_types::TransferId,
        index: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        write_chunk_frame(&mut self.send, transfer_id, index, offset, bytes).await?;
        flush_frame_writer(&mut self.send).await
    }

    async fn recv_frame(&mut self) -> Result<Frame, ProtocolError> {
        read_frame(&mut self.recv).await
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], ProtocolError> {
        let mut output = [0_u8; 32];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|_| CoreError::Transport("failed to export iroh keying material".into()))?;
        Ok(output)
    }

    async fn close(&mut self) -> Result<(), ProtocolError> {
        if self.send.finish().is_ok() {
            let _ = tokio::time::timeout(STREAM_CLOSE_TIMEOUT, self.send.stopped()).await;
        }
        self.connection.close(VarInt::from_u32(0), b"done");
        Ok(())
    }
}

impl Drop for IrohFrameConnection {
    fn drop(&mut self) {
        // Stop the background path logger when the connection goes away (clean
        // close or abrupt drop on interrupt).
        self.path_logger.abort();
    }
}
