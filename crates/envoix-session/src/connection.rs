use std::time::Duration;

use envoix_error::CoreError;
use envoix_protocol::{
    Frame, FrameConnection, ProtocolError, flush_frame_writer, read_frame, write_chunk_frame,
    write_frame,
};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, TransportAddr};

const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct IrohFrameConnection {
    pub(crate) _local_endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

impl IrohFrameConnection {
    /// Human description of the data path in use: a direct IP connection to the
    /// peer, or via a relay. Read at close (after the transfer) so it reflects
    /// the settled path - iroh starts on the relay and upgrades to a direct,
    /// hole-punched path when one is found, so reading earlier can mislead.
    fn data_path(&self) -> String {
        let paths = self.connection.paths();
        for path in paths.iter() {
            if path.is_selected() {
                return match path.remote_addr() {
                    TransportAddr::Ip(addr) => format!("direct ({addr})"),
                    TransportAddr::Relay(url) => format!("relay ({url})"),
                    other => format!("{other:?}"),
                };
            }
        }
        "unknown".into()
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
        // Surface which path the transfer actually used (direct vs relay) without
        // requiring socket-level traces. Logged under the "envoix" target so the
        // CLI's default filter shows it at info while keeping iroh internals quiet.
        tracing::info!(target: "envoix", "data path: {}", self.data_path());
        if self.send.finish().is_ok() {
            let _ = tokio::time::timeout(STREAM_CLOSE_TIMEOUT, self.send.stopped()).await;
        }
        self.connection.close(VarInt::from_u32(0), b"done");
        Ok(())
    }
}
