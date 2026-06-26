use std::time::Duration;

use envoix_error::CoreError;
use envoix_protocol::{
    Frame, FrameConnection, ProtocolError, flush_frame_writer, read_frame, write_chunk_frame,
    write_frame,
};
use iroh::Endpoint;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};

const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct IrohFrameConnection {
    pub(crate) _local_endpoint: Endpoint,
    pub(crate) connection: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
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
