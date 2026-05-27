//! Wire protocol frame types and codecs.

use envoix_error::CoreError;
use envoix_types::{PeerRole, TransferId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

pub type ProtocolError = CoreError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Frame {
    Hello(Hello),
    Ready(Ready),
    FileHeader(FileHeader),
    FileHeaderAck(FileHeaderAck),
    Chunk(Chunk),
    Complete(Complete),
    Error(ErrorFrame),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub role: PeerRole,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ready;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileHeader {
    pub transfer_id: TransferId,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileHeaderAck {
    pub transfer_id: TransferId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Chunk {
    pub transfer_id: TransferId,
    pub index: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Complete {
    pub transfer_id: TransferId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorFrame {
    pub message: String,
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;

    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(CoreError::Protocol(format!(
            "frame length {length} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;

    serde_json::from_slice(&payload).map_err(|error| CoreError::Protocol(error.to_string()))
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let payload =
        serde_json::to_vec(frame).map_err(|error| CoreError::Protocol(error.to_string()))?;

    if payload.len() > MAX_FRAME_SIZE {
        return Err(CoreError::Protocol(format!(
            "frame length {} exceeds maximum {MAX_FRAME_SIZE}",
            payload.len()
        )));
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoix_types::{PROTOCOL_VERSION, PeerRole, TransferId};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let frame = Frame::Chunk(Chunk {
            transfer_id: TransferId::new("transfer-1"),
            index: 2,
            offset: 128,
            bytes: b"hello".to_vec(),
        });

        write_frame(&mut writer, &frame).await.unwrap();
        let decoded = read_frame(&mut reader).await.unwrap();

        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(16);

        writer
            .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes())
            .await
            .unwrap();

        let error = read_frame(&mut reader).await.unwrap_err();

        assert!(matches!(error, CoreError::Protocol(_)));
    }

    #[tokio::test]
    async fn hello_frame_carries_protocol_version_and_role() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let frame = Frame::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            role: PeerRole::Sender,
        });

        write_frame(&mut writer, &frame).await.unwrap();

        assert_eq!(read_frame(&mut reader).await.unwrap(), frame);
    }
}
