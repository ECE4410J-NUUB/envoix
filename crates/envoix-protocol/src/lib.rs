//! Wire protocol frame types and codecs.

use envoix_error::CoreError;
use envoix_types::{PeerRole, TransferId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded frame payload accepted by the length-prefixed codec.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Error type returned by protocol encoding and decoding.
pub type ProtocolError = CoreError;

/// A single wire message exchanged between sender and receiver.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Frame {
    /// Carries pairing-authentication messages before transfer frames.
    Auth(AuthFrame),
    /// Opens the protocol conversation and declares the peer role.
    Hello(Hello),
    /// Confirms that the receiver is ready for file metadata.
    Ready(Ready),
    /// Describes the file and its expected whole-file hash.
    FileHeader(FileHeader),
    /// Tells the sender where this receiver can resume from.
    ResumeStatus(ResumeStatus),
    /// Carries one sequential data chunk.
    Chunk(Chunk),
    /// Marks the sender's end of data for a transfer.
    Complete(Complete),
    /// Confirms that the receiver verified and finalized the file.
    CompleteAck(CompleteAck),
    /// Carries a protocol-level error message.
    Error(ErrorFrame),
}

/// Authentication handshake frame exchanged before transfer metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthFrame {
    /// First SPAKE2 message from the sender.
    Spake2Start(Spake2Start),
    /// SPAKE2 response message from the receiver.
    Spake2Message(Spake2Message),
    /// Role-separated confirmation proof for the derived key.
    Spake2Confirm(Spake2Confirm),
}

/// Sender's initial SPAKE2 frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Spake2Start {
    /// Auth protocol version expected by the sender.
    pub protocol_version: u32,
    /// Sender role bound into the authentication transcript.
    pub role: PeerRole,
    /// Sender-generated nonce.
    pub nonce: Vec<u8>,
    /// SPAKE2 outbound message bytes.
    pub message: Vec<u8>,
}

/// Receiver's SPAKE2 response frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Spake2Message {
    /// Receiver-generated nonce.
    pub nonce: Vec<u8>,
    /// SPAKE2 outbound message bytes.
    pub message: Vec<u8>,
}

/// SPAKE2 key confirmation frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Spake2Confirm {
    /// MAC proving possession of the SPAKE2 key for this transcript.
    pub proof: Vec<u8>,
}

/// Initial handshake frame sent before file metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Hello {
    /// Wire protocol version expected by the sender.
    pub protocol_version: u32,
    /// Peer role for this connection.
    pub role: PeerRole,
}

/// Receiver readiness marker sent after a valid sender `Hello`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ready;

/// File metadata sent before chunks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileHeader {
    /// Transfer identifier used by chunks, resume state, and completion frames.
    pub transfer_id: TransferId,
    /// Plain destination file name, without path components.
    pub file_name: String,
    /// Expected file length in bytes.
    pub file_size: u64,
    /// Sender chunk size in bytes.
    pub chunk_size: u64,
    /// Expected BLAKE3 hash of the complete plaintext file, hex-encoded.
    pub file_hash: String,
}

/// Receiver resume position for a transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResumeStatus {
    /// Transfer this status applies to.
    pub transfer_id: TransferId,
    /// Next sequential chunk index the sender should transmit.
    pub next_chunk_index: u64,
    /// Number of plaintext bytes already stored by the receiver.
    pub bytes_received: u64,
}

/// Sequential file data frame.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Chunk {
    /// Transfer this chunk belongs to.
    pub transfer_id: TransferId,
    /// Zero-based sequential chunk index.
    pub index: u64,
    /// Plaintext byte offset for the first byte in `bytes`.
    pub offset: u64,
    /// Plaintext chunk payload bytes; transport encryption provided by QUIC
    pub bytes: Vec<u8>,
}

/// Sender completion marker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Complete {
    /// Transfer being completed.
    pub transfer_id: TransferId,
    /// BLAKE3 hash the sender expects the receiver to verify.
    pub file_hash: String,
}

/// Receiver acknowledgement sent only after verified finalization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteAck {
    /// Transfer that was verified and finalized.
    pub transfer_id: TransferId,
}

/// Protocol error frame for failures that can be represented on the wire.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorFrame {
    /// Human-readable error description.
    pub message: String,
}

/// Reads one length-prefixed JSON frame from `reader`.
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

/// Writes one length-prefixed JSON frame to `writer`.
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
        let frame = Frame::FileHeader(FileHeader {
            transfer_id: TransferId::new("transfer-1"),
            file_name: "hello.txt".into(),
            file_size: 5,
            chunk_size: 1024,
            file_hash: "abc123".into(),
        });

        write_frame(&mut writer, &frame).await.unwrap();
        let decoded = read_frame(&mut reader).await.unwrap();

        assert_eq!(decoded, frame);
    }

    #[tokio::test]
    async fn resumable_v1_frames_round_trip() {
        let frames = [
            Frame::Auth(AuthFrame::Spake2Start(Spake2Start {
                protocol_version: PROTOCOL_VERSION,
                role: PeerRole::Sender,
                nonce: b"sender nonce".to_vec(),
                message: b"sender spake2 message".to_vec(),
            })),
            Frame::Auth(AuthFrame::Spake2Message(Spake2Message {
                nonce: b"receiver nonce".to_vec(),
                message: b"receiver spake2 message".to_vec(),
            })),
            Frame::Auth(AuthFrame::Spake2Confirm(Spake2Confirm {
                proof: b"confirmation proof".to_vec(),
            })),
            Frame::ResumeStatus(ResumeStatus {
                transfer_id: TransferId::new("transfer-1"),
                next_chunk_index: 2,
                bytes_received: 128,
            }),
            Frame::Chunk(Chunk {
                transfer_id: TransferId::new("transfer-1"),
                index: 2,
                offset: 128,
                bytes: b"hello".to_vec(),
            }),
            Frame::Complete(Complete {
                transfer_id: TransferId::new("transfer-1"),
                file_hash: "abc123".into(),
            }),
            Frame::CompleteAck(CompleteAck {
                transfer_id: TransferId::new("transfer-1"),
            }),
        ];

        for frame in frames {
            let (mut writer, mut reader) = tokio::io::duplex(1024);
            write_frame(&mut writer, &frame).await.unwrap();
            assert_eq!(read_frame(&mut reader).await.unwrap(), frame);
        }
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
