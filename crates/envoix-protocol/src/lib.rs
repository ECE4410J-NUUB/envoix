//! Wire protocol frame types and codecs.

use envoix_error::CoreError;
use envoix_types::{PeerRole, TransferId};
use num_enum::TryFromPrimitive;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"ENVX";
const WIRE_VERSION: u16 = 1;
const HEADER_LEN: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
enum FrameType {
    Auth = 1,
    Hello = 2,
    Ready = 3,
    FileHeader = 4,
    ResumeStatus = 5,
    Chunk = 6,
    Complete = 7,
    CompleteAck = 8,
    Error = 9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
enum AuthFrameType {
    Start = 1,
    Message = 2,
    Confirm = 3,
}

/// Maximum encoded frame payload accepted by the binary codec.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024 + 64 * 1024;

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

/// Reads one versioned binary frame from `reader`.
pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    if &header[0..4] != MAGIC {
        return Err(CoreError::Protocol("bad frame magic".into()));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != WIRE_VERSION {
        return Err(CoreError::Protocol(format!(
            "unsupported frame version {version}"
        )));
    }
    let frame_type =
        FrameType::try_from(header[6]).map_err(|error| CoreError::Protocol(error.to_string()))?;
    if header[7] != 0 {
        return Err(CoreError::Protocol(
            "reserved frame byte must be zero".into(),
        ));
    }

    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(CoreError::Protocol(format!(
            "frame length {length} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;

    decode_frame(frame_type, &payload)
}

/// Writes one versioned binary frame to `writer`.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let (frame_type, payload) = encode_frame(frame)?;

    if payload.len() > MAX_FRAME_SIZE {
        return Err(CoreError::Protocol(format!(
            "frame length {} exceeds maximum {MAX_FRAME_SIZE}",
            payload.len()
        )));
    }

    writer.write_all(MAGIC).await?;
    writer.write_all(&WIRE_VERSION.to_be_bytes()).await?;
    writer.write_all(&[frame_type as u8, 0]).await?;
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Flushes a frame writer when a caller needs a control-frame boundary.
pub async fn flush_frame_writer<W>(writer: &mut W) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    writer.flush().await?;
    Ok(())
}

fn encode_frame(frame: &Frame) -> Result<(FrameType, Vec<u8>), ProtocolError> {
    let mut payload = Vec::new();
    let frame_type = match frame {
        Frame::Auth(auth) => {
            match auth {
                AuthFrame::Spake2Start(start) => {
                    write_u8(&mut payload, AuthFrameType::Start as u8);
                    write_u32(&mut payload, start.protocol_version);
                    write_peer_role(&mut payload, start.role);
                    write_bytes(&mut payload, &start.nonce)?;
                    write_bytes(&mut payload, &start.message)?;
                }
                AuthFrame::Spake2Message(message) => {
                    write_u8(&mut payload, AuthFrameType::Message as u8);
                    write_bytes(&mut payload, &message.nonce)?;
                    write_bytes(&mut payload, &message.message)?;
                }
                AuthFrame::Spake2Confirm(confirm) => {
                    write_u8(&mut payload, AuthFrameType::Confirm as u8);
                    write_bytes(&mut payload, &confirm.proof)?;
                }
            }
            FrameType::Auth
        }
        Frame::Hello(hello) => {
            write_u32(&mut payload, hello.protocol_version);
            write_peer_role(&mut payload, hello.role);
            FrameType::Hello
        }
        Frame::Ready(_) => FrameType::Ready,
        Frame::FileHeader(header) => {
            write_string(&mut payload, &header.transfer_id.0)?;
            write_string(&mut payload, &header.file_name)?;
            write_u64(&mut payload, header.file_size);
            write_u64(&mut payload, header.chunk_size);
            write_string(&mut payload, &header.file_hash)?;
            FrameType::FileHeader
        }
        Frame::ResumeStatus(status) => {
            write_string(&mut payload, &status.transfer_id.0)?;
            write_u64(&mut payload, status.next_chunk_index);
            write_u64(&mut payload, status.bytes_received);
            FrameType::ResumeStatus
        }
        Frame::Chunk(chunk) => {
            write_string(&mut payload, &chunk.transfer_id.0)?;
            write_u64(&mut payload, chunk.index);
            write_u64(&mut payload, chunk.offset);
            write_bytes(&mut payload, &chunk.bytes)?;
            FrameType::Chunk
        }
        Frame::Complete(complete) => {
            write_string(&mut payload, &complete.transfer_id.0)?;
            write_string(&mut payload, &complete.file_hash)?;
            FrameType::Complete
        }
        Frame::CompleteAck(ack) => {
            write_string(&mut payload, &ack.transfer_id.0)?;
            FrameType::CompleteAck
        }
        Frame::Error(error) => {
            write_string(&mut payload, &error.message)?;
            FrameType::Error
        }
    };

    Ok((frame_type, payload))
}

fn decode_frame(frame_type: FrameType, payload: &[u8]) -> Result<Frame, ProtocolError> {
    let mut reader = PayloadReader::new(payload);
    let frame = match frame_type {
        FrameType::Auth => Frame::Auth(decode_auth(&mut reader)?),
        FrameType::Hello => Frame::Hello(Hello {
            protocol_version: reader.read_u32()?,
            role: reader.read_peer_role()?,
        }),
        FrameType::Ready => Frame::Ready(Ready),
        FrameType::FileHeader => Frame::FileHeader(FileHeader {
            transfer_id: TransferId::new(reader.read_string()?),
            file_name: reader.read_string()?,
            file_size: reader.read_u64()?,
            chunk_size: reader.read_u64()?,
            file_hash: reader.read_string()?,
        }),
        FrameType::ResumeStatus => Frame::ResumeStatus(ResumeStatus {
            transfer_id: TransferId::new(reader.read_string()?),
            next_chunk_index: reader.read_u64()?,
            bytes_received: reader.read_u64()?,
        }),
        FrameType::Chunk => Frame::Chunk(Chunk {
            transfer_id: TransferId::new(reader.read_string()?),
            index: reader.read_u64()?,
            offset: reader.read_u64()?,
            bytes: reader.read_bytes()?,
        }),
        FrameType::Complete => Frame::Complete(Complete {
            transfer_id: TransferId::new(reader.read_string()?),
            file_hash: reader.read_string()?,
        }),
        FrameType::CompleteAck => Frame::CompleteAck(CompleteAck {
            transfer_id: TransferId::new(reader.read_string()?),
        }),
        FrameType::Error => Frame::Error(ErrorFrame {
            message: reader.read_string()?,
        }),
    };
    reader.finish()?;
    Ok(frame)
}

fn decode_auth(reader: &mut PayloadReader<'_>) -> Result<AuthFrame, ProtocolError> {
    let auth_type = AuthFrameType::try_from(reader.read_u8()?)
        .map_err(|error| CoreError::Protocol(error.to_string()))?;
    match auth_type {
        AuthFrameType::Start => Ok(AuthFrame::Spake2Start(Spake2Start {
            protocol_version: reader.read_u32()?,
            role: reader.read_peer_role()?,
            nonce: reader.read_bytes()?,
            message: reader.read_bytes()?,
        })),
        AuthFrameType::Message => Ok(AuthFrame::Spake2Message(Spake2Message {
            nonce: reader.read_bytes()?,
            message: reader.read_bytes()?,
        })),
        AuthFrameType::Confirm => Ok(AuthFrame::Spake2Confirm(Spake2Confirm {
            proof: reader.read_bytes()?,
        })),
    }
}

fn write_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_peer_role(output: &mut Vec<u8>, role: PeerRole) {
    output.push(match role {
        PeerRole::Sender => 1,
        PeerRole::Receiver => 2,
    });
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<(), ProtocolError> {
    write_bytes(output, value.as_bytes())
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let length = u32::try_from(value.len())
        .map_err(|_| CoreError::Protocol("field length exceeds u32".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct PayloadReader<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("slice length was checked"),
        ))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("slice length was checked"),
        ))
    }

    fn read_peer_role(&mut self) -> Result<PeerRole, ProtocolError> {
        match self.read_u8()? {
            1 => Ok(PeerRole::Sender),
            2 => Ok(PeerRole::Receiver),
            role => Err(CoreError::Protocol(format!("unknown peer role {role}"))),
        }
    }

    fn read_string(&mut self) -> Result<String, ProtocolError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|error| CoreError::Protocol(error.to_string()))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let length = self.read_u32()? as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.offset == self.payload.len() {
            Ok(())
        } else {
            Err(CoreError::Protocol(format!(
                "{} trailing payload bytes",
                self.payload.len() - self.offset
            )))
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| CoreError::Protocol("payload offset overflow".into()))?;
        if end > self.payload.len() {
            return Err(CoreError::Protocol("malformed frame payload".into()));
        }
        let bytes = &self.payload[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoix_types::{PROTOCOL_VERSION, PeerRole, TransferId};

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
        let frames = vec![
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
            Frame::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                role: PeerRole::Sender,
            }),
            Frame::Ready(Ready),
            Frame::FileHeader(FileHeader {
                transfer_id: TransferId::new("transfer-1"),
                file_name: "hello.txt".into(),
                file_size: 128,
                chunk_size: 64,
                file_hash: "abc123".into(),
            }),
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
            Frame::Error(ErrorFrame {
                message: "bad frame".into(),
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
        let mut input = frame_bytes(FrameType::Ready, &[]);
        input[8..12].copy_from_slice(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes());

        let error = read_frame(&mut input.as_slice()).await.unwrap_err();

        assert!(matches!(error, CoreError::Protocol(_)));
    }

    #[tokio::test]
    async fn chunk_payload_is_encoded_as_raw_bytes() {
        let frame = Frame::Chunk(Chunk {
            transfer_id: TransferId::new("transfer-1"),
            index: 7,
            offset: 1024,
            bytes: br#"{"not":"json-expanded"}"#.to_vec(),
        });
        let mut encoded = Vec::new();

        write_frame(&mut encoded, &frame).await.unwrap();

        assert!(encoded.ends_with(br#"{"not":"json-expanded"}"#));
        assert_eq!(read_frame(&mut encoded.as_slice()).await.unwrap(), frame);
    }

    #[tokio::test]
    async fn rejects_bad_magic_version_and_type() {
        let mut bad_magic = frame_bytes(FrameType::Ready, &[]);
        bad_magic[0] = b'X';
        assert!(matches!(
            read_frame(&mut bad_magic.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));

        let mut bad_version = frame_bytes(FrameType::Ready, &[]);
        bad_version[5] = 2;
        assert!(matches!(
            read_frame(&mut bad_version.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));

        let bad_type = raw_frame_bytes(255, &[]);
        assert!(matches!(
            read_frame(&mut bad_type.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_utf8_and_malformed_payloads() {
        let invalid_utf8 = frame_bytes(FrameType::Error, &[0, 0, 0, 1, 0xff]);
        assert!(matches!(
            read_frame(&mut invalid_utf8.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));

        let malformed = frame_bytes(FrameType::CompleteAck, &[0, 0, 0, 8, b't', b'r']);
        assert!(matches!(
            read_frame(&mut malformed.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));

        let trailing = frame_bytes(FrameType::Ready, &[0]);
        assert!(matches!(
            read_frame(&mut trailing.as_slice()).await,
            Err(CoreError::Protocol(_))
        ));
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

    fn frame_bytes(frame_type: FrameType, payload: &[u8]) -> Vec<u8> {
        raw_frame_bytes(frame_type as u8, payload)
    }

    fn raw_frame_bytes(frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[frame_type, 0]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
}
