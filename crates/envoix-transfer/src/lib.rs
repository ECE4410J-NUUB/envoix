//! File-transfer state machine.

use std::path::PathBuf;

use envoix_crypto::CryptoProvider;
use envoix_error::CoreError;
use envoix_protocol::{Chunk, Complete, FileHeader, FileHeaderAck, Frame, Hello, Ready};
use envoix_storage::LocalFileStorage;
use envoix_transport::FrameConnection;
use envoix_types::{PROTOCOL_VERSION, PeerRole, TransferDirection, TransferId};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

pub type TransferError = CoreError;

pub trait EventSink: Send + Sync {
    fn on_event(&self, event: TransferEvent);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn on_event(&self, _event: TransferEvent) {}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferEvent {
    Started {
        transfer_id: TransferId,
        direction: TransferDirection,
        file_name: String,
        total_bytes: u64,
    },
    Progress {
        transfer_id: TransferId,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    Completed {
        transfer_id: TransferId,
        bytes_transferred: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferSummary {
    pub transfer_id: TransferId,
    pub file_name: String,
    pub bytes_transferred: u64,
}

#[derive(Clone, Debug)]
pub struct TransferEngine<C> {
    crypto: C,
    chunk_size: usize,
}

impl<C> TransferEngine<C>
where
    C: CryptoProvider,
{
    pub fn new(crypto: C, chunk_size: usize) -> Self {
        Self { crypto, chunk_size }
    }

    pub async fn send_file(
        &self,
        connection: &mut dyn FrameConnection,
        path: PathBuf,
        events: &dyn EventSink,
    ) -> Result<TransferSummary, TransferError> {
        if self.chunk_size == 0 {
            return Err(CoreError::InvalidInput(
                "chunk size must be positive".into(),
            ));
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CoreError::InvalidInput("source path has no file name".into()))?
            .to_owned();
        let metadata = tokio::fs::metadata(&path).await?;
        if !metadata.is_file() {
            return Err(CoreError::InvalidInput(format!(
                "source is not a file: {}",
                path.display()
            )));
        }

        let transfer_id = new_transfer_id();
        let total_bytes = metadata.len();

        connection
            .send_frame(Frame::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                role: PeerRole::Sender,
            }))
            .await?;
        expect_ready(connection.recv_frame().await?)?;

        connection
            .send_frame(Frame::FileHeader(FileHeader {
                transfer_id: transfer_id.clone(),
                file_name: file_name.clone(),
                file_size: total_bytes,
                chunk_size: self.chunk_size as u64,
            }))
            .await?;
        expect_file_header_ack(connection.recv_frame().await?, &transfer_id)?;

        events.on_event(TransferEvent::Started {
            transfer_id: transfer_id.clone(),
            direction: TransferDirection::Send,
            file_name: file_name.clone(),
            total_bytes,
        });

        let mut file = LocalFileStorage::open_source(&path).await?;
        let mut buffer = vec![0_u8; self.chunk_size];
        let mut index = 0_u64;
        let mut offset = 0_u64;

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let encrypted =
                self.crypto
                    .encrypt_chunk(&transfer_id, index, &buffer[..bytes_read])?;
            connection
                .send_frame(Frame::Chunk(Chunk {
                    transfer_id: transfer_id.clone(),
                    index,
                    offset,
                    bytes: encrypted,
                }))
                .await?;

            offset += bytes_read as u64;
            index += 1;
            events.on_event(TransferEvent::Progress {
                transfer_id: transfer_id.clone(),
                bytes_transferred: offset,
                total_bytes,
            });
        }

        if offset != total_bytes {
            return Err(CoreError::Transfer(format!(
                "unexpected end of file: expected to read {} bytes but only read {}",
                total_bytes, offset
            )));
        }

        connection
            .send_frame(Frame::Complete(Complete {
                transfer_id: transfer_id.clone(),
            }))
            .await?;
        events.on_event(TransferEvent::Completed {
            transfer_id: transfer_id.clone(),
            bytes_transferred: offset,
        });

        Ok(TransferSummary {
            transfer_id,
            file_name,
            bytes_transferred: offset,
        })
    }

    pub async fn receive_file(
        &self,
        connection: &mut dyn FrameConnection,
        output_dir: PathBuf,
        events: &dyn EventSink,
    ) -> Result<TransferSummary, TransferError> {
        expect_sender_hello(connection.recv_frame().await?)?;
        connection.send_frame(Frame::Ready(Ready)).await?;

        let header = expect_file_header(connection.recv_frame().await?)?;
        let final_path = output_dir.join(&header.file_name);
        // fail early if the final file already exists
        if fs::try_exists(&final_path).await? {
            return Err(CoreError::Storage(format!(
                "destination already exists: {}",
                final_path.display()
            )));
        }
        let (temp_path, mut file) =
            LocalFileStorage::create_temp_destination(&output_dir, &header.file_name).await?;

        connection
            .send_frame(Frame::FileHeaderAck(FileHeaderAck {
                transfer_id: header.transfer_id.clone(),
            }))
            .await?;

        events.on_event(TransferEvent::Started {
            transfer_id: header.transfer_id.clone(),
            direction: TransferDirection::Receive,
            file_name: header.file_name.clone(),
            total_bytes: header.file_size,
        });

        let mut expected_index = 0_u64;
        let mut expected_offset = 0_u64;

        loop {
            match connection.recv_frame().await? {
                Frame::Chunk(chunk) => {
                    validate_chunk(&chunk, &header.transfer_id, expected_index, expected_offset)?;
                    let decrypted = self.crypto.decrypt_chunk(
                        &header.transfer_id,
                        chunk.index,
                        &chunk.bytes,
                    )?;
                    if decrypted.len() as u64 + expected_offset > header.file_size {
                        return Err(CoreError::Transfer(format!(
                            "chunk data exceeds expected file size: chunk offset {} + data length {} > expected file size {}",
                            chunk.offset,
                            decrypted.len(),
                            header.file_size
                        )));
                    }
                    file.write_all(&decrypted).await?;

                    expected_index += 1;
                    expected_offset += decrypted.len() as u64;
                    events.on_event(TransferEvent::Progress {
                        transfer_id: header.transfer_id.clone(),
                        bytes_transferred: expected_offset,
                        total_bytes: header.file_size,
                    });
                }
                Frame::Complete(complete) if complete.transfer_id == header.transfer_id => {
                    if expected_offset != header.file_size {
                        return Err(CoreError::Transfer(format!(
                            "transfer complete but expected offset {expected_offset} does not match file size {}",
                            header.file_size
                        )));
                    }
                    file.flush().await?;
                    drop(file);
                    LocalFileStorage::finalize_temp_file(&temp_path, &final_path).await?;
                    events.on_event(TransferEvent::Completed {
                        transfer_id: header.transfer_id.clone(),
                        bytes_transferred: expected_offset,
                    });

                    return Ok(TransferSummary {
                        transfer_id: header.transfer_id,
                        file_name: header.file_name,
                        bytes_transferred: expected_offset,
                    });
                }
                frame => {
                    return Err(CoreError::Transfer(format!(
                        "unexpected frame while receiving chunks: {frame:?}"
                    )));
                }
            }
        }
    }
}

fn expect_ready(frame: Frame) -> Result<(), TransferError> {
    match frame {
        Frame::Ready(_) => Ok(()),
        frame => Err(CoreError::Transfer(format!(
            "expected Ready, got {frame:?}"
        ))),
    }
}

fn expect_sender_hello(frame: Frame) -> Result<(), TransferError> {
    match frame {
        Frame::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            role: PeerRole::Sender,
        }) => Ok(()),
        frame => Err(CoreError::Transfer(format!(
            "expected sender Hello, got {frame:?}"
        ))),
    }
}

fn expect_file_header(frame: Frame) -> Result<FileHeader, TransferError> {
    match frame {
        Frame::FileHeader(header) => Ok(header),
        frame => Err(CoreError::Transfer(format!(
            "expected FileHeader, got {frame:?}"
        ))),
    }
}

fn expect_file_header_ack(frame: Frame, transfer_id: &TransferId) -> Result<(), TransferError> {
    match frame {
        Frame::FileHeaderAck(ack) if &ack.transfer_id == transfer_id => Ok(()),
        frame => Err(CoreError::Transfer(format!(
            "expected FileHeaderAck for {transfer_id}, got {frame:?}"
        ))),
    }
}

fn validate_chunk(
    chunk: &Chunk,
    transfer_id: &TransferId,
    expected_index: u64,
    expected_offset: u64,
) -> Result<(), TransferError> {
    if &chunk.transfer_id != transfer_id {
        return Err(CoreError::Transfer(format!(
            "chunk transfer id {} does not match {transfer_id}",
            chunk.transfer_id
        )));
    }
    if chunk.index != expected_index {
        return Err(CoreError::Transfer(format!(
            "chunk index {} does not match expected {expected_index}",
            chunk.index
        )));
    }
    if chunk.offset != expected_offset {
        return Err(CoreError::Transfer(format!(
            "chunk offset {} does not match expected {expected_offset}",
            chunk.offset
        )));
    }
    Ok(())
}

fn new_transfer_id() -> TransferId {
    TransferId::new(format!("transfer-{}", Uuid::now_v7()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use envoix_crypto::InsecureNoopCryptoProvider;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn transfers_file_over_frame_connection() {
        let root = unique_test_dir();
        let source_dir = root.join("source");
        let output_dir = root.join("output");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        let source_path = source_dir.join("hello.txt");
        tokio::fs::write(&source_path, b"hello over frames")
            .await
            .unwrap();

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            async move {
                TransferEngine::new(InsecureNoopCryptoProvider, 4)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
                    .unwrap()
            }
        });

        let send_summary = TransferEngine::new(InsecureNoopCryptoProvider, 4)
            .send_file(&mut sender_connection, source_path, &NoopEventSink)
            .await
            .unwrap();
        let receive_summary = receiver.await.unwrap();

        assert_eq!(send_summary.bytes_transferred, 17);
        assert_eq!(receive_summary.bytes_transferred, 17);
        assert_eq!(
            tokio::fs::read(output_dir.join("hello.txt")).await.unwrap(),
            b"hello over frames"
        );

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    struct MemoryFrameConnection {
        tx: mpsc::Sender<Frame>,
        rx: mpsc::Receiver<Frame>,
    }

    fn memory_connection_pair() -> (MemoryFrameConnection, MemoryFrameConnection) {
        let (sender_tx, receiver_rx) = mpsc::channel(16);
        let (receiver_tx, sender_rx) = mpsc::channel(16);

        (
            MemoryFrameConnection {
                tx: sender_tx,
                rx: sender_rx,
            },
            MemoryFrameConnection {
                tx: receiver_tx,
                rx: receiver_rx,
            },
        )
    }

    #[async_trait]
    impl FrameConnection for MemoryFrameConnection {
        async fn send_frame(&mut self, frame: Frame) -> Result<(), CoreError> {
            self.tx
                .send(frame)
                .await
                .map_err(|error| CoreError::Transport(error.to_string()))
        }

        async fn recv_frame(&mut self) -> Result<Frame, CoreError> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| CoreError::Transport("memory connection closed".into()))
        }

        async fn close(&mut self) -> Result<(), CoreError> {
            Ok(())
        }
    }

    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "envoix-transfer-test-{}-{nanos}",
            std::process::id()
        ))
    }
}
