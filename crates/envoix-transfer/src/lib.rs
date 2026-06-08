//! File-transfer state machine.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use envoix_error::CoreError;
use envoix_protocol::{
    Chunk, Complete, CompleteAck, FileHeader, Frame, Hello, Ready, ResumeStatus,
};
use envoix_storage::{LocalFileStorage, TransferResumeState};
use envoix_transport::FrameConnection;
use envoix_types::{PROTOCOL_VERSION, PeerRole, TransferDirection, TransferId};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Default sequential chunk size used by clients that do not override it.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
const RESUME_STATE_WRITE_INTERVAL: u64 = 8 * 1024 * 1024;

/// Error type returned by the transfer state machine.
pub type TransferError = CoreError;

/// Observer for transfer lifecycle and progress events.
pub trait EventSink: Send + Sync {
    /// Handles one transfer event.
    fn on_event(&self, event: TransferEvent);
}

/// Event sink that ignores all transfer events.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn on_event(&self, _event: TransferEvent) {}
}

/// User-visible transfer lifecycle event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferEvent {
    /// A send or receive operation has started.
    Started {
        /// Transfer identifier for correlating events.
        transfer_id: TransferId,
        /// Direction of this local operation.
        direction: TransferDirection,
        /// File name being transferred.
        file_name: String,
        /// Total expected plaintext bytes.
        total_bytes: u64,
    },
    /// More plaintext bytes have been sent or persisted.
    Progress {
        /// Transfer identifier for correlating events.
        transfer_id: TransferId,
        /// Plaintext bytes transferred so far.
        bytes_transferred: u64,
        /// Total expected plaintext bytes.
        total_bytes: u64,
    },
    /// Transfer completed and, on receive, the file was finalized.
    Completed {
        /// Transfer identifier for correlating events.
        transfer_id: TransferId,
        /// Final plaintext byte count.
        bytes_transferred: u64,
    },
}

/// Summary returned after a successful send or receive operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferSummary {
    /// Transfer identifier for the completed transfer.
    pub transfer_id: TransferId,
    /// File name used for the transfer.
    pub file_name: String,
    /// Plaintext bytes transferred.
    pub bytes_transferred: u64,
}

/// Sequential single-file transfer engine.
#[derive(Clone, Debug)]
pub struct TransferEngine {
    chunk_size: usize,
}

impl TransferEngine {
    /// Creates a transfer engine using a fixed chunk size.
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Sends one file over an established frame connection.
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

        let total_bytes = metadata.len();
        let file_hash = hash_file(&path).await?;
        let transfer_id = transfer_id_for_hash(&file_hash);

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
                file_hash: file_hash.clone(),
            }))
            .await?;
        let resume_status = expect_resume_status(
            connection.recv_frame().await?,
            &transfer_id,
            self.chunk_size,
        )?;
        if resume_status.bytes_received > total_bytes {
            return Err(CoreError::Transfer(format!(
                "receiver resume offset {} exceeds file size {total_bytes}",
                resume_status.bytes_received
            )));
        }

        events.on_event(TransferEvent::Started {
            transfer_id: transfer_id.clone(),
            direction: TransferDirection::Send,
            file_name: file_name.clone(),
            total_bytes,
        });

        let mut file = LocalFileStorage::open_source(&path).await?;
        file.seek(SeekFrom::Start(resume_status.bytes_received))
            .await?;
        let mut buffer = vec![0_u8; self.chunk_size];
        let mut index = resume_status.next_chunk_index;
        let mut offset = resume_status.bytes_received;

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            connection
                .send_frame(Frame::Chunk(Chunk {
                    transfer_id: transfer_id.clone(),
                    index,
                    offset,
                    bytes: buffer[..bytes_read].to_vec(),
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
                file_hash: file_hash.clone(),
            }))
            .await?;
        match connection.recv_frame().await {
            Ok(frame) => expect_complete_ack(frame, &transfer_id).map_err(|error| {
                CoreError::Transfer(format!(
                    "transfer interrupted before completion acknowledgement: {error}"
                ))
            })?,
            Err(error) => {
                return Err(CoreError::Transfer(format!(
                    "transfer interrupted before completion acknowledgement: {error}"
                )));
            }
        }
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

    /// Receives one file over an established frame connection.
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
        // file exists
        // either this is a different file -> abort
        // or this is the same file -> skip to complete phase
        if fs::try_exists(&final_path).await? {
            let final_hash = hash_file(&final_path).await?;
            if final_hash != header.file_hash {
                return Err(CoreError::Storage(format!(
                    "destination already exists with different content: {}",
                    final_path.display()
                )));
            }

            connection
                .send_frame(Frame::ResumeStatus(ResumeStatus {
                    transfer_id: header.transfer_id.clone(),
                    next_chunk_index: next_chunk_index(header.file_size, header.chunk_size),
                    bytes_received: header.file_size,
                }))
                .await?;
            let complete = expect_complete(connection.recv_frame().await?, &header.transfer_id)?;
            if complete.file_hash != header.file_hash {
                return Err(CoreError::Transfer(format!(
                    "complete hash {} does not match header hash {}",
                    complete.file_hash, header.file_hash
                )));
            }
            connection
                .send_frame(Frame::CompleteAck(CompleteAck {
                    transfer_id: header.transfer_id.clone(),
                }))
                .await?;

            events.on_event(TransferEvent::Completed {
                transfer_id: header.transfer_id.clone(),
                bytes_transferred: header.file_size,
            });

            return Ok(TransferSummary {
                transfer_id: header.transfer_id,
                file_name: header.file_name,
                bytes_transferred: header.file_size,
            });
        }

        let mut state = load_or_create_resume_state(&output_dir, &header).await?;
        let temp_path = LocalFileStorage::resumable_temp_path(
            &output_dir,
            &state.file_name,
            &state.transfer_id,
        )?;
        let temp_len = match fs::metadata(&temp_path).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(CoreError::from(error)),
        };
        if temp_len != state.bytes_received {
            if temp_len > state.file_size {
                return Err(CoreError::Storage(format!(
                    "resume temp length {temp_len} exceeds recorded file size {}",
                    state.file_size
                )));
            }
            tracing::warn!(
                "resume temp length {temp_len} does not match recorded length {}; trusting temp file",
                state.bytes_received
            );
            state.bytes_received = temp_len;
            state.next_chunk_index = next_chunk_index(temp_len, state.chunk_size);
            LocalFileStorage::write_resume_state(&output_dir, &state).await?;
        }
        let (temp_path, mut file) =
            LocalFileStorage::open_resumable_destination(&output_dir, &state).await?;

        connection
            .send_frame(Frame::ResumeStatus(ResumeStatus {
                transfer_id: header.transfer_id.clone(),
                next_chunk_index: state.next_chunk_index,
                bytes_received: state.bytes_received,
            }))
            .await?;

        events.on_event(TransferEvent::Started {
            transfer_id: header.transfer_id.clone(),
            direction: TransferDirection::Receive,
            file_name: header.file_name.clone(),
            total_bytes: header.file_size,
        });

        let mut expected_index = state.next_chunk_index;
        let mut expected_offset = state.bytes_received;
        let mut last_resume_state_bytes = state.bytes_received;
        events.on_event(TransferEvent::Progress {
            transfer_id: header.transfer_id.clone(),
            bytes_transferred: expected_offset,
            total_bytes: header.file_size,
        });

        loop {
            match connection.recv_frame().await? {
                Frame::Chunk(chunk) => {
                    validate_chunk(&chunk, &header.transfer_id, expected_index, expected_offset)?;
                    if chunk.bytes.len() as u64 + expected_offset > header.file_size {
                        return Err(CoreError::Transfer(format!(
                            "chunk data exceeds expected file size: chunk offset {} + data length {} > expected file size {}",
                            chunk.offset,
                            chunk.bytes.len(),
                            header.file_size
                        )));
                    }
                    file.write_all(&chunk.bytes).await?;

                    expected_index += 1;
                    expected_offset += chunk.bytes.len() as u64;
                    if expected_offset.saturating_sub(last_resume_state_bytes)
                        >= RESUME_STATE_WRITE_INTERVAL
                    {
                        write_resume_state_for_offset(
                            &output_dir,
                            &header,
                            expected_offset,
                            expected_index,
                        )
                        .await?;
                        last_resume_state_bytes = expected_offset;
                    }
                    events.on_event(TransferEvent::Progress {
                        transfer_id: header.transfer_id.clone(),
                        bytes_transferred: expected_offset,
                        total_bytes: header.file_size,
                    });
                }
                Frame::Complete(complete) if complete.transfer_id == header.transfer_id => {
                    if complete.file_hash != header.file_hash {
                        return Err(CoreError::Transfer(format!(
                            "complete hash {} does not match header hash {}",
                            complete.file_hash, header.file_hash
                        )));
                    }
                    if expected_offset != header.file_size {
                        return Err(CoreError::Transfer(format!(
                            "transfer complete but expected offset {expected_offset} does not match file size {}",
                            header.file_size
                        )));
                    }
                    file.flush().await?;
                    drop(file);
                    let actual_hash = hash_file(&temp_path).await?;
                    if actual_hash != header.file_hash {
                        return Err(CoreError::Transfer(format!(
                            "completed file hash {actual_hash} does not match expected {}",
                            header.file_hash
                        )));
                    }
                    LocalFileStorage::finalize_temp_file(&temp_path, &final_path).await?;
                    LocalFileStorage::delete_resume_state(
                        &output_dir,
                        &header.file_name,
                        &header.transfer_id,
                    )
                    .await?;
                    connection
                        .send_frame(Frame::CompleteAck(CompleteAck {
                            transfer_id: header.transfer_id.clone(),
                        }))
                        .await?;
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

fn expect_resume_status(
    frame: Frame,
    transfer_id: &TransferId,
    chunk_size: usize,
) -> Result<ResumeStatus, TransferError> {
    match frame {
        Frame::ResumeStatus(status)
            if &status.transfer_id == transfer_id
                && status.next_chunk_index
                    == next_chunk_index(status.bytes_received, chunk_size as u64) =>
        {
            Ok(status)
        }
        frame => Err(CoreError::Transfer(format!(
            "expected valid ResumeStatus for {transfer_id}, got {frame:?}"
        ))),
    }
}

fn expect_complete_ack(frame: Frame, transfer_id: &TransferId) -> Result<(), TransferError> {
    match frame {
        Frame::CompleteAck(ack) if &ack.transfer_id == transfer_id => Ok(()),
        frame => Err(CoreError::Transfer(format!(
            "expected CompleteAck for {transfer_id}, got {frame:?}"
        ))),
    }
}

fn expect_complete(frame: Frame, transfer_id: &TransferId) -> Result<Complete, TransferError> {
    match frame {
        Frame::Complete(complete) if &complete.transfer_id == transfer_id => Ok(complete),
        frame => Err(CoreError::Transfer(format!(
            "expected Complete for {transfer_id}, got {frame:?}"
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

async fn write_resume_state_for_offset(
    output_dir: &Path,
    header: &FileHeader,
    bytes_received: u64,
    next_chunk_index: u64,
) -> Result<(), TransferError> {
    LocalFileStorage::write_resume_state(
        output_dir,
        &TransferResumeState {
            transfer_id: header.transfer_id.clone(),
            file_name: header.file_name.clone(),
            file_size: header.file_size,
            chunk_size: header.chunk_size,
            expected_file_hash: header.file_hash.clone(),
            bytes_received,
            next_chunk_index,
        },
    )
    .await
}

async fn load_or_create_resume_state(
    output_dir: &Path,
    header: &FileHeader,
) -> Result<TransferResumeState, TransferError> {
    if header.chunk_size == 0 {
        return Err(CoreError::Transfer("chunk size must be positive".into()));
    }

    let state =
        LocalFileStorage::read_resume_state(output_dir, &header.file_name, &header.transfer_id)
            .await?;

    match state {
        Some(state) => {
            if state.file_size != header.file_size
                || state.chunk_size != header.chunk_size
                || state.expected_file_hash != header.file_hash
            {
                return Err(CoreError::Storage(format!(
                    "resume state does not match incoming header for {}",
                    header.file_name
                )));
            }
            Ok(state)
        }
        None => {
            let state = TransferResumeState {
                transfer_id: header.transfer_id.clone(),
                file_name: header.file_name.clone(),
                file_size: header.file_size,
                chunk_size: header.chunk_size,
                expected_file_hash: header.file_hash.clone(),
                bytes_received: 0,
                next_chunk_index: 0,
            };
            LocalFileStorage::write_resume_state(output_dir, &state).await?;
            Ok(state)
        }
    }
}

async fn hash_file(path: &Path) -> Result<String, TransferError> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; DEFAULT_CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn transfer_id_for_hash(file_hash: &str) -> TransferId {
    TransferId::new(format!("transfer-{file_hash}"))
}

fn next_chunk_index(bytes_received: u64, chunk_size: u64) -> u64 {
    if bytes_received == 0 {
        0
    } else {
        bytes_received.div_ceil(chunk_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
                TransferEngine::new(4)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
                    .unwrap()
            }
        });

        let send_summary = TransferEngine::new(4)
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

    #[tokio::test]
    async fn resumes_after_receiver_stops_mid_transfer() {
        let root = unique_test_dir();
        let source_dir = root.join("source");
        let output_dir = root.join("output");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        let source_path = source_dir.join("resume.txt");
        tokio::fs::write(&source_path, b"resume over two connections")
            .await
            .unwrap();

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let stopped = std::sync::Arc::new(AtomicBool::new(false));
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            let stopped = stopped.clone();
            async move {
                TransferEngine::new(4)
                    .receive_file(
                        &mut receiver_connection,
                        output_dir,
                        &StopAfterBytesSink { bytes: 8, stopped },
                    )
                    .await
            }
        });

        let send_error = TransferEngine::new(4)
            .send_file(&mut sender_connection, source_path.clone(), &NoopEventSink)
            .await
            .unwrap_err();
        assert!(matches!(
            send_error,
            CoreError::Transport(_) | CoreError::Transfer(_)
        ));
        match receiver.await {
            Ok(result) => assert!(result.is_err() || stopped.load(Ordering::SeqCst)),
            Err(_) => assert!(stopped.load(Ordering::SeqCst)),
        }

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            async move {
                TransferEngine::new(4)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
                    .unwrap()
            }
        });

        let send_summary = TransferEngine::new(4)
            .send_file(&mut sender_connection, source_path, &NoopEventSink)
            .await
            .unwrap();
        let receive_summary = receiver.await.unwrap();

        assert_eq!(send_summary.bytes_transferred, 27);
        assert_eq!(receive_summary.bytes_transferred, 27);
        assert_eq!(
            tokio::fs::read(output_dir.join("resume.txt"))
                .await
                .unwrap(),
            b"resume over two connections"
        );

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn integrity_failure_does_not_finalize_file() {
        let root = unique_test_dir();
        let source_dir = root.join("source");
        let output_dir = root.join("output");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        tokio::fs::create_dir_all(&output_dir).await.unwrap();
        let source_path = source_dir.join("corrupt.txt");
        let source_bytes = b"abcdefghij";
        tokio::fs::write(&source_path, source_bytes).await.unwrap();

        let file_hash = blake3::hash(source_bytes).to_hex().to_string();
        let transfer_id = transfer_id_for_hash(&file_hash);
        let state = TransferResumeState {
            transfer_id: transfer_id.clone(),
            file_name: "corrupt.txt".into(),
            file_size: source_bytes.len() as u64,
            chunk_size: 5,
            expected_file_hash: file_hash,
            bytes_received: 5,
            next_chunk_index: 1,
        };
        LocalFileStorage::write_resume_state(&output_dir, &state)
            .await
            .unwrap();
        let temp_path =
            LocalFileStorage::resumable_temp_path(&output_dir, "corrupt.txt", &transfer_id)
                .unwrap();
        tokio::fs::write(&temp_path, b"xxxxx").await.unwrap();

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            async move {
                TransferEngine::new(5)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
            }
        });

        let send_error = TransferEngine::new(5)
            .send_file(&mut sender_connection, source_path, &NoopEventSink)
            .await
            .unwrap_err();
        let receive_error = receiver.await.unwrap().unwrap_err();

        assert!(matches!(send_error, CoreError::Transfer(_)));
        assert!(matches!(receive_error, CoreError::Transfer(_)));
        assert!(
            !fs::try_exists(output_dir.join("corrupt.txt"))
                .await
                .unwrap()
        );
        assert!(fs::try_exists(temp_path).await.unwrap());

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn resumes_from_temp_file_when_sidecar_offset_is_stale() {
        let root = unique_test_dir();
        let source_dir = root.join("source");
        let output_dir = root.join("output");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        tokio::fs::create_dir_all(&output_dir).await.unwrap();
        let source_path = source_dir.join("stale-sidecar.txt");
        let source_bytes = b"abcdefghij";
        tokio::fs::write(&source_path, source_bytes).await.unwrap();

        let file_hash = blake3::hash(source_bytes).to_hex().to_string();
        let transfer_id = transfer_id_for_hash(&file_hash);
        let state = TransferResumeState {
            transfer_id: transfer_id.clone(),
            file_name: "stale-sidecar.txt".into(),
            file_size: source_bytes.len() as u64,
            chunk_size: 5,
            expected_file_hash: file_hash,
            bytes_received: 0,
            next_chunk_index: 0,
        };
        LocalFileStorage::write_resume_state(&output_dir, &state)
            .await
            .unwrap();
        let temp_path =
            LocalFileStorage::resumable_temp_path(&output_dir, "stale-sidecar.txt", &transfer_id)
                .unwrap();
        tokio::fs::write(&temp_path, b"abcde").await.unwrap();

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            async move {
                TransferEngine::new(5)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
                    .unwrap()
            }
        });

        let send_summary = TransferEngine::new(5)
            .send_file(&mut sender_connection, source_path, &NoopEventSink)
            .await
            .unwrap();
        let receive_summary = receiver.await.unwrap();

        assert_eq!(send_summary.bytes_transferred, 10);
        assert_eq!(receive_summary.bytes_transferred, 10);
        assert_eq!(
            tokio::fs::read(output_dir.join("stale-sidecar.txt"))
                .await
                .unwrap(),
            source_bytes
        );

        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn already_complete_matching_file_returns_success() {
        let root = unique_test_dir();
        let source_dir = root.join("source");
        let output_dir = root.join("output");
        tokio::fs::create_dir_all(&source_dir).await.unwrap();
        tokio::fs::create_dir_all(&output_dir).await.unwrap();
        let source_path = source_dir.join("done.txt");
        tokio::fs::write(&source_path, b"already done")
            .await
            .unwrap();
        tokio::fs::write(output_dir.join("done.txt"), b"already done")
            .await
            .unwrap();

        let (mut sender_connection, mut receiver_connection) = memory_connection_pair();
        let receiver = tokio::spawn({
            let output_dir = output_dir.clone();
            async move {
                TransferEngine::new(4)
                    .receive_file(&mut receiver_connection, output_dir, &NoopEventSink)
                    .await
                    .unwrap()
            }
        });

        let send_summary = TransferEngine::new(4)
            .send_file(&mut sender_connection, source_path, &NoopEventSink)
            .await
            .unwrap();
        let receive_summary = receiver.await.unwrap();

        assert_eq!(send_summary.bytes_transferred, 12);
        assert_eq!(receive_summary.bytes_transferred, 12);

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

    struct StopAfterBytesSink {
        bytes: u64,
        stopped: std::sync::Arc<AtomicBool>,
    }

    impl EventSink for StopAfterBytesSink {
        fn on_event(&self, event: TransferEvent) {
            if let TransferEvent::Progress {
                bytes_transferred, ..
            } = event
                && bytes_transferred >= self.bytes
                && bytes_transferred > 0
            {
                self.stopped.store(true, Ordering::SeqCst);
                panic!("simulated receiver stop after {bytes_transferred} bytes");
            }
        }
    }

    fn unique_test_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "envoix-transfer-test-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }
}
