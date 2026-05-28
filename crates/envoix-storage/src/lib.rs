//! Local file and transfer-state storage.

use std::path::{Component, Path, PathBuf};

use envoix_error::CoreError;
use envoix_types::TransferId;
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File, OpenOptions};

/// Error type returned by local storage operations.
pub type StorageError = CoreError;

/// Filesystem-backed storage used by the current transfer engine.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalFileStorage;

/// Durable receiver-side state used to resume an interrupted transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferResumeState {
    /// Transfer identifier derived from the expected file hash.
    pub transfer_id: TransferId,
    /// Plain destination file name, without path components.
    pub file_name: String,
    /// Expected final file length in bytes.
    pub file_size: u64,
    /// Chunk size declared by the sender for this transfer.
    pub chunk_size: u64,
    /// Expected BLAKE3 hash of the complete plaintext file, hex-encoded.
    pub expected_file_hash: String,
    /// Number of plaintext bytes already persisted in the temp file.
    pub bytes_received: u64,
    /// Next sequential chunk index expected from the sender.
    pub next_chunk_index: u64,
}

impl LocalFileStorage {
    /// Opens a source file for reading.
    pub async fn open_source(path: &Path) -> Result<File, StorageError> {
        File::open(path).await.map_err(CoreError::from)
    }

    /// Creates a non-resumable temp destination for a new file.
    pub async fn create_temp_destination(
        output_dir: &Path,
        file_name: &str,
    ) -> Result<(PathBuf, File), StorageError> {
        if !is_plain_file_name(file_name) {
            return Err(CoreError::Storage(format!(
                "invalid output file name: {file_name}"
            )));
        }

        fs::create_dir_all(output_dir).await?;

        let temp_path = output_dir.join(format!(".{file_name}.part"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;

        Ok((temp_path, file))
    }

    /// Opens the deterministic resumable temp file in append mode.
    pub async fn open_resumable_destination(
        output_dir: &Path,
        state: &TransferResumeState,
    ) -> Result<(PathBuf, File), StorageError> {
        validate_resume_state_name(state)?;
        fs::create_dir_all(output_dir).await?;

        let temp_path = resumable_temp_path(output_dir, &state.file_name, &state.transfer_id);
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&temp_path)
            .await?;

        Ok((temp_path, file))
    }

    /// Renames a verified temp file to its final destination.
    pub async fn finalize_temp_file(
        temp_path: &Path,
        final_path: &Path,
    ) -> Result<(), StorageError> {
        if fs::try_exists(final_path).await? {
            return Err(CoreError::Storage(format!(
                "destination already exists: {}",
                final_path.display()
            )));
        }

        fs::rename(temp_path, final_path).await?;
        Ok(())
    }

    /// Reads the JSON sidecar state for a resumable transfer, if present.
    pub async fn read_resume_state(
        output_dir: &Path,
        file_name: &str,
        transfer_id: &TransferId,
    ) -> Result<Option<TransferResumeState>, StorageError> {
        validate_resume_path_parts(file_name, transfer_id)?;
        let state_path = resumable_state_path(output_dir, file_name, transfer_id);

        if !fs::try_exists(&state_path).await? {
            return Ok(None);
        }

        let bytes = fs::read(&state_path).await?;
        let state = serde_json::from_slice(&bytes)
            .map_err(|error| CoreError::Storage(format!("invalid resume state: {error}")))?;
        Ok(Some(state))
    }

    /// Writes or replaces the JSON sidecar state for a resumable transfer.
    pub async fn write_resume_state(
        output_dir: &Path,
        state: &TransferResumeState,
    ) -> Result<(), StorageError> {
        validate_resume_state_name(state)?;
        fs::create_dir_all(output_dir).await?;

        let state_path = resumable_state_path(output_dir, &state.file_name, &state.transfer_id);
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        fs::write(state_path, bytes).await?;
        Ok(())
    }

    /// Deletes the JSON sidecar state after a transfer is finalized.
    pub async fn delete_resume_state(
        output_dir: &Path,
        file_name: &str,
        transfer_id: &TransferId,
    ) -> Result<(), StorageError> {
        validate_resume_path_parts(file_name, transfer_id)?;
        let state_path = resumable_state_path(output_dir, file_name, transfer_id);
        if fs::try_exists(&state_path).await? {
            fs::remove_file(state_path).await?;
        }
        Ok(())
    }

    /// Returns the deterministic temp path for a resumable transfer.
    pub fn resumable_temp_path(
        output_dir: &Path,
        file_name: &str,
        transfer_id: &TransferId,
    ) -> Result<PathBuf, StorageError> {
        validate_resume_path_parts(file_name, transfer_id)?;
        Ok(resumable_temp_path(output_dir, file_name, transfer_id))
    }
}

fn is_plain_file_name(file_name: &str) -> bool {
    let mut components = Path::new(file_name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn validate_resume_state_name(state: &TransferResumeState) -> Result<(), StorageError> {
    validate_resume_path_parts(&state.file_name, &state.transfer_id)
}

fn validate_resume_path_parts(
    file_name: &str,
    transfer_id: &TransferId,
) -> Result<(), StorageError> {
    if !is_plain_file_name(file_name) {
        return Err(CoreError::Storage(format!(
            "invalid output file name: {file_name}"
        )));
    }
    if !is_plain_file_name(&transfer_id.0) {
        return Err(CoreError::Storage(format!(
            "invalid transfer id: {transfer_id}"
        )));
    }
    Ok(())
}

fn resumable_temp_path(output_dir: &Path, file_name: &str, transfer_id: &TransferId) -> PathBuf {
    output_dir.join(format!(".{file_name}.{transfer_id}.part"))
}

fn resumable_state_path(output_dir: &Path, file_name: &str, transfer_id: &TransferId) -> PathBuf {
    output_dir.join(format!(".{file_name}.{transfer_id}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn creates_and_finalizes_temp_destination() {
        let dir = unique_test_dir();
        let final_path = dir.join("hello.txt");

        let (temp_path, mut file) = LocalFileStorage::create_temp_destination(&dir, "hello.txt")
            .await
            .unwrap();
        let text = b"hello";
        file.write_all(text).await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        LocalFileStorage::finalize_temp_file(&temp_path, &final_path)
            .await
            .unwrap();

        assert_eq!(fs::read(&final_path).await.unwrap(), text);
        fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_nested_destination_file_name() {
        let dir = unique_test_dir();

        let error = LocalFileStorage::create_temp_destination(&dir, "../hello.txt")
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::Storage(_)));
    }

    #[tokio::test]
    async fn writes_reads_updates_and_deletes_resume_state() {
        let dir = unique_test_dir();
        let state = TransferResumeState {
            transfer_id: TransferId::new("transfer-1"),
            file_name: "hello.txt".into(),
            file_size: 11,
            chunk_size: 4,
            expected_file_hash: "abc123".into(),
            bytes_received: 4,
            next_chunk_index: 1,
        };

        LocalFileStorage::write_resume_state(&dir, &state)
            .await
            .unwrap();
        assert_eq!(
            LocalFileStorage::read_resume_state(&dir, "hello.txt", &state.transfer_id)
                .await
                .unwrap(),
            Some(state.clone())
        );

        let mut updated = state.clone();
        updated.bytes_received = 8;
        updated.next_chunk_index = 2;
        LocalFileStorage::write_resume_state(&dir, &updated)
            .await
            .unwrap();
        assert_eq!(
            LocalFileStorage::read_resume_state(&dir, "hello.txt", &state.transfer_id)
                .await
                .unwrap(),
            Some(updated.clone())
        );

        LocalFileStorage::delete_resume_state(&dir, "hello.txt", &state.transfer_id)
            .await
            .unwrap();
        assert_eq!(
            LocalFileStorage::read_resume_state(&dir, "hello.txt", &state.transfer_id)
                .await
                .unwrap(),
            None
        );

        fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn opens_deterministic_resume_temp_for_append() {
        let dir = unique_test_dir();
        let state = TransferResumeState {
            transfer_id: TransferId::new("transfer-1"),
            file_name: "hello.txt".into(),
            file_size: 11,
            chunk_size: 4,
            expected_file_hash: "abc123".into(),
            bytes_received: 0,
            next_chunk_index: 0,
        };

        let (temp_path, mut file) = LocalFileStorage::open_resumable_destination(&dir, &state)
            .await
            .unwrap();
        file.write_all(b"hello").await.unwrap();
        drop(file);

        let (second_temp_path, mut file) =
            LocalFileStorage::open_resumable_destination(&dir, &state)
                .await
                .unwrap();
        file.write_all(b" world").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        assert_eq!(second_temp_path, temp_path);
        assert_eq!(fs::read(temp_path).await.unwrap(), b"hello world");
        fs::remove_dir_all(&dir).await.unwrap();
    }

    fn unique_test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "envoix-storage-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }
}
