//! Local file and transfer-state storage.

use std::path::{Component, Path, PathBuf};

use envoix_error::CoreError;
use tokio::fs::{self, File, OpenOptions};

pub type StorageError = CoreError;

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalFileStorage;

impl LocalFileStorage {
    pub async fn open_source(path: &Path) -> Result<File, StorageError> {
        File::open(path).await.map_err(CoreError::from)
    }

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
}

fn is_plain_file_name(file_name: &str) -> bool {
    let mut components = Path::new(file_name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
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

    fn unique_test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "envoix-storage-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }
}
