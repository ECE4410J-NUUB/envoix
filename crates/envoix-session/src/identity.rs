use std::path::{Path, PathBuf};

use anyhow::{Context, Result as AnyResult, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use envoix_error::CoreError;
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::SessionError;

const IDENTITY_FILE_VERSION: u32 = 1;

/// iroh endpoint identity policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum IdentityConfig {
    /// Generate a fresh endpoint identity for this process.
    #[default]
    Ephemeral,
    /// Load an existing identity from this file, creating one if missing.
    Persistent(PathBuf),
}

pub(crate) async fn load_secret_key(identity: &IdentityConfig) -> Result<SecretKey, SessionError> {
    match identity {
        IdentityConfig::Ephemeral => Ok(SecretKey::generate()),
        IdentityConfig::Persistent(path) => load_or_create_identity(path)
            .await
            .map_err(|error| CoreError::InvalidInput(error.to_string())),
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct IdentityFile {
    version: u32,
    secret_key: String,
}

async fn load_or_create_identity(path: &Path) -> AnyResult<SecretKey> {
    if fs::try_exists(path)
        .await
        .with_context(|| format!("failed to check identity file {}", path.display()))?
    {
        return read_identity(path).await;
    }

    let secret_key = SecretKey::generate();
    let file = IdentityFile {
        version: IDENTITY_FILE_VERSION,
        secret_key: URL_SAFE_NO_PAD.encode(secret_key.to_bytes()),
    };
    let text = serde_json::to_vec_pretty(&file).context("failed to encode identity file")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create identity directory {}", parent.display()))?;
    }
    write_new_identity_file(path, &text)
        .await
        .with_context(|| format!("failed to create identity file {}", path.display()))?;
    Ok(secret_key)
}

async fn read_identity(path: &Path) -> AnyResult<SecretKey> {
    let text = fs::read(path)
        .await
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    let file: IdentityFile =
        serde_json::from_slice(&text).context("identity file is not valid JSON")?;
    if file.version != IDENTITY_FILE_VERSION {
        return Err(anyhow!(
            "unsupported identity file version {}",
            file.version
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(file.secret_key.as_bytes())
        .context("identity secret is not valid base64url")?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity secret must be 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

#[cfg(unix)]
async fn write_new_identity_file(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).await?;
    use tokio::io::AsyncWriteExt as _;
    file.write_all(bytes).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write_new_identity_file(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    fs::write(path, bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn ephemeral_identity_generates_distinct_keys() {
        let a = load_secret_key(&IdentityConfig::Ephemeral).await.unwrap();
        let b = load_secret_key(&IdentityConfig::Ephemeral).await.unwrap();
        assert_ne!(a.public(), b.public());
    }

    #[tokio::test]
    async fn persistent_identity_is_created_and_reused() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("identity.json");

        let first = load_secret_key(&IdentityConfig::Persistent(path.clone()))
            .await
            .unwrap();
        let second = load_secret_key(&IdentityConfig::Persistent(path))
            .await
            .unwrap();

        assert_eq!(first.public(), second.public());
    }

    #[tokio::test]
    async fn invalid_identity_file_errors() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("identity.json");
        fs::write(&path, b"{\"version\":1,\"secret_key\":\"bad\"}")
            .await
            .unwrap();

        let error = load_secret_key(&IdentityConfig::Persistent(path))
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }
}
