//! Shared error categories.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("discovery error: {0}")]
    Discovery(String),
    #[error("transfer error: {0}")]
    Transfer(String),
    #[error("operation cancelled")]
    Cancelled,
}

impl From<std::io::Error> for CoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
