//! Typed errors. Each variant maps 1:1 to a wire `code` in design §3.4.
//!
//! The HTTP status mapping lives on this type rather than in the API layer
//! so the binary crate stays a thin transport translator.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("session closed")]
    SessionClosed,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("unsupported version")]
    UnsupportedVersion,

    #[error("capacity exceeded")]
    CapacityExceeded,

    #[error("service shutting down")]
    ServiceShuttingDown,

    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable wire code per design §3.4.
    pub fn code(&self) -> &'static str {
        todo!()
    }

    /// HTTP status the API layer should respond with.
    pub fn http_status(&self) -> u16 {
        todo!()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
