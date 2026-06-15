//! Typed errors. Each variant maps 1:1 to a wire `code`.
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
    /// Stable wire code; never change without bumping `/api/v2`.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidRequest(_) => "invalid_request",
            Error::Unauthorized => "unauthorized",
            Error::SessionNotFound => "session_not_found",
            Error::SessionExpired => "session_expired",
            Error::SessionClosed => "session_closed",
            Error::Conflict(_) => "conflict",
            Error::PayloadTooLarge => "payload_too_large",
            Error::UnsupportedVersion => "unsupported_version",
            Error::CapacityExceeded => "capacity_exceeded",
            Error::ServiceShuttingDown => "service_shutting_down",
            Error::Internal(_) => "internal",
        }
    }

    /// HTTP status the API layer should respond with. Status collisions are
    /// intentional; `code()` is what clients branch on.
    pub fn http_status(&self) -> u16 {
        match self {
            Error::InvalidRequest(_) => 400,
            Error::Unauthorized => 401,
            Error::SessionNotFound | Error::SessionExpired => 404,
            Error::Conflict(_) | Error::SessionClosed => 409,
            Error::PayloadTooLarge => 413,
            Error::UnsupportedVersion => 422,
            Error::CapacityExceeded | Error::ServiceShuttingDown => 503,
            Error::Internal(_) => 500,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_matches_design_table() {
        assert_eq!(Error::InvalidRequest("x".into()).code(), "invalid_request");
        assert_eq!(Error::Unauthorized.code(), "unauthorized");
        assert_eq!(Error::SessionNotFound.code(), "session_not_found");
        assert_eq!(Error::SessionExpired.code(), "session_expired");
        assert_eq!(Error::SessionClosed.code(), "session_closed");
        assert_eq!(Error::Conflict("x".into()).code(), "conflict");
        assert_eq!(Error::PayloadTooLarge.code(), "payload_too_large");
        assert_eq!(Error::UnsupportedVersion.code(), "unsupported_version");
        assert_eq!(Error::CapacityExceeded.code(), "capacity_exceeded");
        assert_eq!(Error::ServiceShuttingDown.code(), "service_shutting_down");
        assert_eq!(Error::Internal("x".into()).code(), "internal");
    }

    #[test]
    fn http_status_matches_design_table() {
        assert_eq!(Error::InvalidRequest("x".into()).http_status(), 400);
        assert_eq!(Error::Unauthorized.http_status(), 401);
        assert_eq!(Error::SessionNotFound.http_status(), 404);
        assert_eq!(Error::SessionExpired.http_status(), 404);
        assert_eq!(Error::SessionClosed.http_status(), 409);
        assert_eq!(Error::Conflict("x".into()).http_status(), 409);
        assert_eq!(Error::PayloadTooLarge.http_status(), 413);
        assert_eq!(Error::UnsupportedVersion.http_status(), 422);
        assert_eq!(Error::CapacityExceeded.http_status(), 503);
        assert_eq!(Error::ServiceShuttingDown.http_status(), 503);
        assert_eq!(Error::Internal("x".into()).http_status(), 500);
    }
}
