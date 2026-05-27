//! Public application-facing facade for envoix clients.

use std::net::SocketAddr;
use std::path::PathBuf;

use envoix_error::CoreError;
pub use envoix_session::{
    EventSink, NoopEventSink, TransferDirection, TransferEvent, TransferSummary,
};
use envoix_session::{SessionConfig, receive_file_ipv6, send_file_manual_ipv6};

pub type PublicError = CoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub chunk_size: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            chunk_size: envoix_session::DEFAULT_CHUNK_SIZE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendFileRequest {
    pub peer_addr: SocketAddr,
    pub file_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveFileRequest {
    pub listen_addr: SocketAddr,
    pub output_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct EnvoixClient {
    config: ClientConfig,
}

impl EnvoixClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn send_file(
        &self,
        request: SendFileRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        send_file_manual_ipv6(
            request.peer_addr,
            request.file_path,
            self.session_config(),
            events,
        )
        .await
    }

    pub async fn receive_file(
        &self,
        request: ReceiveFileRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        receive_file_ipv6(
            request.listen_addr,
            request.output_dir,
            self.session_config(),
            events,
        )
        .await
    }

    fn validate_config(&self) -> Result<(), PublicError> {
        if self.config.chunk_size == 0 {
            return Err(CoreError::InvalidInput(
                "chunk size must be positive".into(),
            ));
        }

        Ok(())
    }

    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            chunk_size: self.config.chunk_size,
        }
    }
}

impl Default for EnvoixClient {
    fn default() -> Self {
        Self::new(ClientConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_zero_chunk_size() {
        let client = EnvoixClient::new(ClientConfig { chunk_size: 0 });

        let error = client
            .send_file(
                SendFileRequest {
                    peer_addr: "[::1]:9000".parse().unwrap(),
                    file_path: "missing.txt".into(),
                },
                Box::new(NoopEventSink),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }
}
