//! Public application-facing facade for envoix clients.

use std::net::SocketAddr;
use std::path::PathBuf;

pub use envoix_auth::{PairingConfig, SPAKE2_EXPERIMENTAL_WARNING};
use envoix_error::CoreError;
pub use envoix_session::{
    EventSink, NoopEventSink, TransferDirection, TransferEvent, TransferSummary,
};
use envoix_session::{SessionConfig, receive_file_with_bound_addr, send_file_manual};

/// Error type exposed by the public client facade.
pub type PublicError = CoreError;

/// Public client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Maximum chunk payload size used for transfers.
    pub chunk_size: usize,
    /// Pairing authentication required before transfer.
    pub pairing: PairingConfig,
}

impl ClientConfig {
    /// Creates config using the default chunk size and required pairing auth.
    pub fn new(pairing: PairingConfig) -> Self {
        Self {
            chunk_size: envoix_session::DEFAULT_CHUNK_SIZE,
            pairing,
        }
    }
}

/// Request to send one local file to a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendFileRequest {
    /// Peer socket address to connect to.
    pub peer_addr: SocketAddr,
    /// Local file path to send.
    pub file_path: PathBuf,
}

/// Request to receive one file into a local directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveFileRequest {
    /// Local socket address to listen on.
    pub listen_addr: SocketAddr,
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
}

/// Public facade for sending and receiving files.
#[derive(Clone, Debug)]
pub struct EnvoixClient {
    config: ClientConfig,
}

impl EnvoixClient {
    /// Creates a client with explicit configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Sends one file according to `request`.
    pub async fn send_file(
        &self,
        request: SendFileRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        send_file_manual(
            request.peer_addr,
            request.file_path,
            self.session_config(),
            events,
        )
        .await
    }

    /// Receives one file and reports the concrete bound address before accepting.
    pub async fn receive_file_with_bound_addr<F>(
        &self,
        request: ReceiveFileRequest,
        events: Box<dyn EventSink>,
        on_bound_addr: F,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(SocketAddr) + Send,
    {
        self.validate_config()?;
        receive_file_with_bound_addr(
            request.listen_addr,
            request.output_dir,
            self.session_config(),
            events,
            on_bound_addr,
        )
        .await
    }

    fn validate_config(&self) -> Result<(), PublicError> {
        if self.config.chunk_size == 0 {
            return Err(CoreError::InvalidInput(
                "chunk size must be positive".into(),
            ));
        }
        self.config.pairing.validate()?;

        Ok(())
    }

    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            chunk_size: self.config.chunk_size,
            pairing: self.config.pairing.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_zero_chunk_size() {
        let client = EnvoixClient::new(ClientConfig {
            chunk_size: 0,
            pairing: test_pairing(),
        });

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

    fn test_pairing() -> PairingConfig {
        PairingConfig::spake2_shared_token("abcdefghijkl").unwrap()
    }
}
