//! Public application-facing facade for envoix clients.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub use envoix_auth::{PairingConfig, SPAKE2_EXPERIMENTAL_WARNING};
use envoix_error::CoreError;
pub use envoix_session::{
    EventSink, NoopEventSink, TransferDirection, TransferEvent, TransferSummary,
};
use envoix_session::{SessionConfig, receive_file_with_bound_addr, send_file_manual};
use serde::Deserialize;

/// Environment variable overriding the runtime transfer chunk size.
pub const ENVOIX_CHUNK_SIZE: &str = "ENVOIX_CHUNK_SIZE";
/// Minimum accepted transfer chunk size.
pub const MIN_CHUNK_SIZE: usize = 16 * 1024;
/// Maximum accepted transfer chunk size.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

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

    /// Creates config from default, optional TOML file, and environment overrides.
    pub fn from_runtime_sources(
        pairing: PairingConfig,
        config_path: Option<&Path>,
    ) -> Result<Self, PublicError> {
        Self::from_runtime_sources_with_env(
            pairing,
            config_path,
            std::env::var_os(ENVOIX_CHUNK_SIZE),
        )
    }

    fn from_runtime_sources_with_env(
        pairing: PairingConfig,
        config_path: Option<&Path>,
        env_chunk_size: Option<std::ffi::OsString>,
    ) -> Result<Self, PublicError> {
        let mut config = Self::new(pairing);

        if let Some(config_path) = config_path {
            let file_config = RuntimeConfig::read(config_path)?;
            if let Some(chunk_size) = file_config.chunk_size {
                config.chunk_size = parse_chunk_size(&chunk_size)?;
            }
        }

        if let Some(chunk_size) = env_chunk_size {
            let chunk_size = chunk_size.into_string().map_err(|_| {
                CoreError::InvalidInput(format!("{ENVOIX_CHUNK_SIZE} is not UTF-8"))
            })?;
            config.chunk_size = parse_chunk_size(&chunk_size)?;
        }

        config.validate()?;
        Ok(config)
    }

    /// Validates chunk sizing and pairing fields before starting a transfer.
    pub fn validate(&self) -> Result<(), PublicError> {
        validate_chunk_size(self.chunk_size)?;
        self.pairing.validate()?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    chunk_size: Option<String>,
}

impl RuntimeConfig {
    fn read(path: &Path) -> Result<Self, PublicError> {
        let text = fs::read_to_string(path).map_err(|error| {
            CoreError::InvalidInput(format!("failed to read config {}: {error}", path.display()))
        })?;
        toml::from_str(&text).map_err(|error| {
            CoreError::InvalidInput(format!("invalid config {}: {error}", path.display()))
        })
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

/// Automatic connection policy used by the mobile-facing facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionPolicy {
    /// Try supported connection strategies according to the client default order.
    Auto,
}

/// Request to send one local file using automatic pairing and connection setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRequest {
    /// Local file path to send.
    pub file_path: PathBuf,
    /// Connection strategy policy for this operation.
    pub connection_policy: ConnectionPolicy,
}

/// Request to receive one file using automatic pairing and connection setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveRequest {
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
    /// Connection strategy policy for this operation.
    pub connection_policy: ConnectionPolicy,
}

/// Advisory snapshot of the local network environment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkEnvironment {
    /// Whether local IPv4 connectivity appears available.
    pub ipv4_available: Option<bool>,
    /// Whether local IPv6 connectivity appears available.
    pub ipv6_available: Option<bool>,
    /// Whether UDP connectivity appears usable for QUIC.
    pub udp_available: Option<bool>,
    /// Whether the rendezvous server appears reachable.
    pub server_reachable: Option<bool>,
    /// Human-readable diagnostic notes for UI and logs.
    pub notes: Vec<String>,
}

/// Observer for client-level discovery, pairing, and connection events.
pub trait ClientEventSink: Send + Sync {
    /// Handles one client lifecycle event.
    fn on_event(&self, event: ClientEvent);
}

/// Event sink that ignores all client lifecycle events.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopClientEventSink;

impl ClientEventSink for NoopClientEventSink {
    fn on_event(&self, _event: ClientEvent) {}
}

/// User-visible lifecycle events above the transfer engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientEvent {
    /// Advisory network probing has started.
    NetworkDetectionStarted,
    /// Automatic connection setup has started.
    AutoConnectionStarted {
        /// Direction of this local operation.
        direction: TransferDirection,
    },
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

    /// Sends one file using automatic pairing and connection establishment.
    pub async fn send(
        &self,
        request: SendRequest,
        events: Box<dyn ClientEventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        let _ = request;
        events.on_event(ClientEvent::AutoConnectionStarted {
            direction: TransferDirection::Send,
        });
        Err(auto_not_implemented())
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

    /// Receives one file using automatic pairing and connection establishment.
    pub async fn receive(
        &self,
        request: ReceiveRequest,
        events: Box<dyn ClientEventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        let _ = request;
        events.on_event(ClientEvent::AutoConnectionStarted {
            direction: TransferDirection::Receive,
        });
        Err(auto_not_implemented())
    }

    /// Detects the local network environment for UI diagnostics and strategy hints.
    pub async fn detect_network_environment(
        &self,
        events: Box<dyn ClientEventSink>,
    ) -> Result<NetworkEnvironment, PublicError> {
        self.validate_config()?;
        events.on_event(ClientEvent::NetworkDetectionStarted);
        Err(CoreError::Discovery(
            "network environment detection is not implemented".into(),
        ))
    }

    fn validate_config(&self) -> Result<(), PublicError> {
        self.config.validate()
    }

    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            chunk_size: self.config.chunk_size,
            pairing: self.config.pairing.clone(),
        }
    }
}

fn auto_not_implemented() -> PublicError {
    CoreError::Discovery("automatic connection establishment is not implemented".into())
}

fn parse_chunk_size(value: &str) -> Result<usize, PublicError> {
    let value = value.trim();
    let (number, unit) = if let Some(number) = value.strip_suffix("KiB") {
        (number, 1024_usize)
    } else if let Some(number) = value.strip_suffix("Ki") {
        (number, 1024_usize)
    } else if let Some(number) = value.strip_suffix("MiB") {
        (number, 1024_usize * 1024)
    } else if let Some(number) = value.strip_suffix("Mi") {
        (number, 1024_usize * 1024)
    } else if let Some(number) = value.strip_suffix('B') {
        (number, 1_usize)
    } else {
        return Err(CoreError::InvalidInput(format!(
            "chunk size {value:?} must include B, KiB, or MiB"
        )));
    };

    if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(CoreError::InvalidInput(format!(
            "invalid chunk size {value:?}"
        )));
    }

    let count = number.parse::<usize>().map_err(|error| {
        CoreError::InvalidInput(format!("invalid chunk size {value:?}: {error}"))
    })?;
    let bytes = count.checked_mul(unit).ok_or_else(|| {
        CoreError::InvalidInput(format!("chunk size {value:?} exceeds supported range"))
    })?;
    validate_chunk_size(bytes)?;
    Ok(bytes)
}

fn validate_chunk_size(chunk_size: usize) -> Result<(), PublicError> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CoreError::InvalidInput(format!(
            "chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
        )));
    }

    Ok(())
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

    #[test]
    fn parses_human_readable_chunk_sizes() {
        assert_eq!(parse_chunk_size("16KiB").unwrap(), 16 * 1024);
        assert_eq!(parse_chunk_size("1MiB").unwrap(), 1024 * 1024);
        assert_eq!(parse_chunk_size("16384B").unwrap(), 16 * 1024);
    }

    #[test]
    fn rejects_bare_or_out_of_range_chunk_sizes() {
        assert!(matches!(
            parse_chunk_size("65536"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("15KiB"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("17MiB"),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn config_file_overrides_default_chunk_size() {
        let config_path = unique_test_path("config-overrides-default.toml");
        std::fs::write(&config_path, "chunk_size = \"1MiB\"\n").unwrap();

        let config =
            ClientConfig::from_runtime_sources_with_env(test_pairing(), Some(&config_path), None)
                .unwrap();

        assert_eq!(config.chunk_size, 1024 * 1024);
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn env_chunk_size_overrides_config_file() {
        let config_path = unique_test_path("env-overrides-config.toml");
        std::fs::write(&config_path, "chunk_size = \"1MiB\"\n").unwrap();

        let config = ClientConfig::from_runtime_sources_with_env(
            test_pairing(),
            Some(&config_path),
            Some("4MiB".into()),
        )
        .unwrap();

        assert_eq!(config.chunk_size, 4 * 1024 * 1024);
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn invalid_env_chunk_size_fails_early() {
        let error =
            ClientConfig::from_runtime_sources_with_env(test_pairing(), None, Some("65536".into()))
                .unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    fn test_pairing() -> PairingConfig {
        PairingConfig::spake2_shared_token("abcdefghijkl").unwrap()
    }

    fn unique_test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("envoix-client-test-{}-{name}", std::process::id()))
    }
}
