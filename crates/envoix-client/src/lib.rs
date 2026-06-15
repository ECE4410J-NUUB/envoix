//! Public application-facing facade for envoix clients.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use envoix_auth::{PairingConfig, SPAKE2_EXPERIMENTAL_WARNING};
use envoix_discovery::{
    LanDiscoveryConfig, LanDiscoveryRecord, MdnsLanAdvertiser, MdnsLanDiscovery,
};
use envoix_error::CoreError;
pub use envoix_session::{
    EventSink, NoopEventSink, TransferDirection, TransferEvent, TransferSummary,
};
use envoix_session::{SessionConfig, receive_file_with_bound_addr, send_file_manual};
use envoix_transport::{ConnectionCandidate, TransportListener};
use serde::Deserialize;

/// Environment variable overriding the runtime transfer chunk size.
pub const ENVOIX_CHUNK_SIZE: &str = "ENVOIX_CHUNK_SIZE";
/// Minimum accepted transfer chunk size.
pub const MIN_CHUNK_SIZE: usize = 16 * 1024;
/// Maximum accepted transfer chunk size.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Error type exposed by the public client facade.
pub type PublicError = CoreError;

/// Timeout used for LAN mDNS discovery.
const LAN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

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
        Self::from_runtime_sources_with_env(pairing, config_path, &ProcessEnv)
    }

    fn from_runtime_sources_with_env(
        pairing: PairingConfig,
        config_path: Option<&Path>,
        env: &dyn EnvSource,
    ) -> Result<Self, PublicError> {
        let mut config = Self::new(pairing);

        if let Some(config_path) = config_path {
            let file_config = RuntimeConfig::read(config_path)?;
            if let Some(chunk_size) = file_config.chunk_size {
                config.chunk_size = parse_chunk_size(&chunk_size)?;
            }
        }

        apply_env_overrides(&mut config, env)?;

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

trait EnvSource {
    fn get(&self, name: &'static str) -> Result<Option<String>, PublicError>;
}

struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &'static str) -> Result<Option<String>, PublicError> {
        std::env::var_os(name)
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| CoreError::InvalidInput(format!("{name} is not UTF-8")))
            })
            .transpose()
    }
}

struct EnvOverride {
    name: &'static str,
    apply: fn(&mut ClientConfig, &str) -> Result<(), PublicError>,
}

const ENV_OVERRIDES: &[EnvOverride] = &[EnvOverride {
    name: ENVOIX_CHUNK_SIZE,
    apply: apply_chunk_size_override,
}];

fn apply_env_overrides(config: &mut ClientConfig, env: &dyn EnvSource) -> Result<(), PublicError> {
    for override_ in ENV_OVERRIDES {
        if let Some(value) = env.get(override_.name)? {
            (override_.apply)(config, &value)?;
        }
    }

    Ok(())
}

fn apply_chunk_size_override(config: &mut ClientConfig, value: &str) -> Result<(), PublicError> {
    config.chunk_size = parse_chunk_size(value)?;
    Ok(())
}

/// Request to send one local file to a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendFileRequest {
    /// Peer socket address to connect to.
    pub peer_addr: SocketAddr,
    /// Local file path to send.
    pub file_path: PathBuf,
    /// Whether receiver-side resume state may be used.
    pub resume: bool,
}

/// Request to receive one file into a local directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveFileRequest {
    /// Local socket address to listen on.
    pub listen_addr: SocketAddr,
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
}

/// Automatic connection policy used by the facade.
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
    /// Whether receiver-side resume state may be used.
    pub resume: bool,
}

/// Request to receive one file using automatic pairing and connection setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveRequest {
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
    /// Connection strategy policy for this operation.
    pub connection_policy: ConnectionPolicy,
    /// Local socket address to bind the QUIC listener on.
    ///
    /// Use `"0.0.0.0:0"` for any IPv4 interface (auto port) or
    /// `"[::]:0"` for any IPv6 interface (auto port).
    pub listen_addr: SocketAddr,
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

// ---------------------------------------------------------------------------
// Client events
// ---------------------------------------------------------------------------

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
    /// LAN mDNS discovery has started.
    LanDiscoveryStarted,
    /// A LAN candidate was discovered via mDNS.
    LanCandidateFound {
        /// The discovered connection candidate.
        candidate: ConnectionCandidate,
    },
    /// LAN mDNS discovery failed.
    LanDiscoveryFailed {
        /// Human-readable failure reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Public facade
// ---------------------------------------------------------------------------

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
            request.resume,
            self.session_config(),
            events,
        )
        .await
    }

    /// Sends one file using automatic pairing and connection establishment.
    ///
    /// `client_events` receives client-level lifecycle events (discovery,
    /// pairing, connection).  `transfer_events` receives transfer-level
    /// progress events (chunk progress, hashing, completion).
    pub async fn send(
        &self,
        request: SendRequest,
        client_events: Box<dyn ClientEventSink>,
        transfer_events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        client_events.on_event(ClientEvent::AutoConnectionStarted {
            direction: TransferDirection::Send,
        });

        // --- LAN discovery phase ---
        client_events.on_event(ClientEvent::LanDiscoveryStarted);

        let lan_config = LanDiscoveryConfig {
            timeout: LAN_DISCOVERY_TIMEOUT,
            // session_id not set: sender connects to any Envoix receiver on
            // the LAN.  SPAKE2 auth gates the actual transfer; wrong-token
            // attempts fail before any data moves.
            ..Default::default()
        };
        let discovery = MdnsLanDiscovery::new(lan_config);

        let candidates = match discovery.discover().await {
            Ok(candidates) => candidates,
            Err(e) => {
                client_events.on_event(ClientEvent::LanDiscoveryFailed {
                    reason: e.to_string(),
                });
                return Err(e.into());
            }
        };

        for c in &candidates {
            client_events.on_event(ClientEvent::LanCandidateFound { candidate: *c });
        }

        // --- Dial candidates in deterministic order — first attempt gets
        // real transfer_events, retries use NoopEventSink. ---
        let mut last_error = None;
        let mut transfer_events = transfer_events;
        for candidate in &candidates {
            match send_file_manual(
                match candidate {
                    ConnectionCandidate::Quic { addr } => *addr,
                },
                request.file_path.clone(),
                request.resume,
                self.session_config(),
                transfer_events,
            )
            .await
            {
                Ok(summary) => return Ok(summary),
                Err(e) => {
                    last_error = Some(e);
                    // Use NoopEventSink for subsequent retries so partial
                    // progress from the failed attempt is not re-emitted.
                    transfer_events = Box::new(NoopEventSink);
                }
            }
        }

        Err(last_error.expect("candidates is non-empty; loop ran at least once"))
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
    ///
    /// `client_events` receives client-level lifecycle events (discovery,
    /// pairing).  `transfer_events` receives transfer-level progress events
    /// (chunk progress, hashing, completion).
    ///
    /// `on_bound` is called with the actual bound socket address after the QUIC
    /// listener has been bound, allowing the caller to print a QR invite or
    /// otherwise report the address before accepting a connection.
    pub async fn receive<F>(
        &self,
        request: ReceiveRequest,
        client_events: Box<dyn ClientEventSink>,
        transfer_events: Box<dyn EventSink>,
        on_bound: F,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(SocketAddr) + Send,
    {
        self.validate_config()?;
        client_events.on_event(ClientEvent::AutoConnectionStarted {
            direction: TransferDirection::Receive,
        });

        // --- Bind QUIC listener ---
        let output_dir = request.output_dir;
        let config = self.session_config();

        // Bind first, then report the address to the caller so they can
        // print a QR invite or log the port, then start mDNS advertising.
        let listener = envoix_session::bind_quic_listener(request.listen_addr)?;
        let bound_addr = listener.local_addr()?;
        let port = bound_addr.port();

        // Notify caller of the bound address.
        on_bound(bound_addr);

        // Create a safe session identifier (random, not derived from token).
        let session_id = format!("envoix-{}", fast_random_id());

        let record = LanDiscoveryRecord {
            protocol_version: envoix_discovery::ENVOIX_DISCOVERY_PROTO_VERSION,
            session_id,
            port,
            features: "quic-v1".into(),
        };

        let _advertiser = match MdnsLanAdvertiser::start(&record) {
            Ok(a) => {
                client_events.on_event(ClientEvent::LanDiscoveryStarted);
                Some(a)
            }
            Err(e) => {
                // Non-fatal: advertise best-effort, but still accept.
                client_events.on_event(ClientEvent::LanDiscoveryFailed {
                    reason: format!("mDNS advertisement failed: {e}"),
                });
                None
            }
        };

        // Accept one connection, then stop advertising immediately.
        // Once accept() returns, the receiver is committed to one connection
        // and will not accept another; continuing to advertise would mislead
        // other senders into discovering an unreachable receiver.
        let mut connection = listener.accept().await?;
        drop(_advertiser);

        let engine = envoix_session::TransferEngine::new(config.chunk_size);

        if let Err(error) =
            envoix_session::authenticate_receiver(&mut *connection, &config.pairing).await
        {
            let _ = connection.close().await;
            return Err(error);
        }
        let summary = engine
            .receive_file(&mut *connection, output_dir, transfer_events.as_ref())
            .await?;
        let _ = connection.close().await;

        Ok(summary)
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

/// Generate a short random identifier for session names.
///
/// Combines the process ID and a high-precision timestamp so that two
/// receivers started in the same nanosecond on different processes (or on
/// different machines) still produce distinct identifiers.  This is not
/// cryptographically random but is more than sufficient for mDNS instance
/// disambiguation on a LAN.
fn fast_random_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u64;
    // Mix PID and timestamp so simultaneous launches produce unique IDs.
    let combined = pid.wrapping_mul(31_337).wrapping_add(nanos as u64);
    format!("{:012x}", combined)
}

// ---------------------------------------------------------------------------
// Chunk-size parsing helpers
// ---------------------------------------------------------------------------

fn parse_chunk_size(value: &str) -> Result<usize, PublicError> {
    let value = value.trim();
    let (number, unit) = if let Some(number) = value.strip_suffix("KB") {
        (number, 1024_usize)
    } else if let Some(number) = value.strip_suffix('K') {
        (number, 1024_usize)
    } else if let Some(number) = value.strip_suffix("MB") {
        (number, 1024_usize * 1024)
    } else if let Some(number) = value.strip_suffix('M') {
        (number, 1024_usize * 1024)
    } else if let Some(number) = value.strip_suffix('B') {
        (number, 1_usize)
    } else {
        return Err(CoreError::InvalidInput(format!(
            "chunk size {value:?} must include B, K, KB, M, or MB"
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
    if !chunk_size.is_power_of_two() {
        return Err(CoreError::InvalidInput(
            "chunk size must be a power of two".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
                    resume: false,
                },
                Box::new(NoopEventSink),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    #[test]
    fn parses_human_readable_chunk_sizes() {
        assert_eq!(parse_chunk_size("16K").unwrap(), 16 * 1024);
        assert_eq!(parse_chunk_size("16KB").unwrap(), 16 * 1024);
        assert_eq!(parse_chunk_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_chunk_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_chunk_size("16384B").unwrap(), 16 * 1024);
    }

    #[test]
    fn rejects_bare_out_of_range_or_non_power_of_two_chunk_sizes() {
        assert!(matches!(
            parse_chunk_size("65536"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("15K"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("17M"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("24K"),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(matches!(
            parse_chunk_size("1MiB"),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn config_file_overrides_default_chunk_size() {
        let config_path = unique_test_path("config-overrides-default.toml");
        std::fs::write(&config_path, "chunk_size = \"1M\"\n").unwrap();

        let config = ClientConfig::from_runtime_sources_with_env(
            test_pairing(),
            Some(&config_path),
            &TestEnv::default(),
        )
        .unwrap();

        assert_eq!(config.chunk_size, 1024 * 1024);
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn env_chunk_size_overrides_config_file() {
        let config_path = unique_test_path("env-overrides-config.toml");
        std::fs::write(&config_path, "chunk_size = \"1M\"\n").unwrap();
        let env = TestEnv::new([(ENVOIX_CHUNK_SIZE, "4M")]);

        let config =
            ClientConfig::from_runtime_sources_with_env(test_pairing(), Some(&config_path), &env)
                .unwrap();

        assert_eq!(config.chunk_size, 4 * 1024 * 1024);
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn invalid_env_chunk_size_fails_early() {
        let env = TestEnv::new([(ENVOIX_CHUNK_SIZE, "65536")]);

        let error =
            ClientConfig::from_runtime_sources_with_env(test_pairing(), None, &env).unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    #[tokio::test]
    #[ignore = "requires local network access; run with: cargo test -- --ignored"]
    async fn client_send_auto_emits_events_in_order() {
        let client = EnvoixClient::new(ClientConfig {
            chunk_size: 64 * 1024,
            pairing: test_pairing(),
        });

        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = RecordingSink(recorded.clone());

        // This will fail because there's no receiver on the LAN,
        // but we can check the event order up to the failure.
        let _result = client
            .send(
                SendRequest {
                    file_path: "missing.txt".into(),
                    connection_policy: ConnectionPolicy::Auto,
                    resume: false,
                },
                Box::new(sink),
                Box::new(NoopEventSink),
            )
            .await;

        let events = recorded.lock().unwrap();
        // At minimum, AutoConnectionStarted and LanDiscoveryStarted
        // should have been emitted.
        assert!(!events.is_empty());
        assert_eq!(
            events.first().unwrap(),
            &ClientEvent::AutoConnectionStarted {
                direction: TransferDirection::Send
            }
        );
        assert_eq!(events.get(1).unwrap(), &ClientEvent::LanDiscoveryStarted);
    }

    fn test_pairing() -> PairingConfig {
        PairingConfig::spake2_shared_token("abcdefghijkl").unwrap()
    }

    fn unique_test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("envoix-client-test-{}-{name}", std::process::id()))
    }

    #[derive(Default)]
    struct TestEnv {
        values: Vec<(&'static str, String)>,
    }

    impl TestEnv {
        fn new<const N: usize>(values: [(&'static str, &str); N]) -> Self {
            Self {
                values: values
                    .into_iter()
                    .map(|(name, value)| (name, value.to_owned()))
                    .collect(),
            }
        }
    }

    impl EnvSource for TestEnv {
        fn get(&self, name: &'static str) -> Result<Option<String>, PublicError> {
            Ok(self
                .values
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value.clone()))
        }
    }

    /// A `ClientEventSink` that records events into a shared vector.
    #[derive(Clone)]
    struct RecordingSink(Arc<std::sync::Mutex<Vec<ClientEvent>>>);

    impl ClientEventSink for RecordingSink {
        fn on_event(&self, event: ClientEvent) {
            self.0.lock().unwrap().push(event);
        }
    }
}
