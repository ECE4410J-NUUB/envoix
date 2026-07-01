//! Public application-facing facade for envoix clients.

use std::fs;
use std::path::{Path, PathBuf};

pub use envoix_auth::{PairingConfig, SPAKE2_EXPERIMENTAL_WARNING};
use envoix_error::CoreError;
pub use envoix_protocol::PeerDescriptor;
pub use envoix_session::{
    BindAddrs, EventSink, IdentityConfig, NoopEventSink, TransferCancelToken, TransferDirection,
    TransferEvent, TransferSummary,
};
use envoix_session::{
    SessionConfig, bind_iroh_endpoint_enable_mdns, receive_file_with_bound_peer_with_cancel,
    receive_with_auth_retries_with_cancel, send_file_enable_mdns_with_cancel,
    send_file_manual_with_cancel,
};
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
    /// iroh endpoint identity policy.
    pub identity: IdentityConfig,
}

impl ClientConfig {
    /// Creates config using the default chunk size and required pairing auth.
    pub fn new(pairing: PairingConfig) -> Self {
        Self {
            chunk_size: envoix_session::DEFAULT_CHUNK_SIZE,
            pairing,
            identity: IdentityConfig::Ephemeral,
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
    /// Peer descriptor to connect to.
    pub peer: PeerDescriptor,
    /// Local file path to send.
    pub file_path: PathBuf,
    /// Whether receiver-side resume state may be used.
    pub resume: bool,
}

/// Request to receive one file into a local directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveFileRequest {
    /// Local socket addresses to listen on.
    pub listen_addrs: BindAddrs,
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
}

/// Automatic connection policy used by the facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionPolicy {
    /// Use iroh mDNS/address discovery when available.
    EnableMdns,
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
    /// Local socket addresses to bind the QUIC listener on.
    ///
    /// Use `BindAddrs::dual_stack(0)` for any IPv4 and IPv6 interface
    /// with OS-assigned ports.
    pub listen_addrs: BindAddrs,
}

/// Request to send one file by pairing in a rendezvous room with a short code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomSendRequest {
    /// Rendezvous broker address, `<endpoint-id>@<ip:port>`.
    pub broker: String,
    /// Optional relay URL for WAN/NAT reachability of the data plane and broker.
    pub relay: Option<String>,
    /// Force the data path through the relay (bind no IP transport). Requires
    /// `relay`. For A/B testing relay vs direct.
    pub relay_only: bool,
    /// Force a direct data path: no relay fallback for the transfer (the relay is
    /// still used to reach the broker). Direct-or-fail. For A/B testing.
    pub direct_only: bool,
    /// Short pairing code shared with the receiver.
    pub code: String,
    /// Local file path to send.
    pub file_path: PathBuf,
    /// Whether receiver-side resume state may be used.
    pub resume: bool,
}

/// Request to receive one file by pairing in a rendezvous room with a short code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomReceiveRequest {
    /// Rendezvous broker address, `<endpoint-id>@<ip:port>`.
    pub broker: String,
    /// Optional relay URL for WAN/NAT reachability of the data plane and broker.
    pub relay: Option<String>,
    /// Force the data path through the relay (bind no IP transport). Requires
    /// `relay`. For A/B testing relay vs direct.
    pub relay_only: bool,
    /// Force a direct data path: no relay fallback for the transfer (the relay is
    /// still used to reach the broker). Direct-or-fail. For A/B testing.
    pub direct_only: bool,
    /// Short pairing code shared with the sender.
    pub code: String,
    /// Directory where the received file and resume state are stored.
    pub output_dir: PathBuf,
    /// Local socket addresses to bind the data-plane listener on.
    pub listen_addrs: BindAddrs,
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
    /// Endpoint setup has started.
    EndpointStarted {
        /// Direction of this local operation.
        direction: TransferDirection,
    },
    /// A direct address is available for this endpoint.
    DirectAddressAvailable {
        /// Direct descriptor callers can share with a peer.
        peer: PeerDescriptor,
    },
    /// Dialing a peer has started.
    DialStarted {
        /// Peer being dialed.
        peer: PeerDescriptor,
    },
    /// Pairing authentication completed.
    Authenticated {
        /// Direction of this local operation.
        direction: TransferDirection,
    },
    /// A connection attempt failed.
    ConnectionFailed {
        /// Human-readable failure reason.
        reason: String,
    },
    /// Pairing failed too many times while receiving.
    TooManyAuthFailures,
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
        self.send_file_with_cancel(request, events, TransferCancelToken::new())
            .await
    }

    /// Sends one file according to `request`, stopping on cancellation.
    pub async fn send_file_with_cancel(
        &self,
        request: SendFileRequest,
        events: Box<dyn EventSink>,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        send_file_manual_with_cancel(
            request.peer,
            request.file_path,
            request.resume,
            self.session_config(),
            events,
            cancel,
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
        self.send_with_cancel(
            request,
            client_events,
            transfer_events,
            TransferCancelToken::new(),
        )
        .await
    }

    /// Sends one file using automatic connection setup, stopping on cancellation.
    pub async fn send_with_cancel(
        &self,
        request: SendRequest,
        client_events: Box<dyn ClientEventSink>,
        transfer_events: Box<dyn EventSink>,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError> {
        self.validate_config()?;
        match request.connection_policy {
            ConnectionPolicy::EnableMdns => {
                client_events.on_event(ClientEvent::EndpointStarted {
                    direction: TransferDirection::Send,
                });
                send_file_enable_mdns_with_cancel(
                    request.file_path,
                    request.resume,
                    self.session_config(),
                    transfer_events,
                    cancel,
                )
                .await
            }
        }
    }

    /// Receives one file and reports the concrete bound address before accepting.
    pub async fn receive_file_with_bound_peer<F>(
        &self,
        request: ReceiveFileRequest,
        events: Box<dyn EventSink>,
        on_bound_peer: F,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(PeerDescriptor) + Send,
    {
        self.receive_file_with_bound_peer_with_cancel(
            request,
            events,
            on_bound_peer,
            TransferCancelToken::new(),
        )
        .await
    }

    /// Receives one file and reports the bound address, stopping on cancellation.
    pub async fn receive_file_with_bound_peer_with_cancel<F>(
        &self,
        request: ReceiveFileRequest,
        events: Box<dyn EventSink>,
        on_bound_peer: F,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(PeerDescriptor) + Send,
    {
        self.validate_config()?;
        receive_file_with_bound_peer_with_cancel(
            request.listen_addrs,
            request.output_dir,
            self.session_config(),
            events,
            on_bound_peer,
            cancel,
        )
        .await
    }

    /// Receives one file using automatic pairing and connection establishment.
    ///
    /// `client_events` receives client-level lifecycle events (discovery,
    /// pairing).  `transfer_events` receives transfer-level progress events
    /// (chunk progress, hashing, completion).
    ///
    /// `on_bound` is called with the peer descriptor after the iroh endpoint
    /// has been bound, allowing the caller to print a QR invite.
    pub async fn receive<F>(
        &self,
        request: ReceiveRequest,
        client_events: Box<dyn ClientEventSink>,
        transfer_events: Box<dyn EventSink>,
        on_bound: F,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(PeerDescriptor) + Send,
    {
        self.receive_with_cancel(
            request,
            client_events,
            transfer_events,
            on_bound,
            TransferCancelToken::new(),
        )
        .await
    }

    /// Receives one file using automatic setup, stopping on cancellation.
    pub async fn receive_with_cancel<F>(
        &self,
        request: ReceiveRequest,
        client_events: Box<dyn ClientEventSink>,
        transfer_events: Box<dyn EventSink>,
        on_bound: F,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError>
    where
        F: FnOnce(PeerDescriptor) + Send,
    {
        self.validate_config()?;
        client_events.on_event(ClientEvent::EndpointStarted {
            direction: TransferDirection::Receive,
        });
        let endpoint =
            bind_iroh_endpoint_enable_mdns(request.listen_addrs, &self.config.identity).await?;
        let peer = endpoint.peer_descriptor()?;
        client_events.on_event(ClientEvent::DirectAddressAvailable { peer: peer.clone() });
        on_bound(peer);
        receive_with_auth_retries_with_cancel(
            endpoint,
            request.output_dir,
            self.session_config(),
            transfer_events,
            cancel,
        )
        .await
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

    /// Sends one file by pairing in a rendezvous room using a short code. The
    /// pairing is derived from the SPAKE2 exchange, so no token is required.
    pub async fn send_file_via_room(
        &self,
        request: RoomSendRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.send_file_via_room_with_cancel(request, events, TransferCancelToken::new())
            .await
    }

    /// Like [`Client::send_file_via_room`], stopping on cancellation.
    pub async fn send_file_via_room_with_cancel(
        &self,
        request: RoomSendRequest,
        events: Box<dyn EventSink>,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError> {
        let broker = envoix_session::parse_broker_addr(&request.broker, request.relay.as_deref())?;
        let mut config = self.session_config();
        config.relay = request.relay;
        config.relay_only = request.relay_only;
        config.direct_only = request.direct_only;
        envoix_session::send_file_via_room_with_cancel(
            broker,
            &request.code,
            request.file_path,
            request.resume,
            config,
            events,
            cancel,
        )
        .await
    }

    /// Receives one file by pairing in a rendezvous room using a short code. The
    /// pairing is derived from the SPAKE2 exchange, so no token is required.
    pub async fn receive_file_via_room(
        &self,
        request: RoomReceiveRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError> {
        self.receive_file_via_room_with_cancel(request, events, TransferCancelToken::new())
            .await
    }

    /// Like [`Client::receive_file_via_room`], stopping on cancellation.
    pub async fn receive_file_via_room_with_cancel(
        &self,
        request: RoomReceiveRequest,
        events: Box<dyn EventSink>,
        cancel: TransferCancelToken,
    ) -> Result<TransferSummary, PublicError> {
        let broker = envoix_session::parse_broker_addr(&request.broker, request.relay.as_deref())?;
        let mut config = self.session_config();
        config.relay = request.relay;
        config.relay_only = request.relay_only;
        config.direct_only = request.direct_only;
        envoix_session::receive_file_via_room_with_cancel(
            broker,
            &request.code,
            request.listen_addrs,
            request.output_dir,
            config,
            events,
            cancel,
        )
        .await
    }

    fn validate_config(&self) -> Result<(), PublicError> {
        self.config.validate()
    }

    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            chunk_size: self.config.chunk_size,
            pairing: self.config.pairing.clone(),
            identity: self.config.identity.clone(),
            relay: None,
            relay_only: false,
            direct_only: false,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn rejects_zero_chunk_size() {
        let client = EnvoixClient::new(ClientConfig {
            chunk_size: 0,
            pairing: test_pairing(),
            identity: IdentityConfig::Ephemeral,
        });

        let error = client
            .send_file(
                SendFileRequest {
                    peer: PeerDescriptor::new("peer", vec!["[::1]:9000".parse().unwrap()]).unwrap(),
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
    async fn client_send_enable_mdns_emits_start_event() {
        let client = EnvoixClient::new(ClientConfig {
            chunk_size: 64 * 1024,
            pairing: test_pairing(),
            identity: IdentityConfig::Ephemeral,
        });

        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = RecordingSink(recorded.clone());

        // This will fail because there's no receiver on the LAN,
        // but we can check the event order up to the failure.
        let _result = client
            .send(
                SendRequest {
                    file_path: "missing.txt".into(),
                    connection_policy: ConnectionPolicy::EnableMdns,
                    resume: false,
                },
                Box::new(sink),
                Box::new(NoopEventSink),
            )
            .await;

        let events = recorded.lock().unwrap();
        assert!(!events.is_empty());
        assert_eq!(
            events.first().unwrap(),
            &ClientEvent::EndpointStarted {
                direction: TransferDirection::Send
            }
        );
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
