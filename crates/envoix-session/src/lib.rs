//! Session orchestration for transfer setup and concrete iroh wiring.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result as AnyResult, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub use envoix_auth::{PairingConfig, authenticate_receiver, authenticate_sender};
use envoix_error::CoreError;
use envoix_protocol::{
    Frame, FrameConnection, PeerDescriptor, ProtocolError, flush_frame_writer, read_frame,
    write_chunk_frame, write_frame,
};
pub use envoix_transfer::TransferEngine;
pub use envoix_transfer::{
    DEFAULT_CHUNK_SIZE, EventSink, NoopEventSink, TransferEvent, TransferSummary,
};
pub use envoix_types::TransferDirection;
use iroh::endpoint::{Connection, RecvStream, RelayMode, SendStream, VarInt, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::fs;

const ALPN: &[u8] = b"envoix/1";
const IDENTITY_FILE_VERSION: u32 = 1;
const MAX_AUTH_FAILURES: u32 = 50;
const MDNS_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Error type returned by session orchestration.
pub type SessionError = CoreError;

/// Runtime options used when wiring transports into the transfer engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Maximum chunk payload size sent by the transfer engine.
    pub chunk_size: usize,
    /// Pairing authentication required before any transfer frame.
    pub pairing: PairingConfig,
    /// iroh endpoint identity policy.
    pub identity: IdentityConfig,
}

/// iroh endpoint identity policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum IdentityConfig {
    /// Generate a fresh endpoint identity for this process.
    #[default]
    Ephemeral,
    /// Load an existing identity from this file, creating one if missing.
    Persistent(PathBuf),
}

/// A bound iroh endpoint ready to accept Envoix connections.
#[derive(Clone, Debug)]
pub struct BoundEndpoint {
    endpoint: Endpoint,
}

impl BoundEndpoint {
    /// Returns the endpoint ID as a stable display string.
    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Returns currently known direct socket addresses.
    pub fn direct_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.addr().ip_addrs().copied().collect()
    }

    /// Returns an app-level direct peer descriptor for this endpoint.
    pub fn peer_descriptor(&self) -> Result<PeerDescriptor, SessionError> {
        PeerDescriptor::new(self.endpoint_id(), self.direct_addrs())
    }

    async fn accept(&self) -> Result<IrohFrameConnection, SessionError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| CoreError::Transport("iroh endpoint closed".into()))?;
        let connection = incoming
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        Ok(IrohFrameConnection {
            _endpoint: self.endpoint.clone(),
            connection,
            send,
            recv,
        })
    }
}

/// Bind an iroh endpoint that can accept one incoming connection.
pub async fn bind_iroh_endpoint(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        endpoint: build_endpoint(Some(listen_addr), identity, true, false).await?,
    })
}

/// Bind an iroh endpoint and advertise it through iroh mDNS address lookup.
pub async fn bind_iroh_endpoint_enable_mdns(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<BoundEndpoint, SessionError> {
    Ok(BoundEndpoint {
        endpoint: build_endpoint(Some(listen_addr), identity, true, true).await?,
    })
}

/// Sends one file to a manually supplied peer descriptor.
pub async fn send_file_manual(
    peer: PeerDescriptor,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let endpoint = build_endpoint(None, &config.identity, false, false).await?;
    let mut connection = dial(endpoint.clone(), &peer).await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .send_file(&mut connection, file_path, resume, events.as_ref())
        .await;
    let _ = connection.close().await;
    endpoint.close().await;
    result
}

/// Sends one file to the first mDNS-discovered iroh endpoint that authenticates.
pub async fn send_file_enable_mdns(
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let endpoint = build_endpoint(None, &config.identity, false, false).await?;
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .build(endpoint.id())
        .map_err(|error| CoreError::Discovery(error.to_string()))?;
    endpoint
        .address_lookup()
        .map_err(|error| CoreError::Discovery(error.to_string()))?
        .add(mdns.clone());

    let mut discoveries = mdns.subscribe().await;
    let deadline = tokio::time::Instant::now() + MDNS_DISCOVERY_TIMEOUT;
    let mut last_error = None;
    let mut events = events;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let Some(event) = tokio::time::timeout_at(deadline, discoveries.next())
            .await
            .map_err(|_| {
                CoreError::Discovery(format!(
                    "no iroh mDNS peers discovered within {} seconds",
                    MDNS_DISCOVERY_TIMEOUT.as_secs()
                ))
            })?
        else {
            break;
        };

        let DiscoveryEvent::Discovered { endpoint_info, .. } = event else {
            continue;
        };
        if endpoint_info.endpoint_id == endpoint.id() {
            continue;
        }

        match send_file_over_endpoint_addr(
            endpoint.clone(),
            endpoint_info.to_endpoint_addr(),
            file_path.clone(),
            resume,
            config.clone(),
            events,
        )
        .await
        {
            Ok(summary) => {
                endpoint.close().await;
                return Ok(summary);
            }
            Err(error) => {
                last_error = Some(error);
                events = Box::new(NoopEventSink);
            }
        }
    }

    endpoint.close().await;
    Err(last_error.unwrap_or_else(|| {
        CoreError::Discovery(format!(
            "no iroh mDNS peers discovered within {} seconds",
            MDNS_DISCOVERY_TIMEOUT.as_secs()
        ))
    }))
}

/// Receives one file and reports the concrete peer descriptor before accepting.
pub async fn receive_file_with_bound_peer<F>(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
    on_bound_peer: F,
) -> Result<TransferSummary, SessionError>
where
    F: FnOnce(PeerDescriptor) + Send,
{
    let endpoint = bind_iroh_endpoint(listen_addr, &config.identity).await?;
    let peer = endpoint.peer_descriptor()?;
    on_bound_peer(peer);
    receive_one_authenticated(endpoint, output_dir, config, events).await
}

/// Receives one file on an already-bound endpoint.
pub async fn receive_one_authenticated(
    endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = endpoint.accept().await?;
    let engine = TransferEngine::new(config.chunk_size);

    if let Err(error) = authenticate_receiver(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        endpoint.endpoint.close().await;
        return Err(error);
    }
    let result = engine
        .receive_file(&mut connection, output_dir, events.as_ref())
        .await;
    let _ = connection.close().await;
    endpoint.endpoint.close().await;
    result
}

/// Receives one file, ignoring failed pairing attempts until one peer authenticates.
pub async fn receive_with_auth_retries(
    endpoint: BoundEndpoint,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = accept_authenticated_with_retries(&endpoint, &config).await?;
    let engine = TransferEngine::new(config.chunk_size);
    let result = engine
        .receive_file(&mut connection, output_dir, events.as_ref())
        .await;
    let _ = connection.close().await;
    endpoint.endpoint.close().await;
    result
}

async fn accept_authenticated_with_retries(
    endpoint: &BoundEndpoint,
    config: &SessionConfig,
) -> Result<IrohFrameConnection, SessionError> {
    let mut failures = 0_u32;
    loop {
        let mut connection = endpoint.accept().await?;
        match authenticate_receiver(&mut connection, &config.pairing).await {
            Ok(()) => return Ok(connection),
            Err(_) => {
                let _ = connection.close().await;
                failures += 1;
                if failures >= MAX_AUTH_FAILURES {
                    return Err(CoreError::Protocol(format!(
                        "too many failed pairing attempts (threshold: {MAX_AUTH_FAILURES})"
                    )));
                }
            }
        }
    }
}

async fn dial(
    endpoint: Endpoint,
    peer: &PeerDescriptor,
) -> Result<IrohFrameConnection, SessionError> {
    let endpoint_addr = endpoint_addr_from_peer(peer)?;
    dial_endpoint_addr(endpoint, endpoint_addr).await
}

async fn dial_endpoint_addr(
    endpoint: Endpoint,
    endpoint_addr: EndpointAddr,
) -> Result<IrohFrameConnection, SessionError> {
    let connection = endpoint
        .connect(endpoint_addr, ALPN)
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    Ok(IrohFrameConnection {
        _endpoint: endpoint,
        connection,
        send,
        recv,
    })
}

async fn send_file_over_endpoint_addr(
    endpoint: Endpoint,
    endpoint_addr: EndpointAddr,
    file_path: PathBuf,
    resume: bool,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError> {
    let mut connection = dial_endpoint_addr(endpoint, endpoint_addr).await?;
    let engine = TransferEngine::new(config.chunk_size);
    if let Err(error) = authenticate_sender(&mut connection, &config.pairing).await {
        let _ = connection.close().await;
        return Err(error);
    }
    let result = engine
        .send_file(&mut connection, file_path, resume, events.as_ref())
        .await;
    let _ = connection.close().await;
    result
}

fn endpoint_addr_from_peer(peer: &PeerDescriptor) -> Result<EndpointAddr, SessionError> {
    peer.validate()?;
    let id = peer
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(|error| CoreError::InvalidInput(format!("invalid endpoint id: {error}")))?;
    Ok(EndpointAddr::from_parts(
        id,
        peer.direct_addrs.iter().copied().map(TransportAddr::Ip),
    ))
}

async fn build_endpoint(
    listen_addr: Option<SocketAddr>,
    identity: &IdentityConfig,
    accept_connections: bool,
    enable_mdns: bool,
) -> Result<Endpoint, SessionError> {
    let secret_key = load_secret_key(identity).await?;
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup();
    if accept_connections {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    if enable_mdns {
        builder = builder.address_lookup(MdnsAddressLookup::builder().advertise(true));
    }
    if let Some(addr) = listen_addr {
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|error| CoreError::Transport(error.to_string()))?;
    }
    builder
        .bind()
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))
}

async fn load_secret_key(identity: &IdentityConfig) -> Result<SecretKey, SessionError> {
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

struct IrohFrameConnection {
    _endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

#[async_trait::async_trait]
impl FrameConnection for IrohFrameConnection {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        write_frame(&mut self.send, &frame).await?;
        flush_frame_writer(&mut self.send).await
    }

    async fn send_chunk(
        &mut self,
        transfer_id: &envoix_types::TransferId,
        index: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        write_chunk_frame(&mut self.send, transfer_id, index, offset, bytes).await?;
        flush_frame_writer(&mut self.send).await
    }

    async fn recv_frame(&mut self) -> Result<Frame, ProtocolError> {
        read_frame(&mut self.recv).await
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], ProtocolError> {
        let mut output = [0_u8; 32];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|_| CoreError::Transport("failed to export iroh keying material".into()))?;
        Ok(output)
    }

    async fn close(&mut self) -> Result<(), ProtocolError> {
        if self.send.finish().is_ok() {
            let _ = tokio::time::timeout(STREAM_CLOSE_TIMEOUT, self.send.stopped()).await;
        }
        self.connection.close(VarInt::from_u32(0), b"done");
        Ok(())
    }
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
