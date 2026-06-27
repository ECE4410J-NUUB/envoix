use std::net::SocketAddr;

use envoix_error::CoreError;
use envoix_protocol::PeerDescriptor;
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::connection::IrohFrameConnection;
use crate::identity::{IdentityConfig, load_secret_key};
use crate::{ALPN, SessionError};

/// A bound local iroh endpoint ready to accept Envoix connections.
#[derive(Clone, Debug)]
pub struct BoundEndpoint {
    pub(crate) local_endpoint: Endpoint,
}

impl BoundEndpoint {
    /// Returns the endpoint ID as a stable display string.
    pub fn endpoint_id(&self) -> String {
        self.local_endpoint.id().to_string()
    }

    /// Returns currently known direct socket addresses.
    pub fn direct_addrs(&self) -> Vec<SocketAddr> {
        self.local_endpoint.addr().ip_addrs().copied().collect()
    }

    /// Returns an app-level direct peer descriptor for this local endpoint.
    pub fn peer_descriptor(&self) -> Result<PeerDescriptor, SessionError> {
        PeerDescriptor::new(self.endpoint_id(), self.direct_addrs())
    }

    pub(crate) async fn accept(&self) -> Result<IrohFrameConnection, SessionError> {
        let incoming = self
            .local_endpoint
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
            _local_endpoint: self.local_endpoint.clone(),
            connection,
            send,
            recv,
        })
    }
}

pub(crate) fn peer_addr_from_descriptor(
    peer: &PeerDescriptor,
) -> Result<EndpointAddr, SessionError> {
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

pub(crate) async fn build_accept_endpoint(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addr), identity, true, false).await
}

pub(crate) async fn build_advertising_accept_endpoint(
    listen_addr: SocketAddr,
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addr), identity, true, true).await
}

pub(crate) async fn build_dial_endpoint(
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(None, identity, false, false).await
}

async fn build_endpoint(
    local_listen_addr: Option<SocketAddr>,
    identity: &IdentityConfig,
    accept_incoming: bool,
    advertise_self: bool,
) -> Result<Endpoint, SessionError> {
    let secret_key = load_secret_key(identity).await?;
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup();
    if accept_incoming {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    if advertise_self {
        builder = builder.address_lookup(MdnsAddressLookup::builder().advertise(true));
    }
    if let Some(addr) = local_listen_addr {
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
