use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use envoix_error::CoreError;
use envoix_protocol::PeerDescriptor;
use iroh::endpoint::{BindOpts, RelayMode, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::connection::IrohFrameConnection;
use crate::identity::{IdentityConfig, load_secret_key};
use crate::{ALPN, SessionError};

/// Local socket addresses an accepting iroh endpoint should bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindAddrs {
    addrs: Vec<BindAddr>,
}

impl BindAddrs {
    /// Binds one local socket address.
    pub fn single(addr: SocketAddr) -> Self {
        Self {
            addrs: vec![BindAddr::required(addr)],
        }
    }

    /// Binds unspecified IPv4 and IPv6 sockets on the requested port.
    ///
    /// Passing port `0` lets the OS choose an independent free port per family.
    /// The IPv6 bind is best-effort, matching iroh's default endpoint behavior.
    pub fn dual_stack(port: u16) -> Self {
        Self {
            addrs: vec![
                BindAddr::required(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)),
                BindAddr::optional(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)),
            ],
        }
    }

    fn iter(&self) -> impl Iterator<Item = BindAddr> + '_ {
        self.addrs.iter().copied()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BindAddr {
    addr: SocketAddr,
    required: bool,
}

impl BindAddr {
    fn required(addr: SocketAddr) -> Self {
        Self {
            addr,
            required: true,
        }
    }

    fn optional(addr: SocketAddr) -> Self {
        Self {
            addr,
            required: false,
        }
    }
}

impl From<SocketAddr> for BindAddrs {
    fn from(addr: SocketAddr) -> Self {
        Self::single(addr)
    }
}

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
    listen_addrs: BindAddrs,
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addrs), identity, true, false).await
}

pub(crate) async fn build_advertising_accept_endpoint(
    listen_addrs: BindAddrs,
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addrs), identity, true, true).await
}

pub(crate) async fn build_dial_endpoint(
    identity: &IdentityConfig,
) -> Result<Endpoint, SessionError> {
    build_endpoint(None, identity, false, false).await
}

async fn build_endpoint(
    local_listen_addrs: Option<BindAddrs>,
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
    if let Some(addrs) = local_listen_addrs {
        builder = builder.clear_ip_transports();
        for bind_addr in addrs.iter() {
            builder = builder
                .bind_addr_with_opts(
                    bind_addr.addr,
                    BindOpts::default().set_is_required(bind_addr.required),
                )
                .map_err(|error| CoreError::Transport(error.to_string()))?;
        }
    }
    builder
        .bind()
        .await
        .map_err(|error| CoreError::Transport(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_stack_bind_addrs_include_ipv4_and_ipv6_unspecified() {
        let addrs: Vec<_> = BindAddrs::dual_stack(0)
            .iter()
            .map(|bind_addr| bind_addr.addr)
            .collect();

        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"0.0.0.0:0".parse().unwrap()));
        assert!(addrs.contains(&"[::]:0".parse().unwrap()));
    }

    #[test]
    fn dual_stack_makes_ipv6_best_effort() {
        let addrs: Vec<_> = BindAddrs::dual_stack(0).iter().collect();

        assert!(
            addrs
                .iter()
                .any(|bind_addr| bind_addr.addr.is_ipv4() && bind_addr.required)
        );
        assert!(
            addrs
                .iter()
                .any(|bind_addr| bind_addr.addr.is_ipv6() && !bind_addr.required)
        );
    }
}
