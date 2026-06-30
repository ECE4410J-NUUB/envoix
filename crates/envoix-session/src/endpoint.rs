use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use envoix_error::CoreError;
use envoix_protocol::PeerDescriptor;
use iroh::endpoint::{BindOpts, QuicTransportConfig, RelayMode, VarInt, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayUrl, TransportAddr};
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

    /// Returns this endpoint's full iroh address (id + direct addrs, plus its
    /// relay home when a relay is configured), for advertising to a peer to dial.
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.local_endpoint.addr()
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

/// Parse a rendezvous broker address `<endpoint-id>@<ip:port>` into an
/// [`EndpointAddr`]. When `relay` (a relay URL) is given it is added as a
/// fallback transport, so the broker stays reachable even if direct UDP to it
/// is blocked.
pub fn parse_broker_addr(addr: &str, relay: Option<&str>) -> Result<EndpointAddr, SessionError> {
    let (id, socket) = addr.split_once('@').ok_or_else(|| {
        CoreError::InvalidInput("rendezvous address must be <endpoint-id>@<ip:port>".into())
    })?;
    let id = id
        .parse::<EndpointId>()
        .map_err(|error| CoreError::InvalidInput(format!("invalid endpoint id: {error}")))?;
    let socket = socket
        .parse::<SocketAddr>()
        .map_err(|error| CoreError::InvalidInput(format!("invalid broker address: {error}")))?;
    let mut addrs = vec![TransportAddr::Ip(socket)];
    if let Some(relay) = relay {
        let relay = relay
            .parse::<RelayUrl>()
            .map_err(|error| CoreError::InvalidInput(format!("invalid relay url: {error}")))?;
        addrs.push(TransportAddr::Relay(relay));
    }
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// Convert an optional relay URL into an iroh [`RelayMode`]: `None` -> disabled
/// (LAN/direct, unchanged behavior); `Some(url)` -> a single custom relay so an
/// endpoint behind NAT stays reachable over WAN.
pub(crate) fn relay_mode(relay: &Option<String>) -> Result<RelayMode, SessionError> {
    match relay {
        None => Ok(RelayMode::Disabled),
        Some(url) => {
            let url: RelayUrl = url
                .parse()
                .map_err(|error| CoreError::InvalidInput(format!("invalid relay url: {error}")))?;
            Ok(RelayMode::Custom(RelayMap::from(url)))
        }
    }
}

pub(crate) async fn build_accept_endpoint(
    listen_addrs: BindAddrs,
    identity: &IdentityConfig,
    relay: &Option<String>,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addrs), identity, true, false, relay).await
}

pub(crate) async fn build_advertising_accept_endpoint(
    listen_addrs: BindAddrs,
    identity: &IdentityConfig,
    relay: &Option<String>,
) -> Result<Endpoint, SessionError> {
    build_endpoint(Some(listen_addrs), identity, true, true, relay).await
}

pub(crate) async fn build_dial_endpoint(
    identity: &IdentityConfig,
    relay: &Option<String>,
) -> Result<Endpoint, SessionError> {
    build_endpoint(None, identity, false, false, relay).await
}

/// QUIC transport tuning for high-latency links (e.g. trans-Pacific, ~280 ms RTT).
///
/// quinn's default per-stream receive window is sized for a 100 ms / 100 Mbit
/// link (1.25 MB). A single stream can have at most `window / RTT` bytes in
/// flight, so at 280 ms RTT that default caps one transfer at ~4.5 MB/s no
/// matter how fast the link is. We raise the per-stream flow-control window
/// (and the matching send window) so one transfer can fill a long fat pipe;
/// iroh's holepunching/multipath defaults (from the builder) are left untouched.
fn data_transport_config() -> QuicTransportConfig {
    // 16 MiB fills ~57 MB/s at 280 ms RTT, with headroom for lower-latency links.
    const WINDOW: u32 = 16 * 1024 * 1024;
    QuicTransportConfig::builder()
        .stream_receive_window(VarInt::from_u32(WINDOW))
        .send_window(WINDOW as u64)
        .build()
}

async fn build_endpoint(
    local_listen_addrs: Option<BindAddrs>,
    identity: &IdentityConfig,
    accept_incoming: bool,
    advertise_self: bool,
    relay: &Option<String>,
) -> Result<Endpoint, SessionError> {
    let secret_key = load_secret_key(identity).await?;
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(relay_mode(relay)?)
        .transport_config(data_transport_config())
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
    use iroh::SecretKey;

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

    #[test]
    fn broker_addr_parses_id_and_socket() {
        let id = SecretKey::generate().public();
        let addr = parse_broker_addr(&format!("{id}@127.0.0.1:8445"), None).unwrap();
        let socket: SocketAddr = "127.0.0.1:8445".parse().unwrap();
        assert_eq!(
            addr,
            EndpointAddr::from_parts(id, [TransportAddr::Ip(socket)])
        );
    }

    #[test]
    fn broker_addr_appends_relay() {
        let id = SecretKey::generate().public();
        let addr = parse_broker_addr(
            &format!("{id}@127.0.0.1:8445"),
            Some("https://relay.example:8444"),
        )
        .unwrap();
        assert_eq!(addr.relay_urls().count(), 1);
    }

    #[test]
    fn broker_addr_requires_at_sign() {
        assert!(parse_broker_addr("127.0.0.1:8445", None).is_err());
    }
}
