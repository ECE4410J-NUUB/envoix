//! Peer and connection candidate discovery.

use std::net::SocketAddr;

use envoix_error::CoreError;
use envoix_transport::ConnectionCandidate;

pub type DiscoveryError = CoreError;

pub trait DiscoveryProvider: Send + Sync {
    fn discover(&self) -> Result<Vec<ConnectionCandidate>, DiscoveryError>;
}

#[derive(Clone, Copy, Debug)]
pub struct ManualPeerDiscovery {
    peer_addr: SocketAddr,
}

impl ManualPeerDiscovery {
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self { peer_addr }
    }
}

impl DiscoveryProvider for ManualPeerDiscovery {
    fn discover(&self) -> Result<Vec<ConnectionCandidate>, DiscoveryError> {
        Ok(vec![ConnectionCandidate::Quic {
            addr: self.peer_addr,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_discovery_returns_exact_peer_candidate() {
        let addr = "[::1]:9000".parse().unwrap();
        let discovery = ManualPeerDiscovery::new(addr);

        assert_eq!(
            discovery.discover().unwrap(),
            vec![ConnectionCandidate::Quic { addr }]
        );
    }
}
