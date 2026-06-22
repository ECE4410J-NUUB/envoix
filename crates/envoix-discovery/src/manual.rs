use std::net::SocketAddr;

use envoix_error::CoreError;
use envoix_transport::ConnectionCandidate;

/// Provider of peer candidates.
pub trait DiscoveryProvider: Send + Sync {
    /// Returns a list of candidates that can be dialled.
    fn discover(&self) -> Result<Vec<ConnectionCandidate>, CoreError>;
}

/// Simple provider that returns a single manually-supplied address.
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
    fn discover(&self) -> Result<Vec<ConnectionCandidate>, CoreError> {
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
