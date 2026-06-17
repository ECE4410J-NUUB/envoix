//! Peer and connection candidate discovery.
//!
//! Supports manual peer lookup and LAN-based mDNS discovery so that two
//! Envoix peers on the same local network can find each other without a
//! centralised server.

mod manual;
mod mdns;

use envoix_error::CoreError;
use thiserror::Error;

pub use manual::{DiscoveryProvider, ManualPeerDiscovery};
pub use mdns::{
    DEFAULT_DISCOVERY_TIMEOUT, ENVOIX_DISCOVERY_PROTO_VERSION, ENVOIX_SERVICE_TYPE,
    LanDiscoveryConfig, LanDiscoveryRecord, MdnsLanAdvertiser, MdnsLanDiscovery,
    deduplicate_candidates,
};

/// Errors that can occur during discovery.
#[derive(Clone, Debug, Error)]
pub enum DiscoveryError {
    /// Underlying mDNS subsystem failure (I/O, daemon crash, …).
    #[error("mDNS error: {0}")]
    Mdns(String),
    /// A discovered record failed validation.
    #[error("invalid discovery record: {0}")]
    InvalidRecord(String),
    /// Discovery timed out without finding any candidates.
    #[error("LAN discovery timed out")]
    Timeout,
}

impl From<DiscoveryError> for CoreError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::Mdns(msg) => CoreError::Discovery(msg),
            DiscoveryError::InvalidRecord(msg) => CoreError::Discovery(msg),
            DiscoveryError::Timeout => CoreError::Discovery("LAN discovery timed out".into()),
        }
    }
}
