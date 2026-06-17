use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use envoix_transport::ConnectionCandidate;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::DiscoveryError;

/// The DNS-SD service type used by Envoix LAN discovery.
pub const ENVOIX_SERVICE_TYPE: &str = "_envoix._udp.local.";

/// Current protocol version for LAN discovery records.
pub const ENVOIX_DISCOVERY_PROTO_VERSION: u64 = 1;

/// Default timeout when browsing for LAN candidates.
pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for LAN-based mDNS discovery.
#[derive(Clone, Debug)]
pub struct LanDiscoveryConfig {
    /// How long to wait for discovery results before giving up.
    pub timeout: Duration,
    /// Expected protocol version. Records with a mismatched version are
    /// silently ignored.
    pub protocol_version: u64,
    /// Optional session identifier used to filter candidates.  When `None`,
    /// every compatible Envoix receiver on the LAN is reported.
    pub session_id: Option<String>,
}

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_DISCOVERY_TIMEOUT,
            protocol_version: ENVOIX_DISCOVERY_PROTO_VERSION,
            session_id: None,
        }
    }
}

/// Safe metadata extracted from an mDNS service record.
///
/// This is the only information that leaves the receiver process over the
/// network.  **No token, file name, file size, hash, or path is included.**
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LanDiscoveryRecord {
    /// Protocol version of the record.
    pub protocol_version: u64,
    /// Opaque per-receiver-session identifier (not derived from the token).
    pub session_id: String,
    /// QUIC port the receiver is listening on.
    pub port: u16,
    /// Supported feature flags (e.g. `"quic-v1"`).
    pub features: String,
}

impl LanDiscoveryRecord {
    /// Build a [`LanDiscoveryRecord`] from an mDNS [`ServiceInfo`].
    ///
    /// Returns `Err(DiscoveryError::InvalidRecord)` when required fields are
    /// missing or fail validation.  Unknown TXT keys are silently ignored for
    /// forward compatibility.
    fn try_from_service_info(info: &ServiceInfo) -> Result<Self, DiscoveryError> {
        let proto_str = info
            .get_property_val_str("proto")
            .ok_or_else(|| DiscoveryError::InvalidRecord("missing proto field".into()))?;
        let protocol_version: u64 = proto_str
            .parse()
            .map_err(|_| DiscoveryError::InvalidRecord(format!("invalid proto: {proto_str:?}")))?;

        // Reject unsupported protocol versions.
        if protocol_version != ENVOIX_DISCOVERY_PROTO_VERSION {
            return Err(DiscoveryError::InvalidRecord(format!(
                "unsupported protocol version {protocol_version}"
            )));
        }

        let port_str = info
            .get_property_val_str("port")
            .ok_or_else(|| DiscoveryError::InvalidRecord("missing port field".into()))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| DiscoveryError::InvalidRecord(format!("invalid port: {port_str:?}")))?;
        if port == 0 {
            return Err(DiscoveryError::InvalidRecord("port is 0".into()));
        }

        let session_id = info.get_property_val_str("sid").unwrap_or("").to_string();
        if session_id.is_empty() {
            return Err(DiscoveryError::InvalidRecord("missing sid field".into()));
        }

        let features = info
            .get_property_val_str("features")
            .unwrap_or("")
            .to_string();

        Ok(Self {
            protocol_version,
            session_id,
            port,
            features,
        })
    }

    /// Serialise this record into mDNS TXT key-value pairs.
    ///
    /// The returned list is guaranteed **not** to contain any sensitive fields
    /// (token, file path, file name, file size, file hash).
    pub fn to_txt_pairs(&self) -> Vec<(String, String)> {
        vec![
            ("proto".to_string(), self.protocol_version.to_string()),
            ("sid".to_string(), self.session_id.clone()),
            ("port".to_string(), self.port.to_string()),
            ("features".to_string(), self.features.clone()),
        ]
    }
}

/// Deduplicate a list of candidates, preserving the original order.
///
/// Two candidates are considered equal when they have the same socket address
/// and transport variant.  Candidates discovered through multiple local
/// interfaces that normalise to the same address are collapsed into one.
pub fn deduplicate_candidates(candidates: Vec<ConnectionCandidate>) -> Vec<ConnectionCandidate> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(candidates.len());
    for c in candidates {
        if seen.insert(c) {
            out.push(c);
        }
    }
    out
}

/// Advertises a pending receive session over mDNS so LAN senders can discover
/// it without a manually supplied address.
///
/// Dropping the advertiser stops the advertisement automatically.
pub struct MdnsLanAdvertiser {
    _daemon: ServiceDaemon,
}

impl MdnsLanAdvertiser {
    /// Register a new mDNS service for the given record.
    ///
    /// The host address is resolved from the local machine; `record.port` is
    /// the QUIC listener port.
    pub fn start(record: &LanDiscoveryRecord) -> Result<Self, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let txt_pairs = record.to_txt_pairs();
        let properties: Vec<(&str, &str)> = txt_pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // mdns-sd requires the host name to end with ".local."; the instance
        // name (second argument) does not.
        let host_name = format!("{}.local.", record.session_id);
        let service_info = ServiceInfo::new(
            ENVOIX_SERVICE_TYPE,
            &record.session_id,
            &host_name, // hostname
            "",         // auto-detect local addresses
            record.port,
            properties.as_slice(),
        )
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?
        .enable_addr_auto();

        daemon
            .register(service_info)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        Ok(Self { _daemon: daemon })
    }
}

/// Discovers LAN candidates by browsing for Envoix mDNS services.
pub struct MdnsLanDiscovery {
    config: LanDiscoveryConfig,
}

impl MdnsLanDiscovery {
    /// Creates a new browser with the given configuration.
    pub fn new(config: LanDiscoveryConfig) -> Self {
        Self { config }
    }

    /// Run discovery for up to `self.config.timeout` and return the list of
    /// discovered (and deduplicated) connection candidates.
    ///
    /// The returned candidates are ordered **deterministically** so that tests
    /// can rely on a stable ordering.
    pub async fn discover(&self) -> Result<Vec<ConnectionCandidate>, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let receiver = daemon
            .browse(ENVOIX_SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        let deadline = tokio::time::Instant::now() + self.config.timeout;
        let mut candidates = Vec::new();

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            let event = tokio::time::timeout(remaining, receiver.recv_async()).await;

            match event {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    if let Ok(record) = LanDiscoveryRecord::try_from_service_info(&info) {
                        // If a session filter is set, skip non-matching records.
                        if let Some(ref expected) = self.config.session_id
                            && &record.session_id != expected
                        {
                            continue;
                        }

                        for addr in info.get_addresses() {
                            candidates.push(ConnectionCandidate::Quic {
                                addr: SocketAddr::new(*addr, record.port),
                            });
                        }
                    }
                }
                Ok(Ok(ServiceEvent::ServiceFound(..)))
                | Ok(Ok(ServiceEvent::ServiceRemoved(..)))
                | Ok(Ok(ServiceEvent::SearchStarted(..)))
                | Ok(Ok(ServiceEvent::SearchStopped(..))) => {
                    // Not actionable from the caller's perspective.
                    // ServiceFound is followed by ServiceResolved automatically
                    // by the mdns-sd library; ServiceRemoved is irrelevant once
                    // we have collected resolved records.
                }
                Ok(Err(e)) => {
                    tracing::warn!("mDNS browse event error: {e}");
                }
                Err(_timeout) => {
                    break;
                }
            }
        }

        if candidates.is_empty() {
            return Err(DiscoveryError::Timeout);
        }

        Ok(deduplicate_candidates(candidates))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service_info(pairs: &[(&str, &str)]) -> ServiceInfo {
        ServiceInfo::new(
            ENVOIX_SERVICE_TYPE,
            "test-instance",
            "test-host",
            "127.0.0.1",
            12345,
            pairs,
        )
        .expect("valid ServiceInfo")
    }

    #[test]
    fn valid_txt_record_parses_into_expected_record() {
        let info = make_service_info(&[
            ("proto", "1"),
            ("sid", "abc123"),
            ("port", "9876"),
            ("features", "quic-v1"),
        ]);
        let record = LanDiscoveryRecord::try_from_service_info(&info).unwrap();

        assert_eq!(record.protocol_version, 1);
        assert_eq!(record.session_id, "abc123");
        assert_eq!(record.port, 9876);
        assert_eq!(record.features, "quic-v1");
    }

    #[test]
    fn invalid_missing_version_is_rejected() {
        let info = make_service_info(&[("sid", "abc"), ("port", "9876")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());
    }

    #[test]
    fn invalid_missing_port_is_rejected() {
        let info = make_service_info(&[("proto", "1"), ("sid", "abc")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());
    }

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let info = make_service_info(&[("proto", "99"), ("sid", "abc"), ("port", "9876")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());
    }

    #[test]
    fn port_zero_is_rejected() {
        let info = make_service_info(&[("proto", "1"), ("sid", "abc"), ("port", "0")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());
    }

    #[test]
    fn missing_empty_session_id_is_rejected() {
        let info = make_service_info(&[("proto", "1"), ("port", "9876")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());

        let info = make_service_info(&[("proto", "1"), ("sid", ""), ("port", "9876")]);
        assert!(LanDiscoveryRecord::try_from_service_info(&info).is_err());
    }

    #[test]
    fn unknown_txt_keys_are_ignored() {
        let info = make_service_info(&[
            ("proto", "1"),
            ("sid", "abc"),
            ("port", "9999"),
            ("features", "quic-v1"),
            ("token", "should-not-be-here"),
            ("file", "secret.txt"),
        ]);
        let record = LanDiscoveryRecord::try_from_service_info(&info).unwrap();

        assert_eq!(record.protocol_version, 1);
        assert_eq!(record.port, 9999);
    }

    #[test]
    fn sensitive_fields_are_not_emitted_by_serialization() {
        let record = LanDiscoveryRecord {
            protocol_version: 1,
            session_id: "test-session".into(),
            port: 9999,
            features: "quic-v1".into(),
        };

        let pairs = record.to_txt_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();

        assert!(keys.contains(&"proto"));
        assert!(keys.contains(&"sid"));
        assert!(keys.contains(&"port"));
        assert!(keys.contains(&"features"));
        assert!(!keys.contains(&"token"));
        assert!(!keys.contains(&"file"));
        assert!(!keys.contains(&"file_name"));
        assert!(!keys.contains(&"file_size"));
        assert!(!keys.contains(&"file_hash"));
        assert!(!keys.contains(&"path"));
    }

    #[test]
    fn duplicate_candidates_are_removed_while_order_is_preserved() {
        let a = ConnectionCandidate::Quic {
            addr: "127.0.0.1:9000".parse().unwrap(),
        };
        let b = ConnectionCandidate::Quic {
            addr: "127.0.0.1:9001".parse().unwrap(),
        };

        let input = vec![a, b, a, b, a];
        let output = deduplicate_candidates(input);

        assert_eq!(output, vec![a, b]);
    }
}
