//! Persistent relay configuration (`/etc/envoix-relay/config.toml`).
//!
//! The config file is the base; explicit CLI flags and env vars override it,
//! and built-in defaults fill anything absent from both.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/envoix-relay/config.toml";

/// Address family the reachability probe should use. `Auto` probes BOTH
/// families (one result line each, skipping a family the host lacks);
/// `Ipv4`/`Ipv6` force a single family. The probed address is whichever the
/// relay used to reach the rendezvous, so forcing the family pins what gets
/// tested.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeFamily {
    #[default]
    Auto,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub key_file: PathBuf,
    pub usage_file: PathBuf,
    pub stats_file: PathBuf,
    pub monthly_byte_limit: u64,
    pub max_bytes_per_session: u64,
    pub max_sessions: usize,
    pub idle_timeout_secs: u64,
    pub sweep_interval_secs: u64,
    pub housekeeping_interval_secs: u64,
    /// Public rendezvous base URL (e.g. "https://rdz.example.com/rdv"). When
    /// set, `test` also checks external reachability by asking the rendezvous
    /// to probe this relay's port. Unset (the default) skips that check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendezvous_url: Option<String>,
    /// Address family for the reachability probe. Force `ipv4` when the
    /// rendezvous is IPv4-only (otherwise an IPv6-preferring host is probed
    /// on an address the rendezvous cannot reach).
    pub probe_family: ProbeFamily,
    /// Inclusive UDP port range to listen on, e.g. "9100-9105", letting a
    /// client try several ports when one is blocked/throttled. The `listen`
    /// port must fall inside it. Unset (default) means a single port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<String>,
}

/// Largest port range we will bind (one socket + recv task per port).
const MAX_RANGE_PORTS: u32 = 64;

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:9104".parse().expect("valid default listen addr"),
            key_file: PathBuf::from("/var/lib/envoix-relay/relay.key"),
            usage_file: PathBuf::from("/var/lib/envoix-relay/usage.json"),
            stats_file: PathBuf::from("/var/lib/envoix-relay/stats.json"),
            monthly_byte_limit: 200 * 1024 * 1024 * 1024,
            max_bytes_per_session: 1_288_490_188,
            max_sessions: 64,
            idle_timeout_secs: 60,
            sweep_interval_secs: 30,
            housekeeping_interval_secs: 30,
            rendezvous_url: None,
            probe_family: ProbeFamily::Auto,
            port_range: None,
        }
    }
}

impl Config {
    /// Load from `path`. A missing file (or a missing field) falls back to
    /// defaults; only a present-but-malformed file is an error.
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Serialize to `path`, creating the parent directory if needed.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let body = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The ports the relay should bind: the whole `port_range` if set (with
    /// `primary` inside it), otherwise just `primary`. `primary` is passed in
    /// so it reflects any CLI/env override of `listen`.
    pub fn listen_ports(&self, primary: u16) -> Result<Vec<u16>, String> {
        let Some(spec) = &self.port_range else {
            return Ok(vec![primary]);
        };
        let (start, end) = spec
            .split_once('-')
            .ok_or_else(|| format!("port_range \"{spec}\" must be \"start-end\""))?;
        let start: u16 = start
            .trim()
            .parse()
            .map_err(|_| format!("port_range start \"{start}\" is not a port"))?;
        let end: u16 = end
            .trim()
            .parse()
            .map_err(|_| format!("port_range end \"{end}\" is not a port"))?;
        if start > end {
            return Err(format!("port_range {start}-{end} is empty (start > end)"));
        }
        let count = u32::from(end - start) + 1;
        if count > MAX_RANGE_PORTS {
            return Err(format!(
                "port_range {start}-{end} spans {count} ports (max {MAX_RANGE_PORTS})"
            ));
        }
        if primary < start || primary > end {
            return Err(format!(
                "listen port {primary} is outside port_range {start}-{end}"
            ));
        }
        Ok((start..=end).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "envoix-relay-config-{}-{tag}/config.toml",
            std::process::id()
        ))
    }

    #[test]
    fn missing_file_is_defaults() {
        let c = Config::load(Path::new("/nonexistent/envoix/config.toml")).unwrap();
        assert_eq!(c.max_sessions, 64);
        assert_eq!(c.probe_family, ProbeFamily::Auto);
    }

    #[test]
    fn listen_ports_single_and_range() {
        let mut c = Config::default();
        // No range -> just the primary port.
        assert_eq!(c.listen_ports(9104).unwrap(), vec![9104]);

        // A range containing the primary -> the whole range.
        c.port_range = Some("9100-9105".into());
        assert_eq!(c.listen_ports(9104).unwrap(), vec![9100, 9101, 9102, 9103, 9104, 9105]);

        // primary outside the range -> error.
        assert!(c.listen_ports(8000).is_err());

        // start > end -> error.
        c.port_range = Some("9105-9100".into());
        assert!(c.listen_ports(9104).is_err());

        // Malformed -> error.
        c.port_range = Some("oops".into());
        assert!(c.listen_ports(9104).is_err());

        // Over the cap -> error.
        c.port_range = Some("9104-9999".into());
        assert!(c.listen_ports(9104).is_err());
    }

    #[test]
    fn probe_family_parses_and_round_trips() {
        let path = tmp("fam");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Parses the lowercase string form from a file.
        std::fs::write(&path, "probe_family = \"ipv4\"\n").unwrap();
        assert_eq!(Config::load(&path).unwrap().probe_family, ProbeFamily::Ipv4);
        // And survives a save/load round trip.
        let c = Config { probe_family: ProbeFamily::Ipv6, ..Config::default() };
        c.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap().probe_family, ProbeFamily::Ipv6);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_load_round_trip() {
        let path = tmp("rt");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let c = Config { max_sessions: 7, ..Config::default() };
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back.max_sessions, 7);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn partial_file_fills_defaults() {
        let path = tmp("partial");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "max_sessions = 9\n").unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.max_sessions, 9);
        assert_eq!(c.idle_timeout_secs, 60); // from default
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
