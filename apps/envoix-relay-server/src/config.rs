//! Persistent relay configuration (`/etc/envoix-relay/config.toml`).
//!
//! The config file is the base; explicit CLI flags and env vars override it,
//! and built-in defaults fill anything absent from both.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/envoix-relay/config.toml";

/// Address family the reachability probe should use. `Auto` lets the system
/// pick (curl's default); `Ipv4`/`Ipv6` force the family - needed because the
/// observed address (and thus what the rendezvous can reach) depends on which
/// family was used to contact it. Against an IPv4-only rendezvous, force
/// `Ipv4`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeFamily {
    #[default]
    Auto,
    Ipv4,
    Ipv6,
}

impl ProbeFamily {
    /// The curl flag that forces this family, if any.
    pub fn curl_flag(self) -> Option<&'static str> {
        match self {
            ProbeFamily::Auto => None,
            ProbeFamily::Ipv4 => Some("-4"),
            ProbeFamily::Ipv6 => Some("-6"),
        }
    }
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
}

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
