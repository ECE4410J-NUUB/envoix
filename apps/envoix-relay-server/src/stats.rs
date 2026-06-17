//! Stats snapshot shared between the running relay (writer) and `status`
//! (reader). The relay writes it to a file periodically so a local operator
//! can query the relay without any network surface.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub written_at_unix: u64,
    pub uptime_secs: u64,
    pub forwarding_enabled: bool,
    pub active_pairs: u64,
    pub pairs_created_total: u64,
    pub datagrams_forwarded_total: u64,
    pub bytes_forwarded_total: u64,
    pub month_bytes: u64,
    pub month_byte_limit: u64,
    pub invalid_total: u64,
    pub quota_exceeded_total: u64,
    pub session_cap_cutoff_total: u64,
    pub rejected_capacity_total: u64,
}

impl StatsSnapshot {
    /// Atomically write the snapshot (temp file + rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }

    pub fn load(path: &Path) -> std::io::Result<StatsSnapshot> {
        let s = std::fs::read_to_string(path)?;
        serde_json::from_str(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bytes as a `X.XX GiB` string.
pub fn gib(bytes: u64) -> String {
    format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Seconds as a compact `1d 2h`, `3h 4m`, `5m 6s`, or `7s` string.
pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_scales() {
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m 5s");
        assert_eq!(duration(3 * 3600 + 4 * 60), "3h 4m");
        assert_eq!(duration(26 * 3600), "1d 2h");
    }

    #[test]
    fn gib_rounds() {
        assert_eq!(gib(0), "0.00 GiB");
        assert_eq!(gib(1024 * 1024 * 1024), "1.00 GiB");
    }
}
