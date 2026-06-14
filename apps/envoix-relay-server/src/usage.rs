//! Persisted monthly-usage state.
//!
//! Wraps the pure [`envoix_relay::MonthlyUsage`] with the two things it
//! deliberately doesn't do: compute the current month from the wall clock,
//! and persist `{month, bytes}` to disk so a restart cannot bypass the
//! limit.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use envoix_relay::MonthlyUsage;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct UsageState {
    month: u32,
    bytes: u64,
}

/// Current month as `year * 12 + month0` (month0 in 0..12).
///
/// Pure civil-from-days (Howard Hinnant's algorithm) over the Unix day
/// count - no calendar crate needed, and exact.
pub fn current_month() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    month_of_unix_secs(secs)
}

fn month_of_unix_secs(secs: u64) -> u32 {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year as u32) * 12 + (month as u32 - 1)
}

/// Load the persisted counter, or start fresh if the file is missing or
/// unreadable. `check` later resets it if the month has rolled over.
pub fn load(path: &Path, limit: u64) -> MonthlyUsage {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str::<UsageState>(&s) {
            Ok(st) => MonthlyUsage::with_state(limit, st.month, st.bytes),
            Err(_) => MonthlyUsage::new(limit),
        },
        Err(_) => MonthlyUsage::new(limit),
    }
}

/// Persist the snapshot, creating the parent directory if needed.
/// Best-effort: a write failure is logged by the caller, not fatal.
pub fn save(path: &Path, usage: &MonthlyUsage) -> std::io::Result<()> {
    let (month, bytes) = usage.snapshot();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(&UsageState { month, bytes })?;
    let tmp: PathBuf = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path) // atomic replace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_of_known_dates() {
        // 1970-01-01 -> year 1970, month0 0 -> 1970*12 + 0
        assert_eq!(month_of_unix_secs(0), 1970 * 12);
        // 2026-06-13 ~ 1781e6 s. Compute the boundary precisely:
        // 2026-01-01 00:00:00 UTC = 1767225600
        assert_eq!(month_of_unix_secs(1_767_225_600), 2026 * 12); // Jan = month0 0
        // 2026-06-01 00:00:00 UTC = 1780272000 -> June = month0 5
        assert_eq!(month_of_unix_secs(1_780_272_000), 2026 * 12 + 5);
        // 2026-06-30 23:59:59 = 1782863999 -> still June
        assert_eq!(month_of_unix_secs(1_782_863_999), 2026 * 12 + 5);
        // 2026-07-01 00:00:00 = 1782864000 -> July
        assert_eq!(month_of_unix_secs(1_782_864_000), 2026 * 12 + 6);
    }

    #[test]
    fn save_load_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("envoix-relay-usage-test-{}", std::process::id()));
        let path = dir.join("usage.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut u = MonthlyUsage::new(1000);
        u.check(2026 * 12 + 5);
        u.record(777);
        save(&path, &u).expect("save");

        let restored = load(&path, 1000);
        assert_eq!(restored.snapshot(), (2026 * 12 + 5, 777));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_starts_fresh() {
        let u = load(Path::new("/nonexistent/envoix/usage.json"), 500);
        assert_eq!(u.snapshot(), (0, 0));
        assert_eq!(u.limit(), 500);
    }
}
