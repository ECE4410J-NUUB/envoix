//! `status`: read the relay's stats snapshot and present it for a human.

use std::path::Path;

use crate::config::Config;
use crate::stats::{self, StatsSnapshot};

/// Snapshots older than this are treated as stale (relay likely stopped).
const STALE_AFTER_SECS: u64 = 90;

pub fn run(config_path: &Path) {
    let cfg = Config::load(config_path).unwrap_or_else(|e| {
        eprintln!("error: config: {e}");
        std::process::exit(1);
    });

    match StatsSnapshot::load(&cfg.stats_file) {
        Ok(snap) => print_snapshot(&snap),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("relay is not running, or has not written stats yet");
            println!("  (no snapshot at {})", cfg.stats_file.display());
        }
        Err(e) => {
            eprintln!("error: {}: {e}", cfg.stats_file.display());
            std::process::exit(1);
        }
    }
}

fn print_snapshot(s: &StatsSnapshot) {
    let age = stats::now_unix().saturating_sub(s.written_at_unix);
    let stale = if age > STALE_AFTER_SECS {
        " - STALE, relay may be stopped"
    } else {
        ""
    };
    let pct = if s.month_byte_limit > 0 {
        s.month_bytes as f64 / s.month_byte_limit as f64 * 100.0
    } else {
        0.0
    };

    println!("relay status (snapshot {} ago{stale})", stats::duration(age));
    println!(
        "  forwarding:    {}",
        if s.forwarding_enabled { "enabled" } else { "disabled" }
    );
    println!("  uptime:        {}", stats::duration(s.uptime_secs));
    println!("  active pairs:  {}", s.active_pairs);
    println!(
        "  forwarded:     {} total over {} pairs ({} datagrams)",
        stats::gib(s.bytes_forwarded_total),
        s.pairs_created_total,
        s.datagrams_forwarded_total
    );
    println!(
        "  monthly quota: {} / {} ({pct:.1}%)",
        stats::gib(s.month_bytes),
        stats::gib(s.month_byte_limit)
    );
    println!(
        "  dropped:       invalid {}, over-quota {}, session-cap {}, capacity {}",
        s.invalid_total, s.quota_exceeded_total, s.session_cap_cutoff_total, s.rejected_capacity_total
    );
}
