//! Envoix relay data-plane server (Issue #12).
//!
//! Runs on the VPS. Validates relay tokens (shared key with the home
//! allocation endpoint) and cross-forwards opaque QUIC datagrams between
//! the two peers of a session. Never decrypts; not a trust party.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use envoix_relay::{RelayConfig, RelayTokenKey};

mod server;
mod usage;

use server::RelayServer;

/// CLI per design §5.1 / §4.4 / §4.7.
#[derive(Parser)]
#[command(name = "envoix-relay-server", about = "Envoix relay data plane")]
struct Cli {
    /// UDP bind address.
    #[arg(long, env = "ENVOIX_RELAY_LISTEN", default_value = "0.0.0.0:9104")]
    listen: SocketAddr,

    /// Shared 64-hex relay key - must match the home allocation server's
    /// `--relay-key`.
    #[arg(long, env = "ENVOIX_RELAY_KEY")]
    key: String,

    /// Monthly forwarded-byte limit; forwarding disables on exceed and
    /// auto-resets at the month boundary. Default 200 GiB.
    #[arg(long, env = "ENVOIX_RELAY_MONTHLY_BYTE_LIMIT", default_value_t = 200 * 1024 * 1024 * 1024)]
    monthly_byte_limit: u64,

    /// Per-session forwarded-byte cap; a pair is cut off mid-stream past
    /// this. Default ~1.2 GiB (allows a ~1 GB file).
    #[arg(
        long,
        env = "ENVOIX_RELAY_MAX_BYTES_PER_SESSION",
        default_value_t = 1_288_490_188
    )]
    max_bytes_per_session: u64,

    /// Max concurrent relay pairs.
    #[arg(long, env = "ENVOIX_RELAY_MAX_SESSIONS", default_value_t = 64)]
    max_sessions: usize,

    /// Idle eviction timeout (seconds).
    #[arg(long, env = "ENVOIX_RELAY_IDLE_TIMEOUT", default_value_t = 60)]
    idle_timeout_secs: u64,

    /// Persisted monthly-usage file.
    #[arg(
        long,
        env = "ENVOIX_RELAY_USAGE_FILE",
        default_value = "/var/lib/envoix-relay/usage.json"
    )]
    usage_file: PathBuf,

    /// Start with verbose per-datagram logging (also toggleable via SIGUSR1).
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.debug);

    let key = RelayTokenKey::from_hex(cli.key.trim())
        .unwrap_or_else(|| panic!("--relay-key must be 64 hex characters"));
    let config = RelayConfig {
        max_sessions: cli.max_sessions,
        max_bytes_per_session: cli.max_bytes_per_session,
        idle_timeout: Duration::from_secs(cli.idle_timeout_secs),
    };

    let server = RelayServer::bind(
        cli.listen,
        key,
        config,
        cli.monthly_byte_limit,
        cli.usage_file,
    )
    .await
    .unwrap_or_else(|e| panic!("cannot bind {}: {e}", cli.listen));
    let server = Arc::new(server);
    if cli.debug {
        server.toggle_debug();
    }
    tracing::info!(listen = %cli.listen, "envoix relay data plane listening");

    spawn_background_tasks(server.clone());
    install_signal_handlers(server.clone());

    // The receive loop is the main work; it runs until the process exits.
    // SIGTERM is handled by install_signal_handlers (flush + exit).
    server.run().await;
}

/// Idle sweep (§4.3), periodic usage flush and stats line (§4.4 / §4.6).
fn spawn_background_tasks(server: Arc<RelayServer>) {
    let sweep = server.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(30));
        loop {
            t.tick().await;
            sweep.sweep_idle().await;
        }
    });

    let housekeeping = server;
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(30));
        loop {
            t.tick().await;
            housekeeping.flush_usage();
            housekeeping.log_stats().await;
        }
    });
}

/// SIGUSR1 -> toggle debug logging; SIGUSR2 -> toggle forwarding pause;
/// SIGTERM/SIGINT -> flush usage and exit (design §4.7).
fn install_signal_handlers(server: Arc<RelayServer>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let s = server.clone();
        tokio::spawn(async move {
            let mut sig = signal(SignalKind::user_defined1()).expect("SIGUSR1");
            loop {
                sig.recv().await;
                let on = s.toggle_debug();
                tracing::info!(debug = on, "debug logging toggled");
            }
        });

        let s = server.clone();
        tokio::spawn(async move {
            let mut sig = signal(SignalKind::user_defined2()).expect("SIGUSR2");
            loop {
                sig.recv().await;
                let on = s.toggle_forwarding();
                tracing::warn!(forwarding = on, "forwarding toggled");
            }
        });

        let s = server;
        tokio::spawn(async move {
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
            let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            tracing::info!("shutdown signal; flushing usage");
            s.flush_usage();
            std::process::exit(0);
        });
    }
}

/// envoix targets at `info` (or `debug` with `--debug`), everything else
/// `warn`. `RUST_LOG` overrides.
fn init_tracing(debug: bool) {
    let level = if debug { "debug" } else { "info" };
    let default = format!("envoix_relay_server={level},envoix_relay={level},warn");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
