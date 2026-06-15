//! Envoix relay data-plane server (Issue #12).
//!
//! Runs on the VPS. Validates relay tokens (shared key with the home
//! allocation endpoint) and cross-forwards opaque QUIC datagrams between
//! the two peers of a session. Never decrypts; not a trust party.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use envoix_relay::{RelayConfig, RelayTokenKey};

mod keyfile;
mod server;
mod service;
mod usage;

use server::RelayServer;

/// Run the relay (no subcommand) or manage the installed service.
#[derive(Parser)]
#[command(
    name = "envoix-relay-server",
    about = "Envoix relay data plane",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(flatten)]
    run: RunArgs,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Enable on boot and start the relay service.
    Up,
    /// Stop the relay service.
    Down,
}

/// Data-plane server options (used when no subcommand is given).
#[derive(Args)]
struct RunArgs {
    /// UDP bind address.
    #[arg(long, env = "ENVOIX_RELAY_LISTEN", default_value = "0.0.0.0:9104")]
    listen: SocketAddr,

    /// Explicit 64-hex master key. Overrides `--key-file`; needed for a
    /// public relay that must share a key with the home allocation server.
    /// Prefer the env var or key-file over passing this on the command line.
    #[arg(long, env = "ENVOIX_RELAY_KEY")]
    key: Option<String>,

    /// Master-key file. Generated (0600) on first run if absent. Used unless
    /// `--key` is set.
    #[arg(
        long,
        env = "ENVOIX_RELAY_KEY_FILE",
        default_value = "/var/lib/envoix-relay/relay.key"
    )]
    key_file: PathBuf,

    /// Monthly forwarded-byte limit; forwarding disables on exceed and
    /// the counter resets at the start of each calendar month (UTC).
    /// Default 200 GiB.
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

    /// How often to evict idle pairs (seconds).
    #[arg(long, env = "ENVOIX_RELAY_SWEEP_INTERVAL", default_value_t = 30)]
    sweep_interval_secs: u64,

    /// How often to persist usage and log the stats line (seconds).
    #[arg(long, env = "ENVOIX_RELAY_HOUSEKEEPING_INTERVAL", default_value_t = 30)]
    housekeeping_interval_secs: u64,

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
    match cli.command {
        None => run_server(cli.run).await,
        Some(Command::Up) => service::up(),
        Some(Command::Down) => service::down(),
    }
}

async fn run_server(args: RunArgs) {
    init_tracing(args.debug);

    let key = match args.key {
        Some(hex) => RelayTokenKey::from_hex(hex.trim())
            .unwrap_or_else(|| panic!("--key must be 64 hex characters")),
        None => keyfile::load_or_generate(&args.key_file)
            .unwrap_or_else(|e| panic!("relay key: {e}")),
    };
    let config = RelayConfig {
        max_sessions: args.max_sessions,
        max_bytes_per_session: args.max_bytes_per_session,
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
    };

    let server = RelayServer::bind(
        args.listen,
        key,
        config,
        args.monthly_byte_limit,
        args.usage_file,
    )
    .await
    .unwrap_or_else(|e| panic!("cannot bind {}: {e}", args.listen));
    let server = Arc::new(server);
    if args.debug {
        server.toggle_debug();
    }
    tracing::info!(listen = %args.listen, "envoix relay data plane listening");

    spawn_background_tasks(
        server.clone(),
        Duration::from_secs(args.sweep_interval_secs),
        Duration::from_secs(args.housekeeping_interval_secs),
    );
    install_signal_handlers(server.clone());

    // The receive loop is the main work; it runs until the process exits.
    // SIGTERM is handled by install_signal_handlers (flush + exit).
    server.run().await;
}

/// Spawn the idle-sweep task and the periodic usage-flush/stats task.
fn spawn_background_tasks(
    server: Arc<RelayServer>,
    sweep_interval: Duration,
    housekeeping_interval: Duration,
) {
    let sweep = server.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(sweep_interval);
        loop {
            t.tick().await;
            sweep.sweep_idle().await;
        }
    });

    let housekeeping = server;
    tokio::spawn(async move {
        let mut t = tokio::time::interval(housekeeping_interval);
        loop {
            t.tick().await;
            housekeeping.flush_usage();
            housekeeping.log_stats().await;
        }
    });
}

/// SIGUSR1 -> toggle debug logging; SIGUSR2 -> toggle forwarding pause;
/// SIGTERM/SIGINT -> flush usage and exit.
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
