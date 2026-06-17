//! Envoix relay data-plane server.
//!
//! Validates relay tokens (a shared key with the allocation endpoint) and
//! cross-forwards opaque QUIC datagrams between the two peers of a session.
//! Never decrypts; not a trust party.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use envoix_relay::{RelayConfig, RelayTokenKey};

mod config;
mod doctor;
mod keyfile;
mod pair;
mod server;
mod service;
mod stats;
mod status;
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
    /// Manage the config file.
    Config(ConfigArgs),
    /// Run preflight diagnostics (port, firewall, clock, permissions).
    Test {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Show live stats from the running relay.
    Status {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        config: PathBuf,
    },
    /// Hand this relay's key + port range to a client via a SPAKE2 pairing
    /// code (for a custom relay - the client mints its own tokens).
    Pair(PairCliArgs),
    /// Enable on boot and start the relay service.
    Up,
    /// Stop the relay service.
    Down,
}

#[derive(Args)]
struct ConfigArgs {
    #[command(subcommand)]
    action: ConfigAction,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Write a default config file (if absent) and generate the key file.
    Init {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        path: PathBuf,
    },
    /// Print the effective configuration.
    Show {
        #[arg(long, default_value = config::DEFAULT_PATH)]
        path: PathBuf,
    },
}

/// Options for the `pair` subcommand.
#[derive(Args)]
struct PairCliArgs {
    /// Config file (source of the master key and port range).
    #[arg(long, default_value = config::DEFAULT_PATH)]
    config: PathBuf,

    /// TCP port to listen on for the pairing handshake. A dedicated port,
    /// separate from the data-plane range; forward it temporarily while
    /// pairing.
    #[arg(long, default_value_t = 9099)]
    pairing_port: u16,

    /// Public IP to advertise in the invite. Defaults to reflexive discovery
    /// via a public IP-echo service (the relay can't see its own IP behind
    /// NAT).
    #[arg(long)]
    public_ip: Option<IpAddr>,

    /// Number of words in the generated pairing code.
    #[arg(long, default_value_t = 2)]
    words: usize,

    /// How long the pairing window stays open (seconds).
    #[arg(long, default_value_t = 180)]
    expires_secs: u64,

    /// Give up after this many failed pairing attempts.
    #[arg(long, default_value_t = 5)]
    max_attempts: u32,
}

/// Data-plane server options (used when no subcommand is given). Each value
/// here overrides the config file; absent ones fall back to it.
#[derive(Args)]
struct RunArgs {
    /// Config file to read settings from.
    #[arg(long, default_value = config::DEFAULT_PATH)]
    config: PathBuf,

    /// UDP bind address.
    #[arg(long, env = "ENVOIX_RELAY_LISTEN")]
    listen: Option<SocketAddr>,

    /// Explicit 64-hex master key, overriding the key file - for a public
    /// relay that shares a key with the rendezvous. Prefer the env var or
    /// key file; argv is world-readable.
    #[arg(long, env = "ENVOIX_RELAY_KEY")]
    key: Option<String>,

    /// Master-key file. Generated (0600) on first run if absent.
    #[arg(long, env = "ENVOIX_RELAY_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Monthly forwarded-byte limit; forwarding disables on exceed and the
    /// counter resets at the start of each calendar month (UTC).
    #[arg(long, env = "ENVOIX_RELAY_MONTHLY_BYTE_LIMIT")]
    monthly_byte_limit: Option<u64>,

    /// Per-session forwarded-byte cap; a pair is cut off mid-stream past this.
    #[arg(long, env = "ENVOIX_RELAY_MAX_BYTES_PER_SESSION")]
    max_bytes_per_session: Option<u64>,

    /// Max concurrent relay pairs.
    #[arg(long, env = "ENVOIX_RELAY_MAX_SESSIONS")]
    max_sessions: Option<usize>,

    /// Idle eviction timeout (seconds).
    #[arg(long, env = "ENVOIX_RELAY_IDLE_TIMEOUT")]
    idle_timeout_secs: Option<u64>,

    /// How often to evict idle pairs (seconds).
    #[arg(long, env = "ENVOIX_RELAY_SWEEP_INTERVAL")]
    sweep_interval_secs: Option<u64>,

    /// How often to persist usage and log the stats line (seconds).
    #[arg(long, env = "ENVOIX_RELAY_HOUSEKEEPING_INTERVAL")]
    housekeeping_interval_secs: Option<u64>,

    /// Persisted monthly-usage file.
    #[arg(long, env = "ENVOIX_RELAY_USAGE_FILE")]
    usage_file: Option<PathBuf>,

    /// Stats snapshot file read by the `status` command.
    #[arg(long, env = "ENVOIX_RELAY_STATS_FILE")]
    stats_file: Option<PathBuf>,

    /// Start with verbose per-datagram logging (also toggleable via SIGUSR1).
    #[arg(long)]
    debug: bool,
}

/// Print an error and exit non-zero, without a panic backtrace.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        None => run_server(cli.run).await,
        Some(Command::Config(c)) => run_config(c),
        Some(Command::Test { config }) => doctor::run(&config),
        Some(Command::Status { config }) => status::run(&config),
        Some(Command::Pair(args)) => {
            let args = pair::PairArgs {
                config: args.config,
                pairing_port: args.pairing_port,
                public_ip: args.public_ip,
                words: args.words,
                expires_secs: args.expires_secs,
                max_attempts: args.max_attempts,
            };
            if let Err(e) = pair::run(args).await {
                die(format!("pair: {e}"));
            }
        }
        Some(Command::Up) => service::up(),
        Some(Command::Down) => service::down(),
    }
}

fn run_config(args: ConfigArgs) {
    match args.action {
        ConfigAction::Init { path } => {
            let cfg = if path.exists() {
                println!("config already exists: {}", path.display());
                config::Config::load(&path).unwrap_or_else(|e| die(format!("config: {e}")))
            } else {
                let cfg = config::Config::default();
                cfg.save(&path).unwrap_or_else(|e| die(format!("config: {e}")));
                println!("wrote default config: {}", path.display());
                cfg
            };
            keyfile::load_or_generate(&cfg.key_file).unwrap_or_else(|e| die(format!("relay key: {e}")));
            println!("key file: {}", cfg.key_file.display());
        }
        ConfigAction::Show { path } => {
            let cfg = config::Config::load(&path).unwrap_or_else(|e| die(format!("config: {e}")));
            print!("{}", toml::to_string_pretty(&cfg).expect("serialize config"));
            let exists = cfg.key_file.exists();
            println!("# key file: {} ({})", cfg.key_file.display(), if exists {
                "present"
            } else {
                "absent - generated on first run"
            });
        }
    }
}

async fn run_server(args: RunArgs) {
    let cfg = config::Config::load(&args.config).unwrap_or_else(|e| die(format!("config: {e}")));
    init_tracing(args.debug);

    // Resolve listen + the bound ports before any `cfg` field is moved below.
    let listen = args.listen.unwrap_or(cfg.listen);
    let ports = cfg
        .listen_ports(listen.port())
        .unwrap_or_else(|e| die(format!("config: {e}")));

    let key_file = args.key_file.unwrap_or(cfg.key_file);
    let key = match args.key {
        Some(hex) => {
            let key = RelayTokenKey::from_hex(hex.trim())
                .unwrap_or_else(|| die("--key must be 64 hex characters"));
            tracing::info!("using relay master key from --key/ENVOIX_RELAY_KEY");
            key
        }
        None => keyfile::load_or_generate(&key_file)
            .unwrap_or_else(|e| die(format!("relay key: {e}"))),
    };
    let config = RelayConfig {
        max_sessions: args.max_sessions.unwrap_or(cfg.max_sessions),
        max_bytes_per_session: args.max_bytes_per_session.unwrap_or(cfg.max_bytes_per_session),
        idle_timeout: Duration::from_secs(args.idle_timeout_secs.unwrap_or(cfg.idle_timeout_secs)),
    };

    let server = RelayServer::bind(
        listen,
        &ports,
        key,
        config,
        args.monthly_byte_limit.unwrap_or(cfg.monthly_byte_limit),
        args.usage_file.unwrap_or(cfg.usage_file),
    )
    .await
    .unwrap_or_else(|e| die(format!("cannot bind {listen}: {e}")));
    let server = Arc::new(server);
    if args.debug {
        server.toggle_debug();
    }
    tracing::info!(
        ip = %listen.ip(),
        ports = ?ports,
        "envoix relay data plane listening"
    );

    spawn_background_tasks(
        server.clone(),
        Duration::from_secs(args.sweep_interval_secs.unwrap_or(cfg.sweep_interval_secs)),
        Duration::from_secs(
            args.housekeeping_interval_secs
                .unwrap_or(cfg.housekeeping_interval_secs),
        ),
        args.stats_file.unwrap_or(cfg.stats_file),
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
    stats_file: PathBuf,
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
            housekeeping.write_stats(&stats_file).await;
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
