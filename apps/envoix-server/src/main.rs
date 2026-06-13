//! Envoix rendezvous server binary.
//!
//! Thin transport shell: CLI parsing, tracing initialisation,
//! axum wiring, graceful shutdown. All session behaviour lives in
//! `envoix-rendezvous`.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use envoix_rendezvous::{RegistryConfig, SessionRegistry};

mod api;

/// CLI flags.
#[derive(Parser)]
#[command(name = "envoix-server", about = "Envoix rendezvous server")]
struct Cli {
    /// Socket address to bind.
    #[arg(long, env = "ENVOIX_LISTEN", default_value = "127.0.0.1:9100")]
    listen: SocketAddr,

    /// Bearer token for /api/v1/stats. Unset disables the endpoint.
    #[arg(long, env = "ENVOIX_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// Hard cap on concurrently live sessions.
    #[arg(long, env = "ENVOIX_MAX_SESSIONS", default_value_t = 10_000)]
    max_sessions: usize,

    /// Hard cap on candidates per session.
    #[arg(long, env = "ENVOIX_MAX_CANDIDATES", default_value_t = 32)]
    max_candidates_per_session: usize,

    /// Session TTL when the client does not request one.
    #[arg(long, env = "ENVOIX_DEFAULT_TTL", default_value_t = 300)]
    default_ttl_seconds: u64,

    /// Upper bound on client-requested TTL.
    #[arg(long, env = "ENVOIX_MAX_TTL", default_value_t = 1800)]
    max_ttl_seconds: u64,

    /// Shared 64-hex relay key — must match the relay server's
    /// `--relay-key`. Required (with `--relay-advertise`) to enable the
    /// relay-allocation endpoint.
    #[arg(long, env = "ENVOIX_RELAY_KEY", requires = "relay_advertise")]
    relay_key: Option<String>,

    /// Public relay endpoint advertised to clients, e.g.
    /// "67.230.187.238:9104". Required with `--relay-key`.
    #[arg(long, env = "ENVOIX_RELAY_ADVERTISE", requires = "relay_key")]
    relay_advertise: Option<String>,

    /// Upgrade envoix log targets to debug (ignored if RUST_LOG is set).
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.debug);

    let config = RegistryConfig {
        max_sessions: cli.max_sessions,
        max_candidates_per_session: cli.max_candidates_per_session,
        default_ttl: Duration::from_secs(cli.default_ttl_seconds),
        max_ttl: Duration::from_secs(cli.max_ttl_seconds),
    };
    let relay = match (cli.relay_key, cli.relay_advertise) {
        (Some(key), Some(advertise)) => Some((key, advertise)),
        _ => None,
    };
    let state = api::AppState::new(SessionRegistry::new(config), cli.admin_token, relay);
    let app = api::router(state.clone());

    // Background TTL sweep; tombstoning expired sessions and
    // forgetting stale tombstones. Opportunistic expiry on read covers the
    // window between ticks.
    state.spawn_ttl_sweep(Duration::from_secs(30));

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {e}", cli.listen));
    tracing::info!(listen = %cli.listen, "envoix rendezvous server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await
        .expect("server error");
    tracing::info!("shutdown complete");
}

/// Resolves when SIGTERM or Ctrl-C arrives. Sets the shutting-down flag so
/// new requests get `503 service_shutting_down` while axum
/// drains in-flight ones. The 5-second hard bound on draining is enforced
/// by the supervisor (systemd `TimeoutStopSec`), not in-process.
async fn shutdown_signal(state: api::AppState) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    state.begin_shutdown();
    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Default filter: envoix targets at `info`, everything
/// else at `warn`. `--debug` upgrades envoix targets; `RUST_LOG` overrides
/// everything. Target names are the actual crate names (underscored);
/// `envoix=info` is shorthand for these.
fn init_tracing(debug: bool) {
    let level = if debug { "debug" } else { "info" };
    let default = format!("envoix_server={level},envoix_rendezvous={level},warn");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
