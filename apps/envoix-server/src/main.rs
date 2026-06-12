//! Envoix rendezvous server binary.
//!
//! Thin transport shell per design §2: CLI parsing, tracing initialisation,
//! axum wiring, graceful shutdown. All session behaviour lives in
//! `envoix-rendezvous`.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use envoix_rendezvous::{RegistryConfig, SessionRegistry};

mod api;
mod probe;

/// CLI flags per design §4.9.
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

    /// UDP bind addresses for the reflexive probe service, comma
    /// separated (e.g. "0.0.0.0:9101,0.0.0.0:9102"). Unset disables the
    /// feature entirely.
    #[arg(
        long,
        env = "ENVOIX_PROBE_LISTEN",
        requires = "probe_advertise",
        value_delimiter = ','
    )]
    probe_listen: Vec<SocketAddr>,

    /// Public host:port pairs advertised to clients as probe endpoints,
    /// comma separated. Required with --probe-listen — behind NAT the
    /// server cannot know its own public address.
    #[arg(
        long,
        env = "ENVOIX_PROBE_ADVERTISE",
        requires = "probe_listen",
        value_delimiter = ','
    )]
    probe_advertise: Vec<String>,

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
    let probe_advertise = if cli.probe_listen.is_empty() {
        None
    } else {
        Some(cli.probe_advertise.clone())
    };
    let state = api::AppState::new(
        SessionRegistry::new(config),
        cli.admin_token,
        probe_advertise,
    );
    let app = api::router(state.clone());

    // Background TTL sweep (design §4.4); tombstoning expired sessions and
    // forgetting stale tombstones. Opportunistic expiry on read covers the
    // window between ticks.
    state.spawn_ttl_sweep(Duration::from_secs(30));

    // Reflexive probe sockets (reflexive-discovery design §5). Bind
    // failures abort startup — a half-working deployment is worse than a
    // loud one.
    if !cli.probe_listen.is_empty() {
        let sockets = probe::bind_probe_sockets(&cli.probe_listen)
            .await
            .unwrap_or_else(|e| panic!("cannot bind probe sockets {:?}: {e}", cli.probe_listen));
        state.spawn_probe_tasks(sockets);
    }

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
/// new requests get `503 service_shutting_down` (design §4.6) while axum
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

/// Default filter per design §4.7: envoix targets at `info`, everything
/// else at `warn`. `--debug` upgrades envoix targets; `RUST_LOG` overrides
/// everything. Target names are the actual crate names (underscored) —
/// the design's `envoix=info` is shorthand for these.
fn init_tracing(debug: bool) {
    let level = if debug { "debug" } else { "info" };
    let default = format!("envoix_server={level},envoix_rendezvous={level},warn");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
