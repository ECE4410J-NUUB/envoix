//! Rendezvous server binary: bind an iroh endpoint, print a usable rendezvous
//! address (`<endpoint-id>@<ip:port>`), and serve room pairing until terminated.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use iroh::SecretKey;

use envoix_rendezvous::RoomRegistry;
use envoix_rendezvous_iroh::{build_endpoint, relay_mode_from_url, serve_endpoint};

#[derive(Parser)]
#[command(
    name = "envoix-rendezvous-server",
    about = "Envoix room rendezvous (iroh node)"
)]
struct Cli {
    /// UDP address to bind the iroh endpoint to. Defaults to a fixed port so the
    /// advertised `<endpoint-id>@<ip:port>` stays stable across restarts; use a
    /// random `:0` port only for throwaway or relay-only setups.
    #[arg(long, default_value = "0.0.0.0:8445")]
    bind: SocketAddr,
    /// File holding the server's persistent secret key (created with owner-only
    /// permissions if missing), so the endpoint id stays stable across restarts.
    #[arg(long, default_value = "rendezvous-secret.key")]
    secret_key: PathBuf,
    /// Relay URL to register with for WAN reachability (e.g.
    /// https://relay.example.com:8444). Omit for no relay (LAN/direct only).
    #[arg(long)]
    relay: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("envoix_rendezvous_iroh=info,warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let secret_key = load_or_create_secret_key(&cli.secret_key)
        .with_context(|| format!("secret key {}", cli.secret_key.display()))?;
    let relay = relay_mode_from_url(cli.relay.as_deref())?;
    let endpoint = build_endpoint(cli.bind, secret_key, relay).await?;
    tracing::info!(endpoint_id = %endpoint.id(), bind = %cli.bind, "rendezvous server listening");
    println!("rendezvous endpoint id: {}", endpoint.id());
    println!("listening on {}", cli.bind);
    // Print a ready-to-use --rendezvous value. When bound to an unspecified
    // address (0.0.0.0/::) the reachable host is unknown to the process, so show
    // the (now fixed) port and let the operator fill in the public IP.
    if cli.bind.ip().is_unspecified() {
        println!(
            "connect with: --rendezvous {}@<this-host-ip>:{}",
            endpoint.id(),
            cli.bind.port()
        );
    } else {
        println!("connect with: --rendezvous {}@{}", endpoint.id(), cli.bind);
    }

    serve_endpoint(endpoint, Arc::new(RoomRegistry::new())).await
}

/// Load the server's secret key from `path`, creating a fresh one if the file
/// does not exist, so the endpoint id is stable across restarts. A newly
/// created file is written with owner-only permissions on Unix.
fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret key file must be exactly 32 bytes"))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret_key(path, &key.to_bytes())?;
    Ok(key)
}

#[cfg(unix)]
fn write_secret_key(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(not(unix))]
fn write_secret_key(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn secret_key_is_created_then_reused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.key");

        let first = load_or_create_secret_key(&path).expect("create");
        assert!(path.exists(), "key file should be created");
        let second = load_or_create_secret_key(&path).expect("reuse");

        assert_eq!(first.public(), second.public(), "key must be stable");
    }

    #[test]
    fn wrong_length_key_file_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, b"too short").unwrap();
        assert!(load_or_create_secret_key(&path).is_err());
    }
}
