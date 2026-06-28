//! Rendezvous server binary: bind an iroh endpoint, print its endpoint id (the
//! address clients hard-code), and serve room pairing until terminated.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use iroh::SecretKey;

use envoix_rendezvous::RoomRegistry;
use envoix_rendezvous_iroh::{build_endpoint, serve_endpoint};

#[derive(Parser)]
#[command(
    name = "envoix-rendezvous-server",
    about = "Envoix room rendezvous (iroh node)"
)]
struct Cli {
    /// UDP address to bind the iroh endpoint to.
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("envoix_rendezvous_iroh=info,warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    // TODO: persist the secret key so the endpoint id (the address clients
    // hard-code) is stable across restarts. Ephemeral for now.
    let endpoint = build_endpoint(cli.bind, SecretKey::generate()).await?;
    tracing::info!(endpoint_id = %endpoint.id(), "rendezvous server listening");
    println!("rendezvous endpoint id: {}", endpoint.id());

    serve_endpoint(endpoint, Arc::new(RoomRegistry::new())).await
}
