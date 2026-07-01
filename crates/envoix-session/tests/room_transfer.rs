//! End-to-end: a file transfers from sender to receiver after they pair in a
//! room over a loopback rendezvous broker, using only a short code.

use std::sync::Arc;
use std::time::Duration;

use envoix_rendezvous::RoomRegistry;
use envoix_rendezvous_iroh::{build_endpoint, endpoint_addr, serve_endpoint};
use envoix_session::{
    DEFAULT_CHUNK_SIZE, IdentityConfig, NoopEventSink, PairingConfig, SessionConfig,
    receive_file_via_room, send_file_via_room,
};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tempfile::tempdir;

async fn ready_addr(ep: &Endpoint) -> EndpointAddr {
    for _ in 0..100 {
        if ep.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    endpoint_addr(ep)
}

/// A config whose pairing token is overwritten by the room flow.
fn config() -> SessionConfig {
    SessionConfig {
        chunk_size: DEFAULT_CHUNK_SIZE,
        pairing: PairingConfig::Spake2SharedToken {
            token: "unused-placeholder".into(),
        },
        identity: IdentityConfig::Ephemeral,
        relay: None,
        relay_only: false,
        direct_only: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_transfers_through_the_rendezvous() {
    // Rendezvous broker.
    let server = build_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        SecretKey::generate(),
        RelayMode::Disabled,
    )
    .await
    .unwrap();
    let broker = ready_addr(&server).await;
    tokio::spawn(serve_endpoint(server, Arc::new(RoomRegistry::new())));

    // A source file and an output directory.
    let dir = tempdir().unwrap();
    let src = dir.path().join("greeting.txt");
    let contents = b"hello through the room rendezvous";
    std::fs::write(&src, contents).unwrap();
    let out = dir.path().join("received");
    std::fs::create_dir(&out).unwrap();

    let code = "1234-amber-comet";
    let listen: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (broker_r, broker_s) = (broker.clone(), broker.clone());
    let out_dir = out.clone();
    let recv = tokio::spawn(async move {
        receive_file_via_room(
            broker_r,
            code,
            listen,
            out_dir,
            config(),
            Box::new(NoopEventSink),
        )
        .await
    });
    // Let the receiver bind + start pairing first.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let send = tokio::spawn(async move {
        send_file_via_room(
            broker_s,
            code,
            src,
            false,
            config(),
            Box::new(NoopEventSink),
        )
        .await
    });

    let join = Duration::from_secs(30);
    let sent = tokio::time::timeout(join, send)
        .await
        .expect("send timed out")
        .unwrap();
    let received = tokio::time::timeout(join, recv)
        .await
        .expect("recv timed out")
        .unwrap();
    sent.expect("sender ok");
    received.expect("receiver ok");

    // The file arrived intact under its original name.
    let got = std::fs::read(out.join("greeting.txt")).expect("received file");
    assert_eq!(got, contents);
}
