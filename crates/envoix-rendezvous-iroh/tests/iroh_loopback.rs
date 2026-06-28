//! End-to-end over real iroh: two clients connect to a loopback rendezvous,
//! join the same room, and pair via `pair_in_room`, exchanging their real iroh
//! `PeerDescriptor`s through the broker's blind relay.

use std::sync::Arc;
use std::time::Duration;

use envoix_protocol::PeerDescriptor;
use envoix_rendezvous::RoomRegistry;
use envoix_rendezvous_iroh::{build_endpoint, endpoint_addr, pair_in_room, serve_endpoint};
use iroh::{Endpoint, EndpointAddr, SecretKey};

/// Loopback bind, fresh identity.
async fn endpoint() -> Endpoint {
    build_endpoint("127.0.0.1:0".parse().unwrap(), SecretKey::generate())
        .await
        .expect("bind endpoint")
}

/// Wait until the endpoint has a direct address, then return its connectable addr.
async fn ready_addr(ep: &Endpoint) -> EndpointAddr {
    for _ in 0..100 {
        if ep.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    endpoint_addr(ep)
}

/// This endpoint's app-level descriptor (id + direct addrs).
fn descriptor(ep: &Endpoint) -> PeerDescriptor {
    PeerDescriptor::new(ep.id().to_string(), ep.addr().ip_addrs().copied().collect())
        .expect("descriptor")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_iroh_peers_pair_through_the_rendezvous() {
    // Broker.
    let server = endpoint().await;
    let broker = ready_addr(&server).await;
    tokio::spawn(serve_endpoint(server, Arc::new(RoomRegistry::new())));

    // Two clients, each with a real (address-ready) descriptor to exchange.
    let ca = endpoint().await;
    let cb = endpoint().await;
    let _ = ready_addr(&ca).await;
    let _ = ready_addr(&cb).await;
    let desc_a = descriptor(&ca);
    let desc_b = descriptor(&cb);

    let (broker_a, broker_b) = (broker.clone(), broker.clone());
    let (mine_a, mine_b) = (desc_a.clone(), desc_b.clone());
    let a = tokio::spawn(async move {
        pair_in_room(&ca, broker_a, "room-7", "7-amber-comet", &mine_a).await
    });
    // Small stagger; the SPAKE2 role is by arrival but pair_in_room handles either.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let b = tokio::spawn(async move {
        pair_in_room(&cb, broker_b, "room-7", "7-amber-comet", &mine_b).await
    });

    let join = Duration::from_secs(20);
    let a_got = tokio::time::timeout(join, a).await.expect("A timed out").unwrap().expect("A pairs");
    let b_got = tokio::time::timeout(join, b).await.expect("B timed out").unwrap().expect("B pairs");

    // Each recovered the OTHER peer's iroh descriptor, sealed under the shared key.
    assert_eq!(a_got, desc_b);
    assert_eq!(b_got, desc_a);
}
