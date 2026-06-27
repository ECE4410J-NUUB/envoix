//! End-to-end over real iroh: two clients connect to a loopback rendezvous,
//! join the same room, and run the full SPAKE2 + sealed-descriptor exchange
//! through the broker's blind relay.

use std::sync::Arc;
use std::time::Duration;

use envoix_pairing::{
    Confirm, PakeResponse, PakeStart, initiator_start, open_json, responder_respond, seal_json,
};
use envoix_rendezvous::{Role, RoomRegistry, read_framed, write_framed};
use envoix_rendezvous_server::{
    BrokerSession, build_endpoint, endpoint_addr, join_room, serve_endpoint,
};
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

/// Run whichever pairing side the broker assigned; return (role, peer descriptor).
async fn run_peer(
    session: BrokerSession,
    code: &str,
    my_descriptor: &str,
) -> Result<(Role, String), Box<dyn std::error::Error + Send + Sync>> {
    let BrokerSession { connection, mut send, mut recv, role } = session;
    let key = match role {
        Role::Initiator => {
            let (pending, start) = initiator_start(code)?;
            write_framed(&mut send, &start).await?;
            let response: PakeResponse = read_framed(&mut recv).await?;
            let (confirming, confirm) = pending.finish(&response)?;
            write_framed(&mut send, &confirm).await?;
            let responder_confirm: Confirm = read_framed(&mut recv).await?;
            confirming.verify(&responder_confirm)?
        }
        Role::Responder => {
            let start: PakeStart = read_framed(&mut recv).await?;
            let (confirming, response) = responder_respond(code, &start)?;
            write_framed(&mut send, &response).await?;
            let initiator_confirm: Confirm = read_framed(&mut recv).await?;
            let (key, confirm) = confirming.verify(&initiator_confirm)?;
            write_framed(&mut send, &confirm).await?;
            key
        }
    };

    write_framed(&mut send, &seal_json(key.key(), &my_descriptor.to_string())?).await?;
    let sealed: Vec<u8> = read_framed(&mut recv).await?;
    let other: String = open_json(key.key(), &sealed)?;

    // Finish our send, then wait for the broker to acknowledge it (stopped) so
    // the FIN is actually delivered through the relay. Then drain our recv to
    // EOF so we have all relayed data before the connection is dropped.
    let _ = send.finish();
    let _ = send.stopped().await;
    let mut drain = Vec::new();
    let _ = tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut drain).await;
    drop(connection);
    Ok((role, other))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_iroh_peers_pair_through_the_rendezvous() {
    // Broker.
    let server = endpoint().await;
    let broker = ready_addr(&server).await;
    tokio::spawn(serve_endpoint(server, Arc::new(RoomRegistry::new())));

    // Two clients join the same room.
    let ca = endpoint().await;
    let cb = endpoint().await;
    let broker_a = broker.clone();
    let broker_b = broker.clone();

    let a = tokio::spawn(async move {
        let session = join_room(&ca, broker_a, "room-7").await.unwrap();
        run_peer(session, "7-amber-comet", "endpoint-A").await
    });
    // Small stagger; run_peer handles either role assignment regardless.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let b = tokio::spawn(async move {
        let session = join_room(&cb, broker_b, "room-7").await.unwrap();
        run_peer(session, "7-amber-comet", "endpoint-B").await
    });

    let join = Duration::from_secs(20);
    let (role_a, a_got) = tokio::time::timeout(join, a)
        .await
        .expect("peer A timed out")
        .unwrap()
        .expect("peer A pairs");
    let (role_b, b_got) = tokio::time::timeout(join, b)
        .await
        .expect("peer B timed out")
        .unwrap()
        .expect("peer B pairs");

    // Exactly one initiator and one responder.
    assert_ne!(role_a, role_b);
    // Each received the OTHER peer's descriptor, sealed under the shared key.
    assert_eq!(a_got, "endpoint-B");
    assert_eq!(b_got, "endpoint-A");
}
