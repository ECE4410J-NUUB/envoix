//! End-to-end: two peers join a room through the broker and run the full
//! `envoix-pairing` exchange (SPAKE2 + sealed descriptors) over the broker's
//! blind relay. Uses in-memory duplexes - no sockets, no iroh.

use std::sync::Arc;
use std::time::Duration;

use envoix_pairing::{
    Confirm, PakeResponse, PakeStart, initiator_start, open_json, responder_respond, seal_json,
};
use envoix_rendezvous::{Join, Paired, PeerConn, Role, RoomRegistry, read_framed, write_framed};
use tokio::io::DuplexStream;

/// Wrap the broker's side of a duplex as a `PeerConn` (the halves own the
/// stream, so no separate keep-alive is needed).
fn broker_conn(stream: DuplexStream) -> PeerConn {
    let (reader, writer) = tokio::io::split(stream);
    PeerConn::new(writer, reader, ())
}

/// Drive the initiator client over `stream`; returns the role the broker
/// assigned and the peer descriptor recovered from the other side.
async fn run_initiator(
    stream: DuplexStream,
    room: &str,
    code: &str,
    my_descriptor: &str,
) -> Result<(Role, String), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    write_framed(
        &mut writer,
        &Join {
            room_id: room.to_string(),
        },
    )
    .await?;
    let paired: Paired = read_framed(&mut reader).await?;

    let (pending, start) = initiator_start(code)?;
    write_framed(&mut writer, &start).await?;
    let response: PakeResponse = read_framed(&mut reader).await?;
    let (confirming, confirm) = pending.finish(&response)?;
    write_framed(&mut writer, &confirm).await?;
    let responder_confirm: Confirm = read_framed(&mut reader).await?;
    let key = confirming.verify(&responder_confirm)?;

    // Seal our descriptor under K and exchange.
    write_framed(
        &mut writer,
        &seal_json(key.key(), b"room-test", &my_descriptor.to_string())?,
    )
    .await?;
    let sealed: Vec<u8> = read_framed(&mut reader).await?;
    let other: String = open_json(key.key(), b"room-test", &sealed)?;
    Ok((paired.role, other))
}

/// Drive the responder client over `stream`.
async fn run_responder(
    stream: DuplexStream,
    room: &str,
    code: &str,
    my_descriptor: &str,
) -> Result<(Role, String), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    write_framed(
        &mut writer,
        &Join {
            room_id: room.to_string(),
        },
    )
    .await?;
    let paired: Paired = read_framed(&mut reader).await?;

    let start: PakeStart = read_framed(&mut reader).await?;
    let (confirming, response) = responder_respond(code, &start)?;
    write_framed(&mut writer, &response).await?;
    let initiator_confirm: Confirm = read_framed(&mut reader).await?;
    let (key, confirm) = confirming.verify(&initiator_confirm)?;
    write_framed(&mut writer, &confirm).await?;

    write_framed(
        &mut writer,
        &seal_json(key.key(), b"room-test", &my_descriptor.to_string())?,
    )
    .await?;
    let sealed: Vec<u8> = read_framed(&mut reader).await?;
    let other: String = open_json(key.key(), b"room-test", &sealed)?;
    Ok((paired.role, other))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_pair_and_exchange_descriptors() {
    let registry = Arc::new(RoomRegistry::with_ttl(Duration::from_secs(5)));
    let (client_a, broker_a) = tokio::io::duplex(64 * 1024);
    let (client_b, broker_b) = tokio::io::duplex(64 * 1024);

    let r1 = registry.clone();
    let s1 = tokio::spawn(async move { r1.serve(broker_conn(broker_a)).await });
    let r2 = registry.clone();
    let s2 = tokio::spawn(async move { r2.serve(broker_conn(broker_b)).await });

    // First joiner becomes the initiator. Give A a small head start so the
    // role assignment is deterministic.
    let a = tokio::spawn(async move {
        run_initiator(client_a, "room-42", "12-orange-tiger", "endpoint-A").await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let b = tokio::spawn(async move {
        run_responder(client_b, "room-42", "12-orange-tiger", "endpoint-B").await
    });

    let (role_a, a_got) = a.await.unwrap().expect("initiator pairs");
    let (role_b, b_got) = b.await.unwrap().expect("responder pairs");

    assert_eq!(role_a, Role::Initiator);
    assert_eq!(role_b, Role::Responder);
    // Each recovered the OTHER peer's descriptor, sealed under the shared key.
    assert_eq!(a_got, "endpoint-B");
    assert_eq!(b_got, "endpoint-A");

    s1.await.unwrap().expect("broker serves A");
    s2.await.unwrap().expect("broker serves B");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lone_peer_expires() {
    let registry = Arc::new(RoomRegistry::with_ttl(Duration::from_millis(200)));
    let (mut client, broker) = tokio::io::duplex(4096);

    let serve = tokio::spawn(async move { registry.serve(broker_conn(broker)).await });

    // Join a room nobody else joins.
    let (mut reader, mut writer) = tokio::io::split(&mut client);
    write_framed(
        &mut writer,
        &Join {
            room_id: "empty".to_string(),
        },
    )
    .await
    .unwrap();

    // The broker gives up after the TTL.
    let result = serve.await.unwrap();
    assert!(matches!(
        result,
        Err(envoix_rendezvous::RendezvousError::Expired)
    ));

    // And the parked stream is closed, so the client sees EOF.
    let pending: Result<Paired, _> = read_framed(&mut reader).await;
    assert!(pending.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_long_room_id_is_rejected() {
    let registry = Arc::new(RoomRegistry::new());
    let (mut client, broker) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn(async move { registry.serve(broker_conn(broker)).await });

    let (_reader, mut writer) = tokio::io::split(&mut client);
    write_framed(
        &mut writer,
        &Join {
            room_id: "x".repeat(1024),
        },
    )
    .await
    .unwrap();

    let result = serve.await.unwrap();
    assert!(matches!(
        result,
        Err(envoix_rendezvous::RendezvousError::Rejected(_))
    ));
}
