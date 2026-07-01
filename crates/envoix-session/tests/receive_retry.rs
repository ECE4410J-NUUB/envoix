use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use envoix_protocol::PeerDescriptor;
use envoix_session::{
    DEFAULT_CHUNK_SIZE, IdentityConfig, NoopEventSink, PairingConfig, SessionConfig,
    bind_iroh_endpoint, receive_with_auth_retries_with_cancel, send_file_manual_with_cancel,
};
use tempfile::tempdir;

fn config() -> SessionConfig {
    SessionConfig {
        chunk_size: DEFAULT_CHUNK_SIZE,
        pairing: PairingConfig::Spake2SharedToken {
            token: "abcdefghijkl".into(),
        },
        identity: IdentityConfig::Ephemeral,
        relay: None,
    }
}

fn loopback_peer(peer: &PeerDescriptor) -> PeerDescriptor {
    let port = peer.direct_addrs[0].port();
    PeerDescriptor::new(
        peer.endpoint_id.clone(),
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receiver_waits_for_next_sender_after_authenticated_peer_quits() {
    let dir = tempdir().unwrap();
    let output_dir = dir.path().join("received");
    std::fs::create_dir(&output_dir).unwrap();

    let bound = bind_iroh_endpoint(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        &IdentityConfig::Ephemeral,
    )
    .await
    .unwrap();
    let peer = loopback_peer(&bound.peer_descriptor().unwrap());
    let cancel = envoix_session::TransferCancelToken::new();
    let receive = tokio::spawn(receive_with_auth_retries_with_cancel(
        bound,
        output_dir.clone(),
        config(),
        Box::new(NoopEventSink),
        cancel.clone(),
    ));

    let missing_file = dir.path().join("sender-quit-before-hello.txt");
    let first_send = send_file_manual_with_cancel(
        peer.clone(),
        missing_file,
        false,
        config(),
        Box::new(NoopEventSink),
        envoix_session::TransferCancelToken::new(),
    )
    .await;
    assert!(
        first_send.is_err(),
        "first sender should quit before transfer"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !receive.is_finished(),
        "receiver exited instead of waiting again"
    );

    let source = dir.path().join("retry.txt");
    let contents = b"hello after sender quit";
    std::fs::write(&source, contents).unwrap();
    let send = send_file_manual_with_cancel(
        peer,
        source,
        false,
        config(),
        Box::new(NoopEventSink),
        envoix_session::TransferCancelToken::new(),
    )
    .await;
    send.expect("second sender should complete");

    tokio::time::timeout(Duration::from_secs(10), receive)
        .await
        .expect("receiver timed out")
        .unwrap()
        .expect("receiver should complete after retry");

    assert_eq!(
        std::fs::read(output_dir.join("retry.txt")).unwrap(),
        contents
    );
}
