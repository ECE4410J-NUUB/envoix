use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use envoix_discovery::{
    LanDiscoveryConfig, LanDiscoveryRecord, MdnsLanAdvertiser, MdnsLanDiscovery,
};
use envoix_error::CoreError;
use envoix_session::{EventSink, NoopEventSink, SessionConfig, TransferDirection, TransferSummary};
use envoix_transport::{ConnectionCandidate, FrameConnection, TransportListener};

use crate::{ClientEvent, ClientEventSink, PublicError, ReceiveRequest, SendRequest};

/// Timeout used for LAN mDNS discovery.
const LAN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_AUTH_FAILURES: u32 = 50;
/// Cap on pairing handshakes running at once, so a flood of half-open
/// connections cannot exhaust the receiver while we authenticate in parallel.
const MAX_CONCURRENT_AUTH: usize = 16;

pub(crate) async fn send(
    request: SendRequest,
    config: SessionConfig,
    client_events: Box<dyn ClientEventSink>,
    transfer_events: Box<dyn EventSink>,
) -> Result<TransferSummary, PublicError> {
    client_events.on_event(ClientEvent::AutoConnectionStarted {
        direction: TransferDirection::Send,
    });

    let candidates = discover_lan_candidates(client_events.as_ref()).await?;
    dial_lan_candidates(request, config, candidates, transfer_events).await
}

async fn discover_lan_candidates(
    client_events: &dyn ClientEventSink,
) -> Result<Vec<ConnectionCandidate>, PublicError> {
    client_events.on_event(ClientEvent::LanDiscoveryStarted);

    let lan_config = LanDiscoveryConfig {
        timeout: LAN_DISCOVERY_TIMEOUT,
        // session_id not set: sender connects to any Envoix receiver on
        // the LAN.  SPAKE2 auth gates the actual transfer; wrong-token
        // attempts fail before any data moves.
        ..Default::default()
    };
    let discovery = MdnsLanDiscovery::new(lan_config);

    let candidates = match discovery.discover().await {
        Ok(candidates) => candidates,
        Err(e) => {
            client_events.on_event(ClientEvent::LanDiscoveryFailed {
                reason: e.to_string(),
            });
            return Err(e.into());
        }
    };

    for c in &candidates {
        client_events.on_event(ClientEvent::LanCandidateFound { candidate: *c });
    }

    Ok(candidates)
}

async fn dial_lan_candidates(
    request: SendRequest,
    config: SessionConfig,
    candidates: Vec<ConnectionCandidate>,
    transfer_events: Box<dyn EventSink>,
) -> Result<TransferSummary, PublicError> {
    let mut last_error = None;
    let mut transfer_events = transfer_events;
    for candidate in &candidates {
        match envoix_session::send_file_manual(
            match candidate {
                ConnectionCandidate::Quic { addr } => *addr,
            },
            request.file_path.clone(),
            request.resume,
            config.clone(),
            transfer_events,
        )
        .await
        {
            Ok(summary) => return Ok(summary),
            Err(e) => {
                last_error = Some(e);
                // Use NoopEventSink for subsequent retries so partial
                // progress from the failed attempt is not re-emitted.
                transfer_events = Box::new(NoopEventSink);
            }
        }
    }

    Err(last_error.expect("candidates is non-empty; loop ran at least once"))
}

pub(crate) async fn receive<F>(
    request: ReceiveRequest,
    config: SessionConfig,
    client_events: Box<dyn ClientEventSink>,
    transfer_events: Box<dyn EventSink>,
    on_bound: F,
) -> Result<TransferSummary, PublicError>
where
    F: FnOnce(SocketAddr) + Send,
{
    client_events.on_event(ClientEvent::AutoConnectionStarted {
        direction: TransferDirection::Receive,
    });

    let output_dir = request.output_dir;

    // Bind first, then report the address to the caller so they can
    // print a QR invite or log the port, then start mDNS advertising.
    let listener = Arc::new(envoix_session::bind_quic_listener(request.listen_addr)?);
    let bound_addr = listener.local_addr()?;
    let port = bound_addr.port();

    on_bound(bound_addr);

    // Create a safe session identifier (random, not derived from token).
    let session_id = format!("envoix-{}", fast_random_id());

    let record = LanDiscoveryRecord {
        protocol_version: envoix_discovery::ENVOIX_DISCOVERY_PROTO_VERSION,
        session_id,
        port,
        features: "quic-v1".into(),
    };

    let advertiser = match MdnsLanAdvertiser::start(&record) {
        Ok(a) => {
            client_events.on_event(ClientEvent::LanDiscoveryStarted);
            Some(a)
        }
        Err(e) => {
            // Non-fatal: advertise best-effort, but still accept.
            client_events.on_event(ClientEvent::LanDiscoveryFailed {
                reason: format!("mDNS advertisement failed: {e}"),
            });
            None
        }
    };

    let engine = envoix_session::TransferEngine::new(config.chunk_size);
    let mut connection = match accept_authenticated_connection(listener, &config).await {
        Ok(conn) => conn,
        Err(e) => {
            client_events.on_event(ClientEvent::TooManyAuthFailures);
            return Err(e);
        }
    };
    drop(advertiser);

    let summary = engine
        .receive_file(&mut *connection, output_dir, transfer_events.as_ref())
        .await?;
    let _ = connection.close().await;

    Ok(summary)
}

async fn accept_authenticated_connection(
    listener: Arc<envoix_session::BoundListener>,
    config: &SessionConfig,
) -> Result<Box<dyn FrameConnection>, PublicError> {
    // Accept AND authenticate connections concurrently. A peer that connects
    // but never finishes - whether it stalls opening its stream (so `accept`
    // itself blocks) or stalls the SPAKE2 handshake (up to AUTH_TIMEOUT) - then
    // only ties up one slot instead of blocking every peer behind it. We keep
    // MAX_CONCURRENT_AUTH attempts in flight and the first to authenticate
    // wins; remaining attempts are dropped when this returns. Total failures
    // stay bounded by MAX_AUTH_FAILURES.
    // Per-attempt result: Ok = authenticated; Err(Some) = a real listener
    // error (fatal, propagate it); Err(None) = this peer just failed to
    // authenticate (count it and keep trying).
    type Attempt = Result<Box<dyn FrameConnection>, Option<PublicError>>;
    let spawn_attempt = |tasks: &mut tokio::task::JoinSet<Attempt>| {
        let listener = listener.clone();
        let pairing = config.pairing.clone();
        tasks.spawn(async move {
            // A failed accept means the listener/endpoint is broken, not a bad
            // peer - carry the error out so it is reported, not miscounted.
            let mut connection = listener.accept().await.map_err(Some)?;
            let authenticated = matches!(
                tokio::time::timeout(
                    AUTH_TIMEOUT,
                    envoix_session::authenticate_receiver(&mut *connection, &pairing),
                )
                .await,
                Ok(Ok(())),
            );
            if authenticated {
                Ok(connection)
            } else {
                let _ = connection.close().await;
                Err(None)
            }
        });
    };

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..MAX_CONCURRENT_AUTH {
        spawn_attempt(&mut tasks);
    }

    let mut failures = 0u32;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(connection)) => return Ok(connection), // first authenticated peer wins
            Ok(Err(Some(error))) => return Err(error),   // listener broke; surface it
            // Auth failed/timed out, or the task panicked.
            Ok(Err(None)) | Err(_) => {}
        }
        failures += 1;
        if failures >= MAX_AUTH_FAILURES {
            break;
        }
        spawn_attempt(&mut tasks); // keep the pool topped up
    }

    Err(CoreError::Protocol(format!(
        "too many failed pairing attempts (threshold: {MAX_AUTH_FAILURES}); another peer may be using the wrong token or interfering"
    )))
}

/// Generate a short random identifier for session names.
///
/// Combines the process ID and a high-precision timestamp so that two
/// receivers started in the same nanosecond on different processes (or on
/// different machines) still produce distinct identifiers.  This is not
/// cryptographically random but is more than sufficient for mDNS instance
/// disambiguation on a LAN.
/// The function should not be called in other places, especially where
/// a crypto-secure random id is needed.
fn fast_random_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u64;
    // Mix PID and timestamp so simultaneous launches produce unique IDs.
    let combined = pid.wrapping_mul(31_337).wrapping_add(nanos as u64);
    format!("{:012x}", combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use envoix_auth::PairingConfig;
    use envoix_transport::{ConnectionCandidate, TransportDialer};
    use envoix_transport_quic::QuicDialer;

    fn test_config(token: &str) -> SessionConfig {
        SessionConfig {
            chunk_size: envoix_session::DEFAULT_CHUNK_SIZE,
            pairing: PairingConfig::Spake2SharedToken { token: token.to_string() },
        }
    }

    /// A peer that connects but never authenticates must not block a peer
    /// behind it: with sequential auth the receiver would wait AUTH_TIMEOUT
    /// (10s) on the staller, so returning well inside that window proves the
    /// handshakes run in parallel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalling_peer_does_not_block_a_good_peer() {
        let config = test_config("shared-pairing-token");
        let listener =
            Arc::new(envoix_session::bind_quic_listener("127.0.0.1:0".parse().unwrap()).unwrap());
        let addr = listener.local_addr().unwrap();

        // Stalling peer: dial, then sit there without ever authenticating.
        let staller = tokio::spawn(async move {
            let conn = QuicDialer
                .dial(ConnectionCandidate::Quic { addr })
                .await
                .expect("staller dials");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        });

        // Let the staller connect first, so it is the one queued ahead.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Good peer: dial and complete the SPAKE2 handshake, then hold open.
        let good_config = config.clone();
        let good = tokio::spawn(async move {
            let mut conn = QuicDialer
                .dial(ConnectionCandidate::Quic { addr })
                .await
                .expect("good peer dials");
            envoix_session::authenticate_sender(&mut *conn, &good_config.pairing)
                .await
                .expect("good peer authenticates");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let start = Instant::now();
        // Outer timeout is below AUTH_TIMEOUT: a sequential receiver blocked on
        // the staller would trip this, failing the test.
        let accepted = tokio::time::timeout(
            Duration::from_secs(5),
            accept_authenticated_connection(listener, &config),
        )
        .await;

        let elapsed = start.elapsed();
        staller.abort();
        good.abort();

        let accepted = accepted.expect("accept timed out: staller blocked the good peer");
        assert!(accepted.is_ok(), "the good peer should have authenticated");
        assert!(
            elapsed < AUTH_TIMEOUT,
            "accepted in {elapsed:?}, not faster than one auth timeout - not parallel?"
        );
    }
}
