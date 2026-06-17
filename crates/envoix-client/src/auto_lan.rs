use std::net::SocketAddr;
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
    let listener = envoix_session::bind_quic_listener(request.listen_addr)?;
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
    let mut connection = match accept_authenticated_connection(&listener, &config).await {
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
    listener: &envoix_session::BoundListener,
    config: &SessionConfig,
) -> Result<Box<dyn FrameConnection>, PublicError> {
    // TODO: consider concurrently trying multiple candidates to make the app
    // more DoS resistant.
    for _ in 0..MAX_AUTH_FAILURES {
        let mut connection = listener.accept().await?;
        let result = tokio::time::timeout(
            AUTH_TIMEOUT,
            envoix_session::authenticate_receiver(&mut *connection, &config.pairing),
        )
        .await;

        match result {
            Ok(Ok(())) => return Ok(connection),
            Ok(Err(_)) | Err(_) => {
                let _ = connection.close().await;
            }
        }
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
