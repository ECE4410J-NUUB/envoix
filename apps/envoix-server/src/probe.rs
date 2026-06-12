//! UDP probe service: the socket task for reflexive discovery.
//!
//! Thin transport per the crate split — frame parsing, token validation,
//! and candidate publication all live in `envoix-rendezvous`; this module
//! owns only the socket loop. Behaviour per
//! `docs/reflexive-discovery-design.md` §4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use envoix_rendezvous::{
    CandidateKind, CandidatePublish, Error, ProbeReply, ProbeRequest, ProbeTokenKey,
    SessionRegistry, Transport,
};
use tokio::net::UdpSocket;

/// Priority assigned to auto-published reflexive candidates (design §9:
/// below typical host/LAN priorities; advisory, the client re-ranks).
const REFLEXIVE_PRIORITY: i32 = 50;

/// Counters for the `probes` stats block (design §4.4).
#[derive(Default)]
pub struct ProbeCounters {
    pub received_total: AtomicU64,
    pub invalid_total: AtomicU64,
    pub published_total: AtomicU64,
}

/// Run one probe socket until process exit. Non-panicking by
/// construction: every fallible call is matched, transient socket errors
/// are logged and the loop continues.
pub async fn run_probe_socket(
    socket: UdpSocket,
    registry: Arc<SessionRegistry>,
    key: Arc<ProbeTokenKey>,
    counters: Arc<ProbeCounters>,
) {
    let local = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".into());
    tracing::info!(listen = %local, "probe socket listening");

    // Largest valid datagram is 70 bytes; anything bigger is invalid by
    // definition, so a small buffer suffices (oversized datagrams arrive
    // truncated and fail the exact-length check).
    let mut buf = [0u8; 128];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(ok) => ok,
            Err(e) => {
                tracing::warn!(error = %e, "probe recv error; continuing");
                continue;
            }
        };
        counters.received_total.fetch_add(1, Ordering::Relaxed);

        // Silent-drop pipeline (design §4.1) — cheapest checks first.
        let Some(request) = ProbeRequest::decode(&buf[..len]) else {
            counters.invalid_total.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some((session_id, role, _expires_at)) = key.verify(&request.token) else {
            counters.invalid_total.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        // Session liveness is part of validation: a probe against a dead
        // session gets silence. A live session whose candidate cap is
        // full still gets a reply (the mapping is valid information) —
        // the candidate just isn't stored.
        let publish = registry
            .publish_candidate_for_role(
                &session_id,
                role,
                CandidatePublish {
                    kind: CandidateKind::ServerReflexiveUdp,
                    transport: Transport::Quic,
                    addr: src,
                    priority: REFLEXIVE_PRIORITY,
                },
            )
            .await;
        match publish {
            Ok(_) => {
                counters.published_total.fetch_add(1, Ordering::Relaxed);
            }
            Err(Error::InvalidRequest(_)) => {
                // Candidate cap reached: reply but don't count a publish.
            }
            Err(_) => {
                // Not found / expired / closed: silent drop.
                counters.invalid_total.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }

        let reply = ProbeReply {
            txid: request.txid,
            observed: src,
        }
        .encode();
        if let Err(e) = socket.send_to(&reply, src).await {
            tracing::debug!(error = %e, "probe reply send failed");
        }
        tracing::debug!(session_ref = ?session_id, observed = %src, "probe answered");
    }
}

/// Bind every configured probe address. Fails fast at startup — a
/// misconfigured deployment should not come up half-working.
pub async fn bind_probe_sockets(addrs: &[SocketAddr]) -> std::io::Result<Vec<UdpSocket>> {
    let mut sockets = Vec::with_capacity(addrs.len());
    for addr in addrs {
        sockets.push(UdpSocket::bind(addr).await?);
    }
    Ok(sockets)
}
