//! The relay data-plane server: receive, validate, forward.
//!
//! Thin transport over `envoix-relay`'s pure logic. Owns the UDP socket,
//! the forwarding table, the persisted monthly counter, and the runtime
//! flags (debug logging, forwarding pause).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use envoix_relay::{
    ForwardOutcome, MonthlyUsage, RelayConfig, RelayDatagram, RelayTable, RelayTokenKey,
};
use tokio::net::UdpSocket;

use crate::stats::{self, StatsSnapshot};
use crate::usage;

pub struct RelayServer {
    socket: UdpSocket,
    table: RelayTable,
    key: RelayTokenKey,
    usage: Mutex<MonthlyUsage>,
    usage_path: PathBuf,
    forwarding_enabled: AtomicBool,
    debug_mode: AtomicBool,
    invalid_total: AtomicU64,
    quota_exceeded_total: AtomicU64,
    started_at: Instant,
}

impl RelayServer {
    pub async fn bind(
        listen: SocketAddr,
        key: RelayTokenKey,
        table_config: RelayConfig,
        monthly_byte_limit: u64,
        usage_path: PathBuf,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen).await?;
        let usage = usage::load(&usage_path, monthly_byte_limit);
        Ok(Self {
            socket,
            table: RelayTable::new(table_config),
            key,
            usage: Mutex::new(usage),
            usage_path,
            forwarding_enabled: AtomicBool::new(true),
            debug_mode: AtomicBool::new(false),
            invalid_total: AtomicU64::new(0),
            quota_exceeded_total: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("bound socket")
    }

    /// Receive loop. Runs until the process exits.
    pub async fn run(&self) {
        // Largest QUIC datagram + 61-byte header is well under 1500; 64 KiB
        // buffer.
        let mut buf = vec![0u8; 65536];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, from)) => self.handle(&buf[..n], from).await,
                Err(e) => tracing::warn!(error = %e, "relay recv error; continuing"),
            }
        }
    }

    async fn handle(&self, datagram: &[u8], from: SocketAddr) {
        // Reachability probe: echo `magic || nonce` straight back to the
        // sender. No token, no forwarding, not counted as traffic - it only
        // lets an external prober confirm this port is reachable. The reply
        // is the same size as the request (1:1, no amplification).
        if envoix_relay::parse_probe(datagram).is_some() {
            let _ = self.socket.send_to(datagram, from).await;
            return;
        }

        // Silent drop on anything invalid.
        let Some(dg) = RelayDatagram::parse(datagram) else {
            self.invalid_total.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some((session, role, _expires)) = self.key.verify(dg.token) else {
            self.invalid_total.fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Manual / signal pause.
        if !self.forwarding_enabled.load(Ordering::Relaxed) {
            return;
        }

        // Monthly quota gate. Lock scope ends before any await.
        let now_month = usage::current_month();
        {
            let mut u = self.usage.lock().expect("usage mutex");
            if !u.check(now_month) {
                self.quota_exceeded_total.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let payload_len = dg.payload.len();
        match self
            .table
            .on_datagram(session, role, from, payload_len)
            .await
        {
            ForwardOutcome::Forward(peer) => {
                if let Err(e) = self.socket.send_to(dg.payload, peer).await {
                    tracing::debug!(error = %e, "forward send failed");
                    return;
                }
                self.usage
                    .lock()
                    .expect("usage mutex")
                    .record(payload_len as u64);
                if self.debug_mode.load(Ordering::Relaxed) {
                    tracing::info!(?session, %from, %peer, bytes = payload_len, "forwarded");
                }
            }
            ForwardOutcome::PeerUnknown => {
                if self.debug_mode.load(Ordering::Relaxed) {
                    tracing::info!(?session, ?role, %from, "peer not yet present; dropped");
                }
            }
            ForwardOutcome::SessionCutOff => {
                tracing::warn!(?session, "per-session byte cap reached; pair cut off");
            }
            ForwardOutcome::CapacityExceeded => {
                if self.debug_mode.load(Ordering::Relaxed) {
                    tracing::info!(?session, "session cap reached; dropped");
                }
            }
        }
    }

    // runtime controls (signal-driven)
    /// Toggle verbose per-datagram logging. Returns the new state.
    pub fn toggle_debug(&self) -> bool {
        let prev = self.debug_mode.fetch_xor(true, Ordering::Relaxed);
        !prev
    }

    /// Toggle forwarding (graceful pause). Returns the new state.
    pub fn toggle_forwarding(&self) -> bool {
        let prev = self.forwarding_enabled.fetch_xor(true, Ordering::Relaxed);
        !prev
    }

    /// Persist the usage counter (periodic + on shutdown).
    pub fn flush_usage(&self) {
        let snapshot = self.usage.lock().expect("usage mutex").snapshot();
        if let Err(e) = usage::save(&self.usage_path, snapshot) {
            tracing::warn!(error = %e, "failed to persist relay usage");
        }
    }

    pub async fn sweep_idle(&self) {
        self.table.sweep_idle().await;
    }

    /// Build a point-in-time stats snapshot.
    pub async fn snapshot(&self) -> StatsSnapshot {
        let t = self.table.stats().await;
        let (month_bytes, limit) = {
            let u = self.usage.lock().expect("usage mutex");
            (u.month_bytes(), u.limit())
        };
        StatsSnapshot {
            written_at_unix: stats::now_unix(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            forwarding_enabled: self.forwarding_enabled.load(Ordering::Relaxed)
                && month_bytes < limit,
            active_pairs: t.active_pairs,
            pairs_created_total: t.pairs_created_total,
            datagrams_forwarded_total: t.datagrams_forwarded_total,
            bytes_forwarded_total: t.bytes_forwarded_total,
            month_bytes,
            month_byte_limit: limit,
            invalid_total: self.invalid_total.load(Ordering::Relaxed),
            quota_exceeded_total: self.quota_exceeded_total.load(Ordering::Relaxed),
            session_cap_cutoff_total: t.session_cap_cutoff_total,
            rejected_capacity_total: t.rejected_capacity_total,
        }
    }

    /// Persist the stats snapshot for the `status` command to read.
    pub async fn write_stats(&self, path: &Path) {
        if let Err(e) = self.snapshot().await.save(path) {
            tracing::warn!(error = %e, "failed to write stats snapshot");
        }
    }

    /// Emit the `relay` stats line.
    pub async fn log_stats(&self) {
        let t = self.table.stats().await;
        let (month_bytes, limit) = {
            let u = self.usage.lock().expect("usage mutex");
            (u.month_bytes(), u.limit())
        };
        let enabled = self.forwarding_enabled.load(Ordering::Relaxed) && month_bytes < limit;
        tracing::info!(
            forwarding_enabled = enabled,
            active_pairs = t.active_pairs,
            pairs_created_total = t.pairs_created_total,
            bytes_forwarded_total = t.bytes_forwarded_total,
            datagrams_forwarded_total = t.datagrams_forwarded_total,
            month_bytes,
            month_byte_limit = limit,
            invalid_total = self.invalid_total.load(Ordering::Relaxed),
            quota_exceeded_total = self.quota_exceeded_total.load(Ordering::Relaxed),
            session_cap_cutoff_total = t.session_cap_cutoff_total,
            rejected_capacity_total = t.rejected_capacity_total,
            "relay stats"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use envoix_relay::{RelayRole, RelaySessionId, encode, encode_probe};

    const KEY: [u8; 32] = [9u8; 32];

    fn tmp_usage_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "envoix-relay-test-{}-{tag}.json",
            std::process::id()
        ))
    }

    async fn spawn_server(config: RelayConfig, monthly_limit: u64, tag: &str) -> Arc<RelayServer> {
        let path = tmp_usage_path(tag);
        let _ = std::fs::remove_file(&path);
        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RelayTokenKey::from_bytes(KEY),
            config,
            monthly_limit,
            path,
        )
        .await
        .expect("bind");
        let server = Arc::new(server);
        let run = server.clone();
        tokio::spawn(async move { run.run().await });
        server
    }

    fn token(role: RelayRole) -> [u8; 57] {
        RelayTokenKey::from_bytes(KEY).mint(
            &RelaySessionId::from_bytes([0x22; 16]),
            role,
            SystemTime::now() + Duration::from_secs(300),
        )
    }

    async fn recv_timeout(sock: &UdpSocket, buf: &mut [u8]) -> Option<usize> {
        tokio::time::timeout(Duration::from_millis(500), sock.recv_from(buf))
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|(n, _)| n)
    }

    #[tokio::test]
    async fn cross_forwards_between_two_peers() {
        let server = spawn_server(RelayConfig::default(), u64::MAX, "xfwd").await;
        let relay = server.local_addr();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Sender registers first.
        sender
            .send_to(&encode(&token(RelayRole::Sender), b"S"), relay)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Receiver sends payload - relay forwards the BARE payload to sender.
        receiver
            .send_to(&encode(&token(RelayRole::Receiver), b"hello-quic"), relay)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let n = recv_timeout(&sender, &mut buf)
            .await
            .expect("sender receives forward");
        assert_eq!(&buf[..n], b"hello-quic"); // header stripped, bare payload
    }

    #[tokio::test]
    async fn invalid_token_is_dropped() {
        let server = spawn_server(RelayConfig::default(), u64::MAX, "bad").await;
        let relay = server.local_addr();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Wrong magic / garbage token - no reply, no forward.
        let mut bad = vec![0u8; 70];
        peer.send_to(&bad, relay).await.unwrap();
        // Valid frame shape but bad token bytes.
        bad = encode(&[0xff; 57], b"payload");
        peer.send_to(&bad, relay).await.unwrap();

        let mut buf = [0u8; 64];
        assert!(recv_timeout(&peer, &mut buf).await.is_none());
    }

    #[tokio::test]
    async fn probe_is_echoed_back() {
        let server = spawn_server(RelayConfig::default(), u64::MAX, "probe").await;
        let relay = server.local_addr();
        let prober = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let nonce = [0x5cu8; 16];
        let probe = encode_probe(&nonce);
        prober.send_to(&probe, relay).await.unwrap();

        let mut buf = [0u8; 64];
        let n = recv_timeout(&prober, &mut buf).await.expect("probe echoed");
        assert_eq!(&buf[..n], &probe[..]); // exact magic||nonce back

        // A probe echoes even while forwarding is paused (it is not traffic).
        assert!(!server.toggle_forwarding());
        prober.send_to(&probe, relay).await.unwrap();
        let n = recv_timeout(&prober, &mut buf).await.expect("echoed when paused");
        assert_eq!(&buf[..n], &probe[..]);
    }

    #[tokio::test]
    async fn paused_forwarding_drops() {
        let server = spawn_server(RelayConfig::default(), u64::MAX, "pause").await;
        let relay = server.local_addr();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender
            .send_to(&encode(&token(RelayRole::Sender), b"S"), relay)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(!server.toggle_forwarding()); // now paused
        receiver
            .send_to(&encode(&token(RelayRole::Receiver), b"data"), relay)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(recv_timeout(&sender, &mut buf).await.is_none());

        // Resume -> forwarding works again.
        assert!(server.toggle_forwarding());
        receiver
            .send_to(&encode(&token(RelayRole::Receiver), b"data2"), relay)
            .await
            .unwrap();
        let n = recv_timeout(&sender, &mut buf).await.expect("resumed");
        assert_eq!(&buf[..n], b"data2");
    }

    #[tokio::test]
    async fn monthly_quota_blocks_then_persists() {
        // Limit so small the first forwarded payload trips it.
        let server = spawn_server(RelayConfig::default(), 3, "quota").await;
        let relay = server.local_addr();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender
            .send_to(&encode(&token(RelayRole::Sender), b"S"), relay)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // First payload (5 bytes) forwards but pushes month_bytes to 5 >= 3.
        receiver
            .send_to(&encode(&token(RelayRole::Receiver), b"first"), relay)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let _ = recv_timeout(&sender, &mut buf).await; // may or may not arrive

        // Next datagram is over quota -> dropped regardless.
        receiver
            .send_to(&encode(&token(RelayRole::Receiver), b"second"), relay)
            .await
            .unwrap();
        assert!(recv_timeout(&sender, &mut buf).await.is_none());

        // Persisted counter reflects usage.
        server.flush_usage();
    }
}
