//! uniffi bridge exposing the envoix client core to native UIs (Swift/Kotlin).
//!
//! The bridge is intentionally thin: it wires the existing [`EnvoixClient`]
//! facade and the QR invite codec to a small, foreign-implementable observer.
//! All networking, pairing, and transfer logic stays in the Rust core.
//!
//! Operations are non-blocking. Each call spawns work on a session-owned tokio
//! runtime and returns immediately; results arrive through [`TransferObserver`]
//! callbacks, which fire on runtime threads — the UI must hop to its own main
//! thread before touching UI state.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use envoix_client::{
    ClientConfig, ClientEvent, ClientEventSink, ConnectionPolicy, EnvoixClient, EventSink,
    PairingConfig, PeerDescriptor, PublicError, ReceiveRequest, SendFileRequest, SendRequest,
    TransferCancelToken, TransferEvent, TransferSummary,
};
use envoix_qr::{QrInvitePayload, generate_token};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// Lifetime of a generated invite before it expires, in seconds.
const INVITE_TTL_SECS: u64 = 300;
/// Receiver bind address: any IPv4 interface, OS-assigned port.
const RECEIVE_ADDR: &str = "0.0.0.0:0";

/// Error surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EnvoixError {
    /// An operation failed; `message` is a human-readable reason.
    #[error("{message}")]
    Operation {
        /// Human-readable failure reason.
        message: String,
    },
}

fn op_err(error: impl std::fmt::Display) -> EnvoixError {
    EnvoixError::Operation {
        message: error.to_string(),
    }
}

/// Observer implemented by the native UI to receive transfer updates.
///
/// Callbacks arrive on a Rust runtime thread; the UI must marshal to its main
/// thread before mutating UI state. Exactly one of [`on_completed`] /
/// [`on_failed`] fires per operation.
///
/// [`on_completed`]: TransferObserver::on_completed
/// [`on_failed`]: TransferObserver::on_failed
#[uniffi::export(with_foreign)]
pub trait TransferObserver: Send + Sync {
    /// Receiver only: the `envoix:…` invite string to render as a QR / share.
    fn on_invite_ready(&self, invite: String);
    /// A transfer started; `total_bytes` is the full file size.
    fn on_started(&self, file_name: String, total_bytes: u64);
    /// Progress update: `transferred` of `total` plaintext bytes.
    fn on_progress(&self, transferred: u64, total: u64);
    /// Terminal success: the transfer finished and was verified.
    fn on_completed(&self, bytes: u64);
    /// Terminal failure with a human-readable reason.
    fn on_failed(&self, reason: String);
    /// Free-form lifecycle/status text for display or logging.
    fn on_status(&self, message: String);
}

/// A send/receive session driving the envoix core off its own runtime.
#[derive(uniffi::Object)]
pub struct EnvoixSession {
    runtime: Runtime,
    cancel: Mutex<Option<TransferCancelToken>>,
}

#[uniffi::export]
impl EnvoixSession {
    /// Creates a session with its own multi-threaded runtime.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        Arc::new(Self {
            runtime,
            cancel: Mutex::new(None),
        })
    }

    /// Starts receiving one file into `output_dir`.
    ///
    /// Returns immediately. A fresh pairing token is generated and the invite
    /// is delivered via [`TransferObserver::on_invite_ready`]; the outcome
    /// arrives via `on_completed` / `on_failed`.
    pub fn receive(
        &self,
        output_dir: String,
        observer: Arc<dyn TransferObserver>,
    ) -> Result<(), EnvoixError> {
        let token = generate_token().map_err(op_err)?;
        let client = build_client(token.clone())?;
        let listen_addr = RECEIVE_ADDR.parse().map_err(op_err)?;
        let cancel = self.replace_cancel();

        self.runtime.spawn(async move {
            let transfer_sink = Box::new(ObserverSink(observer.clone()));
            let client_sink = Box::new(ClientSink(observer.clone()));
            let invite_observer = observer.clone();
            let on_bound = move |peer: PeerDescriptor| {
                let payload = QrInvitePayload::new(token, peer, unix_now() + INVITE_TTL_SECS);
                invite_observer.on_invite_ready(payload.encode());
            };
            let result = client
                .receive_with_cancel(
                    ReceiveRequest {
                        output_dir: output_dir.into(),
                        connection_policy: ConnectionPolicy::EnableMdns,
                        listen_addr,
                    },
                    client_sink,
                    transfer_sink,
                    on_bound,
                    cancel,
                )
                .await;
            report_terminal(&*observer, result);
        });
        Ok(())
    }

    /// Starts sending `file_path` to the peer encoded in `invite`.
    ///
    /// Returns immediately; the outcome arrives via `on_completed` /
    /// `on_failed`. The invite is validated (expiry, version) before any
    /// connection is attempted.
    pub fn send_invite(
        &self,
        invite: String,
        file_path: String,
        observer: Arc<dyn TransferObserver>,
    ) -> Result<(), EnvoixError> {
        let ResolvedInvite { peer, token } = resolve_invite(&invite)?;
        let client = build_client(token)?;
        let cancel = self.replace_cancel();

        self.runtime.spawn(async move {
            let transfer_sink = Box::new(ObserverSink(observer.clone()));
            let result = client
                .send_file_with_cancel(
                    SendFileRequest {
                        peer,
                        file_path: file_path.into(),
                        resume: true,
                    },
                    transfer_sink,
                    cancel,
                )
                .await;
            report_terminal(&*observer, result);
        });
        Ok(())
    }

    /// Starts receiving one file into `output_dir`, pairing on the local
    /// network with a shared `token` (no invite needed).
    ///
    /// Both peers enter the same token; the receiver advertises over mDNS and
    /// the sender discovers it. Requires both peers on the same LAN. The token
    /// must be at least 12 ASCII bytes.
    pub fn receive_mdns(
        &self,
        output_dir: String,
        token: String,
        observer: Arc<dyn TransferObserver>,
    ) -> Result<(), EnvoixError> {
        let client = build_client(token)?;
        let listen_addr = RECEIVE_ADDR.parse().map_err(op_err)?;
        let cancel = self.replace_cancel();

        self.runtime.spawn(async move {
            let transfer_sink = Box::new(ObserverSink(observer.clone()));
            let client_sink = Box::new(ClientSink(observer.clone()));
            let result = client
                .receive_with_cancel(
                    ReceiveRequest {
                        output_dir: output_dir.into(),
                        connection_policy: ConnectionPolicy::EnableMdns,
                        listen_addr,
                    },
                    client_sink,
                    transfer_sink,
                    |_peer| {},
                    cancel,
                )
                .await;
            report_terminal(&*observer, result);
        });
        Ok(())
    }

    /// Starts sending `file_path`, discovering the receiver on the local
    /// network via a shared `token` (no invite needed).
    ///
    /// Both peers enter the same token; requires both on the same LAN. The
    /// token must be at least 12 ASCII bytes.
    pub fn send_mdns(
        &self,
        file_path: String,
        token: String,
        observer: Arc<dyn TransferObserver>,
    ) -> Result<(), EnvoixError> {
        let client = build_client(token)?;
        let cancel = self.replace_cancel();

        self.runtime.spawn(async move {
            let transfer_sink = Box::new(ObserverSink(observer.clone()));
            let client_sink = Box::new(ClientSink(observer.clone()));
            let result = client
                .send_with_cancel(
                    SendRequest {
                        file_path: file_path.into(),
                        connection_policy: ConnectionPolicy::EnableMdns,
                        resume: true,
                    },
                    client_sink,
                    transfer_sink,
                    cancel,
                )
                .await;
            report_terminal(&*observer, result);
        });
        Ok(())
    }

    /// Requests cancellation of the in-flight transfer, if any.
    pub fn cancel(&self) {
        if let Some(cancel) = self.cancel.lock().unwrap().as_ref() {
            cancel.cancel();
        }
    }
}

impl EnvoixSession {
    /// Installs a fresh cancel token for a new operation and returns it.
    fn replace_cancel(&self) -> TransferCancelToken {
        let cancel = TransferCancelToken::new();
        *self.cancel.lock().unwrap() = Some(cancel.clone());
        cancel
    }
}

fn build_client(token: String) -> Result<EnvoixClient, EnvoixError> {
    let pairing = PairingConfig::spake2_shared_token(token).map_err(op_err)?;
    Ok(EnvoixClient::new(ClientConfig::new(pairing)))
}

/// Fields extracted from a validated invite.
struct ResolvedInvite {
    peer: PeerDescriptor,
    token: String,
}

fn resolve_invite(invite: &str) -> Result<ResolvedInvite, EnvoixError> {
    let payload = QrInvitePayload::decode(invite).map_err(op_err)?;
    payload.validate(unix_now()).map_err(op_err)?;
    let peer = payload.peer_descriptor().map_err(op_err)?;
    Ok(ResolvedInvite {
        peer,
        token: payload.token,
    })
}

/// Reports the single terminal outcome from the awaited operation result.
fn report_terminal(observer: &dyn TransferObserver, result: Result<TransferSummary, PublicError>) {
    match result {
        Ok(summary) => observer.on_completed(summary.bytes_transferred),
        Err(error) => observer.on_failed(error.to_string()),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Adapts core transfer events onto the foreign observer. Terminal
/// `Completed`/`Failed` events are dropped here so the outcome is reported
/// exactly once from the awaited result instead.
struct ObserverSink(Arc<dyn TransferObserver>);

impl EventSink for ObserverSink {
    fn on_event(&self, event: TransferEvent) {
        match event {
            TransferEvent::Started {
                file_name,
                total_bytes,
                ..
            } => self.0.on_started(file_name, total_bytes),
            TransferEvent::Progress {
                bytes_transferred,
                total_bytes,
                ..
            } => self.0.on_progress(bytes_transferred, total_bytes),
            TransferEvent::HashStarted { .. } => self.0.on_status("verifying".to_string()),
            TransferEvent::HashCompleted { .. } => self.0.on_status("verified".to_string()),
            TransferEvent::Completed { .. } | TransferEvent::Failed { .. } => {}
        }
    }
}

/// Adapts core client-lifecycle events onto the foreign observer as status text.
struct ClientSink(Arc<dyn TransferObserver>);

impl ClientEventSink for ClientSink {
    fn on_event(&self, event: ClientEvent) {
        let message = match event {
            ClientEvent::NetworkDetectionStarted => "detecting network".to_string(),
            ClientEvent::EndpointStarted { .. } => "starting endpoint".to_string(),
            ClientEvent::DirectAddressAvailable { peer } => format!("address: {peer}"),
            ClientEvent::DialStarted { peer } => format!("dialing {peer}"),
            ClientEvent::Authenticated { .. } => "authenticated".to_string(),
            ClientEvent::ConnectionFailed { reason } => format!("connection failed: {reason}"),
            ClientEvent::TooManyAuthFailures => "too many failed pairing attempts".to_string(),
        };
        self.0.on_status(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc::{Sender, channel};
    use std::time::Duration;

    enum Msg {
        Invite(String),
        Completed(u64),
        Failed(String),
    }

    struct TestObserver(Sender<Msg>);

    impl TransferObserver for TestObserver {
        fn on_invite_ready(&self, invite: String) {
            let _ = self.0.send(Msg::Invite(invite));
        }
        fn on_started(&self, _file_name: String, _total_bytes: u64) {}
        fn on_progress(&self, _transferred: u64, _total: u64) {}
        fn on_completed(&self, bytes: u64) {
            let _ = self.0.send(Msg::Completed(bytes));
        }
        fn on_failed(&self, reason: String) {
            let _ = self.0.send(Msg::Failed(reason));
        }
        fn on_status(&self, _message: String) {}
    }

    /// Rewrites an invite's direct addresses to loopback, keeping the port, so
    /// the transfer stays on the local machine (mirrors the CLI loopback test).
    fn loopback_invite(invite: &str) -> String {
        let mut payload = QrInvitePayload::decode(invite).unwrap();
        let port = payload.peer.direct_addrs[0].port();
        payload.peer.direct_addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)];
        payload.encode()
    }

    #[test]
    fn ffi_qr_invite_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("received");
        std::fs::create_dir_all(&output_dir).unwrap();
        let source = dir.path().join("hello.txt");
        let text = b"hello from the ffi bridge";
        std::fs::write(&source, text).unwrap();

        let receiver = EnvoixSession::new();
        let (rtx, rrx) = channel();
        receiver
            .receive(
                output_dir.to_str().unwrap().to_string(),
                Arc::new(TestObserver(rtx)),
            )
            .unwrap();

        let invite = match rrx.recv_timeout(Duration::from_secs(10)).unwrap() {
            Msg::Invite(invite) => loopback_invite(&invite),
            _ => panic!("expected an invite before any other event"),
        };

        // Let the receiver's accept loop start before dialing.
        std::thread::sleep(Duration::from_millis(300));

        let sender = EnvoixSession::new();
        let (stx, srx) = channel();
        sender
            .send_invite(
                invite,
                source.to_str().unwrap().to_string(),
                Arc::new(TestObserver(stx)),
            )
            .unwrap();

        match srx.recv_timeout(Duration::from_secs(15)).unwrap() {
            Msg::Completed(_) => {}
            Msg::Failed(reason) => panic!("send failed: {reason}"),
            Msg::Invite(_) => panic!("sender unexpectedly produced an invite"),
        }

        let bytes = loop {
            match rrx.recv_timeout(Duration::from_secs(15)).expect("receiver timed out") {
                Msg::Completed(bytes) => break bytes,
                Msg::Failed(reason) => panic!("receiver failed: {reason}"),
                Msg::Invite(_) => continue,
            }
        };

        assert_eq!(bytes, text.len() as u64);
        assert_eq!(std::fs::read(output_dir.join("hello.txt")).unwrap(), text);
    }
}
