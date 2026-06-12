//! HTTP surface: routes, request/response shapes, error mapping.
//!
//! Thin transport layer per design §2 — all session behaviour lives in
//! `envoix-rendezvous`; this module translates HTTP to library calls and
//! library errors to the JSON envelope of design §3.4.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use envoix_rendezvous::{
    Candidate, CandidateKind, CandidatePublish, Capability, CapabilityHash, Error, PeerMetadata,
    ProbeRole, ProbeTokenKey, SessionId, SessionRegistry, Transport,
};
// SSoT: the wire version the whole workspace speaks (design §3.3
// `protocol_versions`). Never redeclare locally — a future bump in
// envoix-types must reach this server's 422 check automatically.
use envoix_types::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

use crate::probe::{ProbeCounters, run_probe_socket};

/// Request body cap per design §4.6 robustness budget.
const BODY_LIMIT_BYTES: usize = 64 * 1024;

/// HTTP-level request counters for `/api/v1/stats` (design §4.8).
#[derive(Default)]
struct RequestCounters {
    total: AtomicU64,
    by_status: Mutex<HashMap<u16, u64>>,
}

/// Probe-service state, present only when `--probe-listen` is configured
/// (`docs/reflexive-discovery-design.md` §5).
struct ProbeState {
    key: Arc<ProbeTokenKey>,
    advertise: Vec<String>,
}

#[derive(Clone)]
pub struct AppState {
    registry: Arc<SessionRegistry>,
    shutting_down: Arc<AtomicBool>,
    /// BLAKE3 of the admin token; `None` disables `/api/v1/stats`.
    admin_token_hash: Option<blake3::Hash>,
    request_counters: Arc<RequestCounters>,
    probe: Option<Arc<ProbeState>>,
    probe_counters: Arc<ProbeCounters>,
    started_at: Instant,
}

impl AppState {
    /// `probe_advertise`: the public `host:port` list put into
    /// `probe_endpoints` response fields. `Some` enables the probe
    /// feature (a fresh token key is generated); `None` disables it.
    pub fn new(
        registry: SessionRegistry,
        admin_token: Option<String>,
        probe_advertise: Option<Vec<String>>,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            shutting_down: Arc::new(AtomicBool::new(false)),
            admin_token_hash: admin_token.map(|t| blake3::hash(t.as_bytes())),
            request_counters: Arc::new(RequestCounters::default()),
            probe: probe_advertise.map(|advertise| {
                Arc::new(ProbeState {
                    key: Arc::new(ProbeTokenKey::random()),
                    advertise,
                })
            }),
            probe_counters: Arc::new(ProbeCounters::default()),
            started_at: Instant::now(),
        }
    }

    /// Spawn one task per bound probe socket. No-op (empty vec) when the
    /// probe feature is disabled.
    pub fn spawn_probe_tasks(
        &self,
        sockets: Vec<tokio::net::UdpSocket>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let Some(probe) = &self.probe else {
            return Vec::new();
        };
        sockets
            .into_iter()
            .map(|socket| {
                tokio::spawn(run_probe_socket(
                    socket,
                    self.registry.clone(),
                    probe.key.clone(),
                    self.probe_counters.clone(),
                ))
            })
            .collect()
    }

    /// Flip the flag consulted by [`reject_during_shutdown`]. Called once
    /// from the signal handler.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
    }

    /// Background TTL sweep per design §4.4 — non-panicking by
    /// construction; recovery from task death is the supervisor's job.
    pub fn spawn_ttl_sweep(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let registry = self.registry.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                registry.sweep_expired().await;
                tracing::debug!("ttl sweep completed");
            }
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/sessions", post(register))
        .route("/api/v1/sessions/{id}/join", post(join))
        .route("/api/v1/sessions/{id}", delete(close))
        .route(
            "/api/v1/sessions/{id}/candidates",
            post(publish_candidate).get(poll_candidates),
        )
        .route("/api/v1/stats", get(stats))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            reject_during_shutdown,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            count_requests,
        ))
        .with_state(state)
}

// ── Error envelope ───────────────────────────────────────────────────────

/// Wrapper so library errors become the `{code, message}` envelope.
struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if matches!(self.0, Error::Internal(_)) {
            tracing::error!(error = %self.0, "internal error");
        }
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = Json(serde_json::json!({
            "code": self.0.code(),
            "message": self.0.to_string(),
        }));
        (status, body).into_response()
    }
}

/// `axum::Json` with rejections mapped into the error envelope
/// (over-limit body → `payload_too_large`, malformed JSON →
/// `invalid_request`).
struct AppJson<T>(T);

impl<S, T> FromRequest<S> for AppJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(AppJson(value)),
            Err(rej) => Err(ApiError(match rej.status() {
                StatusCode::PAYLOAD_TOO_LARGE => Error::PayloadTooLarge,
                _ => Error::InvalidRequest(rej.body_text()),
            })),
        }
    }
}

// ── Middleware ───────────────────────────────────────────────────────────

/// New requests after SIGTERM get `503 service_shutting_down`; in-flight
/// requests (already past this layer) finish naturally (design §4.6).
async fn reject_during_shutdown(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if state.shutting_down.load(Ordering::Relaxed) {
        return ApiError(Error::ServiceShuttingDown).into_response();
    }
    next.run(req).await
}

/// Outermost layer: counts every response by status for `/api/v1/stats`.
async fn count_requests(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let res = next.run(req).await;
    state.request_counters.total.fetch_add(1, Ordering::Relaxed);
    let mut by_status = state
        .request_counters
        .by_status
        .lock()
        .expect("status-counter mutex poisoned");
    *by_status.entry(res.status().as_u16()).or_insert(0) += 1;
    res
}

// ── Request/response shapes ──────────────────────────────────────────────

#[derive(Deserialize)]
struct PeerMetadataBody {
    protocol_versions: Vec<u32>,
    #[serde(default)]
    strategies: Vec<String>,
}

#[derive(Deserialize)]
struct RegisterBody {
    session_id: String,
    /// BLAKE3 hash of `sender_cap`, 64 lowercase hex chars. The raw sender
    /// capability never reaches the server (design §4.1).
    sender_cap_hash: String,
    peer_metadata: PeerMetadataBody,
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
struct RegisterResponse {
    session_id: String,
    /// Effective expiry after server-side TTL clamping, RFC 3339.
    expires_at: String,
    /// Present only when the probe service is enabled (design §3.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_endpoints: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct JoinBody {
    peer_metadata: PeerMetadataBody,
}

#[derive(Serialize)]
struct JoinResponse {
    /// Refreshed session expiry, RFC 3339.
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_endpoints: Option<Vec<String>>,
}

/// Candidate `kind` wire strings (design §3.3). Unknown kinds fail serde
/// → `400 invalid_request`.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KindBody {
    Host,
    Ipv6Global,
    /// Accepted over HTTP too — a client may publish reflexive addresses
    /// learned elsewhere (e.g. public STUN).
    ServerReflexiveUdp,
}

impl From<KindBody> for CandidateKind {
    fn from(k: KindBody) -> Self {
        match k {
            KindBody::Host => CandidateKind::Host,
            KindBody::Ipv6Global => CandidateKind::Ipv6Global,
            KindBody::ServerReflexiveUdp => CandidateKind::ServerReflexiveUdp,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportBody {
    Quic,
}

impl From<TransportBody> for Transport {
    fn from(t: TransportBody) -> Self {
        match t {
            TransportBody::Quic => Transport::Quic,
        }
    }
}

#[derive(Deserialize)]
struct PublishBody {
    kind: KindBody,
    transport: TransportBody,
    addr: SocketAddr,
    #[serde(default)]
    priority: i32,
}

#[derive(Serialize)]
struct CandidateJson {
    kind: &'static str,
    transport: &'static str,
    addr: String,
    priority: i32,
    sequence: u64,
    published_at: String,
}

impl From<Candidate> for CandidateJson {
    fn from(c: Candidate) -> Self {
        Self {
            kind: match c.kind {
                CandidateKind::Host => "host",
                CandidateKind::Ipv6Global => "ipv6_global",
                CandidateKind::ServerReflexiveUdp => "server_reflexive_udp",
            },
            transport: match c.transport {
                Transport::Quic => "quic",
            },
            addr: c.addr.to_string(),
            priority: c.priority,
            sequence: c.sequence,
            published_at: humantime::format_rfc3339_seconds(c.published_at).to_string(),
        }
    }
}

#[derive(Serialize)]
struct PeerMetadataJson {
    observed_http_addr: Option<String>,
    protocol_versions: Vec<u32>,
    strategies: Vec<String>,
    first_seen: String,
    last_seen: String,
}

impl From<PeerMetadata> for PeerMetadataJson {
    fn from(m: PeerMetadata) -> Self {
        Self {
            observed_http_addr: m.observed_http_addr.map(|a| a.to_string()),
            protocol_versions: m.protocol_versions,
            strategies: m.strategies,
            first_seen: humantime::format_rfc3339_seconds(m.first_seen).to_string(),
            last_seen: humantime::format_rfc3339_seconds(m.last_seen).to_string(),
        }
    }
}

#[derive(Serialize)]
struct PollResponse {
    peer_metadata: Option<PeerMetadataJson>,
    candidates: Vec<CandidateJson>,
}

#[derive(Deserialize)]
struct PollQuery {
    #[serde(default)]
    since: u64,
}

// ── Handlers ─────────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<RegisterBody>,
) -> Result<impl IntoResponse, ApiError> {
    let receiver_cap_hex = bearer_token(&headers)?;
    let receiver_cap = Capability::from_hex(receiver_cap_hex).map_err(|_| Error::Unauthorized)?;

    // Raw-string distinctness (design §3.1) is checked here because the
    // library only ever sees hashes.
    if body.session_id == receiver_cap_hex {
        return Err(
            Error::InvalidRequest("session_id must differ from receiver_cap".into()).into(),
        );
    }

    check_version(&body.peer_metadata)?;
    let id = SessionId::from_hex(&body.session_id)?;
    let sender_cap_hash = CapabilityHash::from_hex(&body.sender_cap_hash)?;
    let metadata = peer_metadata(&headers, body.peer_metadata);
    let ttl = body.ttl_seconds.map(Duration::from_secs);

    let expires_at = state
        .registry
        .register(
            id.clone(),
            receiver_cap.hash(),
            sender_cap_hash,
            metadata,
            ttl,
        )
        .await?;
    let (probe_token, probe_endpoints) = probe_fields(&state, &id, ProbeRole::Receiver, expires_at);

    tracing::info!(session_ref = &body.session_id[..8], "session registered");
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            session_id: body.session_id,
            expires_at: humantime::format_rfc3339_seconds(expires_at).to_string(),
            probe_token,
            probe_endpoints,
        }),
    ))
}

async fn join(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    AppJson(body): AppJson<JoinBody>,
) -> Result<impl IntoResponse, ApiError> {
    let cap = Capability::from_hex(bearer_token(&headers)?).map_err(|_| Error::Unauthorized)?;
    check_version(&body.peer_metadata)?;
    let session_id = SessionId::from_hex(&id)?;
    let metadata = peer_metadata(&headers, body.peer_metadata);

    let expires_at = state
        .registry
        .join(&session_id, &cap.hash(), metadata)
        .await?;
    let (probe_token, probe_endpoints) =
        probe_fields(&state, &session_id, ProbeRole::Sender, expires_at);

    tracing::info!(session_ref = &id[..8], "sender joined");
    Ok(Json(JoinResponse {
        expires_at: humantime::format_rfc3339_seconds(expires_at).to_string(),
        probe_token,
        probe_endpoints,
    }))
}

async fn close(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let cap = Capability::from_hex(bearer_token(&headers)?).map_err(|_| Error::Unauthorized)?;
    let session_id = SessionId::from_hex(&id)?;

    state.registry.close(&session_id, &cap.hash()).await?;

    tracing::info!(session_ref = &id[..8], "session closed");
    Ok(StatusCode::NO_CONTENT)
}

/// Publish one candidate. Returns the canonical stored record — for a
/// duplicate `(kind, transport, addr)` that is the existing record with
/// its original `sequence` (design §3.3 no-op rule), hence 200 not 201.
async fn publish_candidate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    AppJson(body): AppJson<PublishBody>,
) -> Result<impl IntoResponse, ApiError> {
    let cap = Capability::from_hex(bearer_token(&headers)?).map_err(|_| Error::Unauthorized)?;
    let session_id = SessionId::from_hex(&id)?;

    // An ipv6_global candidate must actually carry an IPv6 address.
    if matches!(body.kind, KindBody::Ipv6Global) && !body.addr.is_ipv6() {
        return Err(
            Error::InvalidRequest("ipv6_global candidate requires an IPv6 address".into()).into(),
        );
    }

    let stored = state
        .registry
        .publish_candidate(
            &session_id,
            &cap.hash(),
            CandidatePublish {
                kind: body.kind.into(),
                transport: body.transport.into(),
                addr: body.addr,
                priority: body.priority,
            },
        )
        .await?;

    tracing::debug!(
        session_ref = &id[..8],
        sequence = stored.sequence,
        "candidate published"
    );
    Ok(Json(CandidateJson::from(stored)))
}

/// Short-poll for the other peer's candidates. Returns immediately;
/// an empty `candidates` array is the normal "nothing new" answer.
async fn poll_candidates(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<PollQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let cap = Capability::from_hex(bearer_token(&headers)?).map_err(|_| Error::Unauthorized)?;
    let session_id = SessionId::from_hex(&id)?;

    let result = state
        .registry
        .poll_candidates(&session_id, &cap.hash(), query.since)
        .await?;

    Ok(Json(PollResponse {
        peer_metadata: result.peer_metadata.map(PeerMetadataJson::from),
        candidates: result
            .candidates
            .into_iter()
            .map(CandidateJson::from)
            .collect(),
    }))
}

/// Admin-token-gated stats (design §4.8). With no token configured the
/// route answers plain 404 — indistinguishable from a nonexistent route.
async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = &state.admin_token_hash else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authorized = bearer_token(&headers)
        .map(|t| blake3::hash(t.as_bytes()) == *expected) // blake3::Hash eq is constant-time
        .unwrap_or(false);
    if !authorized {
        return ApiError(Error::Unauthorized).into_response();
    }

    let registry = state.registry.stats().await;
    let by_status: HashMap<String, u64> = state
        .request_counters
        .by_status
        .lock()
        .expect("status-counter mutex poisoned")
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();

    Json(serde_json::json!({
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "sessions": {
            "active": registry.sessions_active,
            "created_total": registry.created_total,
            "expired_total": registry.expired_total,
            "closed_total": registry.closed_total,
            "rejected_capacity_total": registry.rejected_capacity_total,
            "rejected_authz_total": registry.rejected_authz_total,
        },
        "candidates": {
            "published_total": registry.candidates_published_total,
            "active": registry.candidates_active,
        },
        "probes": {
            "received_total": state.probe_counters.received_total.load(Ordering::Relaxed),
            "invalid_total": state.probe_counters.invalid_total.load(Ordering::Relaxed),
            "published_total": state.probe_counters.published_total.load(Ordering::Relaxed),
        },
        "requests": {
            "total": state.request_counters.total.load(Ordering::Relaxed),
            "by_status": by_status,
        },
    }))
    .into_response()
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Mint the probe-token / probe-endpoints response fields, or `(None,
/// None)` when the probe service is disabled (clients treat absence as
/// "feature off").
fn probe_fields(
    state: &AppState,
    session_id: &SessionId,
    role: ProbeRole,
    expires_at: SystemTime,
) -> (Option<String>, Option<Vec<String>>) {
    match &state.probe {
        None => (None, None),
        Some(probe) => {
            let token = probe.key.mint(session_id, role, expires_at);
            let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
            (Some(hex), Some(probe.advertise.clone()))
        }
    }
}

/// Missing or malformed `Authorization` header is `401 unauthorized`
/// without inspecting the session id (design §3.4 — prevents probing for
/// live ids).
fn bearer_token(headers: &HeaderMap) -> Result<&str, Error> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)
}

fn check_version(meta: &PeerMetadataBody) -> Result<(), Error> {
    if meta.protocol_versions.contains(&PROTOCOL_VERSION) {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion)
    }
}

/// Observed address per design §5.2: `X-Real-IP`, else leftmost
/// `X-Forwarded-For`, else none. The direct TCP source is intentionally
/// not consulted — behind nginx it is always 127.0.0.1 (no information)
/// and the field is advisory metadata only. nginx does not forward the
/// client's source port, so port 0 marks it unknown.
fn observed_http_addr(headers: &HeaderMap) -> Option<SocketAddr> {
    let ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        })?;
    Some(SocketAddr::new(ip, 0))
}

fn peer_metadata(headers: &HeaderMap, body: PeerMetadataBody) -> PeerMetadata {
    let now = SystemTime::now();
    PeerMetadata {
        observed_http_addr: observed_http_addr(headers),
        protocol_versions: body.protocol_versions,
        strategies: body.strategies,
        first_seen: now,
        last_seen: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use envoix_rendezvous::RegistryConfig;
    use serde_json::{Value, json};

    const SESSION_ID: &str = "11111111111111111111111111111111";
    const RECEIVER_CAP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SENDER_CAP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sender_cap_hash() -> String {
        // BLAKE3 of the 16 bytes that SENDER_CAP encodes.
        blake3::hash(&[0xbb_u8; 16]).to_hex().to_string()
    }

    const ADMIN_TOKEN: &str = "test-admin-token";

    fn test_server() -> (TestServer, AppState) {
        test_server_with(RegistryConfig::default(), Some(ADMIN_TOKEN.into()))
    }

    fn test_server_with(
        config: RegistryConfig,
        admin_token: Option<String>,
    ) -> (TestServer, AppState) {
        let state = AppState::new(SessionRegistry::new(config), admin_token, None);
        let server = TestServer::new(router(state.clone())).unwrap();
        (server, state)
    }

    /// Probe-enabled server plus a live UDP probe socket on loopback.
    async fn test_server_with_probe() -> (TestServer, AppState, std::net::SocketAddr) {
        let state = AppState::new(
            SessionRegistry::new(RegistryConfig::default()),
            Some(ADMIN_TOKEN.into()),
            Some(vec!["198.51.100.1:9101".into(), "198.51.100.1:9102".into()]),
        );
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = socket.local_addr().unwrap();
        state.spawn_probe_tasks(vec![socket]);
        let server = TestServer::new(router(state.clone())).unwrap();
        (server, state, probe_addr)
    }

    fn register_body() -> Value {
        json!({
            "session_id": SESSION_ID,
            "sender_cap_hash": sender_cap_hash(),
            "peer_metadata": { "protocol_versions": [1] },
        })
    }

    fn join_body() -> Value {
        json!({ "peer_metadata": { "protocol_versions": [1] } })
    }

    async fn do_register(server: &TestServer) {
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        res.assert_status(StatusCode::CREATED);
    }

    #[tokio::test]
    async fn health_ok() {
        let (server, _) = test_server();
        let res = server.get("/api/v1/health").await;
        res.assert_status_ok();
        res.assert_text("ok");
    }

    #[tokio::test]
    async fn register_created_with_expiry() {
        let (server, _) = test_server();
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: Value = res.json();
        assert_eq!(body["session_id"], SESSION_ID);
        assert!(body["expires_at"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn register_missing_auth_is_401() {
        let (server, _) = test_server();
        let res = server.post("/api/v1/sessions").json(&register_body()).await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: Value = res.json();
        assert_eq!(body["code"], "unauthorized");
    }

    #[tokio::test]
    async fn register_session_id_equal_to_cap_is_400() {
        let (server, _) = test_server();
        let mut body = register_body();
        body["session_id"] = json!(RECEIVER_CAP);
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&body)
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: Value = res.json();
        assert_eq!(body["code"], "invalid_request");
    }

    #[tokio::test]
    async fn register_unsupported_version_is_422() {
        let (server, _) = test_server();
        let mut body = register_body();
        body["peer_metadata"]["protocol_versions"] = json!([2]);
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&body)
            .await;
        res.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value = res.json();
        assert_eq!(body["code"], "unsupported_version");
    }

    #[tokio::test]
    async fn register_duplicate_is_409() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        res.assert_status(StatusCode::CONFLICT);
        let body: Value = res.json();
        assert_eq!(body["code"], "conflict");
    }

    #[tokio::test]
    async fn join_then_close_round_trip() {
        let (server, _) = test_server();
        do_register(&server).await;

        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer(SENDER_CAP)
            .json(&join_body())
            .await;
        res.assert_status_ok();

        let res = server
            .delete(&format!("/api/v1/sessions/{SESSION_ID}"))
            .authorization_bearer(RECEIVER_CAP)
            .await;
        res.assert_status(StatusCode::NO_CONTENT);

        // Post-close join → 409 session_closed.
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer(SENDER_CAP)
            .json(&join_body())
            .await;
        res.assert_status(StatusCode::CONFLICT);
        let body: Value = res.json();
        assert_eq!(body["code"], "session_closed");
    }

    #[tokio::test]
    async fn join_wrong_cap_is_401() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer("cccccccccccccccccccccccccccccccc")
            .json(&join_body())
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn join_unknown_session_is_404() {
        let (server, _) = test_server();
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer(SENDER_CAP)
            .json(&join_body())
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
        let body: Value = res.json();
        assert_eq!(body["code"], "session_not_found");
    }

    #[tokio::test]
    async fn close_with_sender_cap_is_401() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .delete(&format!("/api/v1/sessions/{SESSION_ID}"))
            .authorization_bearer(SENDER_CAP)
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let (server, _) = test_server();
        let mut body = register_body();
        body["peer_metadata"]["strategies"] = json!(["x".repeat(70 * 1024)]);
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&body)
            .await;
        res.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
        let body: Value = res.json();
        assert_eq!(body["code"], "payload_too_large");
    }

    #[tokio::test]
    async fn requests_during_shutdown_are_503() {
        let (server, state) = test_server();
        state.begin_shutdown();
        let res = server.get("/api/v1/health").await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = res.json();
        assert_eq!(body["code"], "service_shutting_down");
    }

    fn candidate_body(addr: &str) -> Value {
        json!({ "kind": "host", "transport": "quic", "addr": addr, "priority": 100 })
    }

    #[tokio::test]
    async fn candidate_exchange_both_directions() {
        let (server, _) = test_server();
        do_register(&server).await;
        server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer(SENDER_CAP)
            .json(&join_body())
            .await
            .assert_status_ok();

        // Receiver publishes; sender publishes.
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&candidate_body("10.0.0.1:9000"))
            .await;
        res.assert_status_ok();
        let recv_pub: Value = res.json();
        assert_eq!(recv_pub["kind"], "host");
        assert!(recv_pub["sequence"].as_u64().unwrap() >= 1);

        server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(SENDER_CAP)
            .json(&candidate_body("10.0.0.2:9000"))
            .await
            .assert_status_ok();

        // Each side polls and sees only the other's candidate.
        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(SENDER_CAP)
            .await;
        res.assert_status_ok();
        let seen_by_sender: Value = res.json();
        assert_eq!(seen_by_sender["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(seen_by_sender["candidates"][0]["addr"], "10.0.0.1:9000");
        assert!(seen_by_sender["peer_metadata"].is_object());

        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .await;
        let seen_by_recv: Value = res.json();
        assert_eq!(seen_by_recv["candidates"][0]["addr"], "10.0.0.2:9000");
    }

    #[tokio::test]
    async fn poll_since_filters_over_http() {
        let (server, _) = test_server();
        do_register(&server).await;

        for addr in ["10.0.0.1:9000", "10.0.0.2:9000"] {
            server
                .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
                .authorization_bearer(RECEIVER_CAP)
                .json(&candidate_body(addr))
                .await
                .assert_status_ok();
        }

        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates?since=1"))
            .authorization_bearer(SENDER_CAP)
            .await;
        let body: Value = res.json();
        let candidates = body["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0]["sequence"], 2);
    }

    #[tokio::test]
    async fn empty_poll_returns_empty_array() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .await;
        res.assert_status_ok();
        let body: Value = res.json();
        assert_eq!(body["candidates"], json!([]));
        assert!(body["peer_metadata"].is_null()); // sender not joined yet
    }

    #[tokio::test]
    async fn candidate_cap_enforced_over_http() {
        let config = RegistryConfig {
            max_candidates_per_session: 1,
            ..RegistryConfig::default()
        };
        let (server, _) = test_server_with(config, None);
        do_register(&server).await;

        server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&candidate_body("10.0.0.1:9000"))
            .await
            .assert_status_ok();
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&candidate_body("10.0.0.2:9000"))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: Value = res.json();
        assert_eq!(body["code"], "invalid_request");
    }

    #[tokio::test]
    async fn unknown_candidate_kind_is_400() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&json!({ "kind": "relay", "transport": "quic", "addr": "10.0.0.1:9000" }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ipv6_global_with_v4_addr_is_400() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&json!({ "kind": "ipv6_global", "transport": "quic", "addr": "10.0.0.1:9000" }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_expiry_with_sweep_over_http() {
        let (server, state) = test_server();
        let mut body = register_body();
        body["ttl_seconds"] = json!(1);
        server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&body)
            .await
            .assert_status(StatusCode::CREATED);

        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        state.registry.sweep_expired().await;

        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
        let body: Value = res.json();
        assert_eq!(body["code"], "session_expired");

        // The sweep recorded the expiry in stats.
        let res = server
            .get("/api/v1/stats")
            .authorization_bearer(ADMIN_TOKEN)
            .await;
        let stats: Value = res.json();
        assert_eq!(stats["sessions"]["expired_total"], 1);
    }

    #[tokio::test]
    async fn stats_disabled_without_admin_token() {
        let (server, _) = test_server_with(RegistryConfig::default(), None);
        let res = server.get("/api/v1/stats").await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn stats_wrong_token_is_401() {
        let (server, _) = test_server();
        let res = server
            .get("/api/v1/stats")
            .authorization_bearer("wrong-token")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stats_counters_increment() {
        let (server, _) = test_server();
        do_register(&server).await;
        server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&candidate_body("10.0.0.1:9000"))
            .await
            .assert_status_ok();

        let res = server
            .get("/api/v1/stats")
            .authorization_bearer(ADMIN_TOKEN)
            .await;
        res.assert_status_ok();
        let stats: Value = res.json();
        assert_eq!(stats["sessions"]["active"], 1);
        assert_eq!(stats["sessions"]["created_total"], 1);
        assert_eq!(stats["candidates"]["published_total"], 1);
        assert_eq!(stats["candidates"]["active"], 1);
        // The register + publish requests above were counted.
        assert!(stats["requests"]["total"].as_u64().unwrap() >= 2);
        assert!(stats["requests"]["by_status"]["200"].as_u64().unwrap() >= 1);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn probe_fields_present_only_when_enabled() {
        let (server, _, _) = test_server_with_probe().await;
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: Value = res.json();
        assert_eq!(body["probe_token"].as_str().unwrap().len(), 114); // 57 bytes hex
        assert_eq!(body["probe_endpoints"].as_array().unwrap().len(), 2);

        // Disabled server: fields absent entirely (not null).
        let (server, _) = test_server();
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        let body: Value = res.json();
        assert!(body.get("probe_token").is_none());
        assert!(body.get("probe_endpoints").is_none());
    }

    #[tokio::test]
    async fn join_response_carries_expiry_and_sender_token() {
        let (server, _, _) = test_server_with_probe().await;
        do_register(&server).await;
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/join"))
            .authorization_bearer(SENDER_CAP)
            .json(&join_body())
            .await;
        res.assert_status_ok();
        let body: Value = res.json();
        assert!(body["expires_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(body["probe_token"].as_str().unwrap().len(), 114);
    }

    /// The full reflexive loop: HTTPS register → UDP probe → XOR'd reply
    /// with the observed address → candidate auto-published → peer sees it.
    #[tokio::test]
    async fn udp_probe_end_to_end() {
        use envoix_rendezvous::{PROBE_TOKEN_LEN, ProbeReply, ProbeRequest};

        let (server, _, probe_addr) = test_server_with_probe().await;
        let res = server
            .post("/api/v1/sessions")
            .authorization_bearer(RECEIVER_CAP)
            .json(&register_body())
            .await;
        let body: Value = res.json();
        let token_bytes = hex_to_bytes(body["probe_token"].as_str().unwrap());

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let request = ProbeRequest {
            txid: [9, 8, 7, 6, 5, 4, 3, 2],
            token: token_bytes.try_into().unwrap(),
        };
        client.send_to(&request.encode(), probe_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("probe reply within 2s")
        .unwrap();

        let reply = ProbeReply::decode(&buf[..len]).expect("decodable reply");
        assert_eq!(reply.txid, request.txid);
        assert_eq!(reply.observed, client_addr); // loopback: no NAT in between
        assert_eq!(PROBE_TOKEN_LEN, 57);

        // The auto-published candidate is visible to the other peer.
        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(SENDER_CAP)
            .await;
        let body: Value = res.json();
        let cands = body["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0]["kind"], "server_reflexive_udp");
        assert_eq!(cands[0]["addr"], client_addr.to_string());
        assert_eq!(cands[0]["priority"], 50);

        // Retransmit: same mapping, dedup keeps one candidate.
        client.send_to(&request.encode(), probe_addr).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("retransmit also answered")
        .unwrap();
        let res = server
            .get(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(SENDER_CAP)
            .await;
        let body: Value = res.json();
        assert_eq!(body["candidates"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_probes_get_silence() {
        let (server, _, probe_addr) = test_server_with_probe().await;
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Garbage of the right length, wrong magic/token.
        client.send_to(&[0u8; 70], probe_addr).await.unwrap();
        // Wrong length entirely.
        client.send_to(&[0x3f; 10], probe_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(got.is_err(), "invalid probe must get no reply");

        let res = server
            .get("/api/v1/stats")
            .authorization_bearer(ADMIN_TOKEN)
            .await;
        let stats: Value = res.json();
        assert_eq!(stats["probes"]["received_total"], 2);
        assert_eq!(stats["probes"]["invalid_total"], 2);
        assert_eq!(stats["probes"]["published_total"], 0);
    }

    #[tokio::test]
    async fn reflexive_kind_accepted_over_http() {
        let (server, _) = test_server();
        do_register(&server).await;
        let res = server
            .post(&format!("/api/v1/sessions/{SESSION_ID}/candidates"))
            .authorization_bearer(RECEIVER_CAP)
            .json(&json!({
                "kind": "server_reflexive_udp",
                "transport": "quic",
                "addr": "198.51.100.7:40000",
            }))
            .await;
        res.assert_status_ok();
        let body: Value = res.json();
        assert_eq!(body["kind"], "server_reflexive_udp");
    }

    /// End-to-end over real TCP loopback per design §7 PR 2.
    #[tokio::test]
    async fn e2e_register_join_close_over_tcp() {
        let state = AppState::new(SessionRegistry::new(RegistryConfig::default()), None, None);
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base = format!("http://{addr}/api/v1");
        let client = reqwest::Client::new();

        let res = client
            .post(format!("{base}/sessions"))
            .bearer_auth(RECEIVER_CAP)
            .json(&register_body())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);

        let res = client
            .post(format!("{base}/sessions/{SESSION_ID}/join"))
            .bearer_auth(SENDER_CAP)
            .json(&join_body())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);

        let res = client
            .delete(format!("{base}/sessions/{SESSION_ID}"))
            .bearer_auth(RECEIVER_CAP)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 204);
    }
}
