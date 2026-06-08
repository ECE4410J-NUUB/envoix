# Rendezvous Server — Design

Status: draft
Scope: Issue #6 — centralized rendezvous and signaling server
Owner: chkxw
Adjacent docs: `docs/arch.md` (especially §10 final architecture and §11.5
server-side notes), `docs/auth.md` (current SPAKE2 peer authentication —
unaffected by this server), Issue #6 itself.

This document fixes the architecture, wire model, and runtime semantics of
the envoix rendezvous server **before** code is written. Reviewers should
push back on this document. Implementation PRs that follow are expected to
match these decisions.

This is the merged design: a parallel draft was reviewed and the agreed
positions are absorbed here. Differences are noted inline only where the
reasoning matters for future revisits.

---

## 1. Scope

### 1.1 What this server does

A short-lived session registry with observers. Two clients arrive with a
shared session identifier and a pair of role-separated bearer capabilities;
each publishes its own network candidates; each observes the other's
candidates; they leave when the actual file transfer (which is peer-to-peer,
not via this server) is connected or has failed.

The functional surface is:

1. Accept session registration from a receiver.
2. Accept session join from a sender.
3. Accept candidate publication from either side.
4. Serve candidate queries from either side.
5. Accept explicit session close from the receiver.
6. Expire idle sessions on a TTL.
7. Reject every above operation when the presented capability does not match
   the registered hash.

That is the entire functional surface.

### 1.2 What this server does NOT do

- **It never carries file bytes.** Relay is Issue #12's concern; this
  server does not allocate relay sessions. A `relay` candidate `kind` is
  reserved for the future relay API but is not part of the v1 candidate
  schema (see §3.3).
- **It runs no cryptographic key exchange.** End-to-end peer authentication
  happens after the QUIC connection is established (currently SPAKE2,
  see `docs/auth.md`). A server capability check is not a substitute for
  peer authentication.
- **It does not validate file metadata.** Filenames, hashes, and sizes are
  meaningful only between sender and receiver. The server never sees them.
- **It does not implement reflexive UDP discovery (STUN-equivalent).**
  The HTTP request source address is recorded as advisory metadata only,
  *not* as a UDP/QUIC candidate. NAT bindings are per-5-tuple — an HTTP
  TCP source address says nothing useful about the UDP binding a later
  QUIC socket will see. Real reflexive discovery requires a UDP probe path
  and is deferred to Issue #10.

### 1.3 Non-goals for v1

The following are intentionally out of scope. Each has a clear future path
but should not be designed into v1:

- Persistent state across server restarts. Sessions are minutes-long and an
  in-memory store is sufficient.
- Distributed / horizontally-scaled deployment. Single instance.
- WebSocket or SSE push channels. Polling at ~200–500 ms is enough for the
  bursty cadence of candidate exchange.
- Sophisticated rate limiting. The reference deployment uses nginx in front;
  nginx handles per-IP throttling.
- Prometheus exposition. A JSON `/api/v1/stats` endpoint is enough;
  promote to Prometheus only when a scraper actually exists.
- Per-tenant or per-organisation quotas; multi-tenancy concepts.
- TLS termination inside the binary. The reference deployment terminates
  TLS at nginx and the binary binds loopback.

---

## 2. Architecture

### 2.1 Crate and binary layout

```
crates/envoix-rendezvous/
  src/
    lib.rs            public re-exports
    capabilities.rs   capability newtype, BLAKE3 hashing, redaction, role split
    state.rs          session/candidate types, in-memory registry, TTL logic
    error.rs          typed errors

apps/envoix-server/
  src/
    main.rs           clap CLI, tracing init, axum wiring, graceful shutdown
    api.rs            HTTP routes, error mapping, request/response shaping
```

The split is **two crates**: a library and a binary.

- `crates/envoix-rendezvous` holds every load-bearing decision: session
  lifecycle, capability handling, the in-memory store, TTL semantics, the
  error taxonomy. It is pure logic with no HTTP and no axum dependency.
  Async is used only where the data structures themselves require it.
- `apps/envoix-server` holds the transport layer: axum routes, request and
  response JSON shapes, HTTP status code mapping, the CLI surface, tracing
  initialisation, graceful shutdown wiring. It is intentionally thin and
  delegates every meaningful behaviour to the library crate.

### 2.2 Why a library crate, not internal modules

`CLAUDE.md` §2 explicitly warns against premature abstraction. A library
crate is justified here on three concrete grounds:

1. **Unit-testability without HTTP.** All v1 acceptance criteria from Issue
   #6 (register, join, publish candidates, poll candidates, TTL expiry,
   reject unauthorised join, close session) are exercisable at the
   state-layer level without binding a TCP port, constructing axum requests,
   or running a Tokio runtime beyond what the data structures themselves
   need. The PR introducing the library crate ships unit tests for every
   acceptance criterion. The HTTP PR that follows is then mostly thin
   transport mapping, with HTTP-specific tests that don't have to rehearse
   the same business-logic edges.

2. **Future client reuse.** `envoix-discovery` (existing crate, currently
   containing only `ManualPeerDiscovery`) will gain a
   `RendezvousDiscoveryProvider` that talks to this server. The client and
   the server share request/response types, capability format, and
   candidate types. Putting these in a library crate lets `envoix-discovery`
   import them without depending on axum, the server binary, or any
   server-side state. In a single-binary world the client would have to
   redeclare every type or import from a `bin` crate (which Cargo
   discourages).

3. **Alignment with `docs/arch.md` §10.** The architecture document already
   plans `apps/envoix-server` + `crates/envoix-server-core` as the
   server-side split. `crates/envoix-rendezvous` is the rendezvous-specific
   slice of `envoix-server-core`. If a future relay server (Issue #12)
   shares any types or behaviour, the precedent is set and the relay crate
   can sit alongside.

The cost is one extra `Cargo.toml` and one extra `lib.rs`. The split is
one crate, not a forest. This is the minimum necessary for the testability
and reuse properties above.

### 2.3 Module boundaries

Within `crates/envoix-rendezvous`:

| Module | Aware of | Unaware of |
|---|---|---|
| `capabilities` | byte arrays, BLAKE3, constant-time compare | sessions, time, the registry |
| `state` | sessions, candidates, TTL, the registry | HTTP, axum, hashing internals (consumes `capabilities` opaquely) |
| `error` | error variants | everything else |

Within `apps/envoix-server`:

| Module | Aware of | Unaware of |
|---|---|---|
| `main` | CLI args, tracing setup, axum wiring | session internals |
| `api` | HTTP shapes, status code mapping | how capabilities are hashed, how state is stored |

`api.rs` calls into `envoix-rendezvous` exclusively through `lib.rs`'s
public surface. It does not know whether tokens are BLAKE3-hashed, how the
registry is locked, or how TTL is enforced. This boundary is enforced by
visibility (`pub(crate)` for internals) and reviewed at PR time.

---

## 3. Wire model

### 3.1 Identifiers and capabilities

A session is identified by three values, all 32-character lowercase hex
strings (128 bits if uniformly random):

| Name | Generated by | Carried in | Purpose |
|---|---|---|---|
| `session_id` | client (receiver) | URL path | Public lookup key |
| `receiver_cap` | client (receiver) | `Authorization: Bearer …` | Authority to register, publish receiver candidates, close |
| `sender_cap` | client (receiver) | `Authorization: Bearer …` | Authority to join, publish sender candidates |

The receiver generates all three locally before the first request. It then
transmits `(rendezvous_url, session_id, sender_cap)` to the sender via QR
or other out-of-band channel. The exact QR encoding is the responsibility
of Issue #5 and is not specified here; this server is deployment-agnostic
with respect to its public URL.

**Format validation, not entropy validation.** The server cannot prove
entropy from an opaque string. It enforces:

- Length: exactly 32 characters.
- Charset: `^[0-9a-f]{32}$`.
- Distinctness: `session_id`, `receiver_cap`, `sender_cap` are pairwise
  distinct.

A client that ships weak (e.g., all-zero or sequentially incremented)
identifiers is responsible for its own security. Documentation will
recommend `getrandom`.

Capabilities are hashed with BLAKE3 immediately on intake; the raw byte
sequence is zeroized after hashing and is never written to disk, returned
in any response, or appearing in any log line. Capability comparison
uses constant-time equality (`subtle::ConstantTimeEq` or equivalent) on
the BLAKE3 output.

### 3.2 Session lifecycle

```
            register
              │
              ▼
         ┌─────────┐
         │ Pending │
         └────┬────┘
              │ join         ttl / close
              ▼              ────────────┐
         ┌─────────┐                     ▼
         │ Joined  │ ─── ttl / close ─►  removed
         └─────────┘
```

States:

- **`Pending`** — receiver has registered; no sender has joined yet.
- **`Joined`** — sender has presented `sender_cap` and is now a peer in the
  session.
- *removed* — session has been removed from the registry, by either TTL
  expiry, explicit `DELETE`, or capacity-driven eviction (in practice
  capacity-driven eviction does not happen in v1 because the registration
  endpoint returns `503` once the cap is hit).

There is no explicit "completed" state. Clients close explicitly when their
transfer succeeds, or let the session TTL expire.

Removed sessions are distinguished by *why* they were removed:

- **Never existed**: `404 session_not_found`.
- **Existed but TTL elapsed**: `404 session_expired`. Distinct code so a
  client can tell "we were too slow to pair" from "wrong id". Same HTTP
  status — recovery is the same (re-pair via QR), but the diagnostic
  message is more useful.
- **Existed but explicitly closed**: `409 session_closed`. A peer asking
  about a session whose receiver already issued `DELETE` should not
  retry; that is a terminal state.

The state-layer registry retains a small "tombstone" entry for closed and
expired sessions for one TTL cycle so the API layer can map removed
sessions to the right code. Tombstones never carry candidates or
metadata; they only carry the disposition.

### 3.3 Peer metadata vs. candidates

These are two cleanly separated types. **Conflating them was an early
design mistake; this document codifies the corrected shape.**

#### PeerMetadata — what the server observes or the peer claims

```json
{
  "observed_http_addr": "203.0.113.10:54321",
  "protocol_versions": [1],
  "strategies": ["lan", "ipv6", "hole_punch", "relay"],
  "first_seen": "2026-06-08T15:14:09.024Z",
  "last_seen": "2026-06-08T15:14:32.512Z"
}
```

- **`observed_http_addr`** — source IP:port of the most recent HTTP request
  from this peer. **Advisory metadata only.** Not a viable UDP/QUIC
  hole-punch candidate (NAT mappings are per-5-tuple; the HTTP/TCP binding
  shares nothing useful with the eventual UDP binding). Useful cases:
  detecting same-NAT placement of both peers (favouring LAN discovery) and
  diagnostic correlation between rendezvous registration and downstream
  transfer outcome.
- **`protocol_versions`** — wire versions this peer can speak.
- **`strategies`** — connection strategies this peer is willing to try.
  Server does not interpret these; it just passes them through.

#### Candidate — a single network endpoint the peer claims to be reachable at

```json
{
  "kind": "ipv6_global",
  "transport": "quic",
  "addr": "[2001:db8::1]:9000",
  "priority": 100,
  "sequence": 7,
  "published_at": "2026-06-08T15:14:12.000Z"
}
```

- **`kind`** — tagged union. Initial variants in v1:
  - `"host"` — LAN-local address.
  - `"ipv6_global"` — publicly routable IPv6.

  Future variants — `"server_reflexive_udp"` (Issue #10),
  `"server_reflexive_quic"`, `"relay"` (Issue #12) — are added without
  breaking old clients. `relay` is intentionally *not* in v1: the
  rendezvous server has no way to validate that a claimed relay endpoint
  is real, and accepting unvalidated `relay` candidates would create a
  redirection surface. The candidate `kind` enum on the server is
  non-exhaustive in the JSON schema sense: a future peer can publish a
  kind today's server has never heard of, and the server forwards it
  verbatim; only known kinds are subject to schema-level validation.
- **`transport`** — `"quic"` for now. Adding `"tcp"` is non-breaking.
- **`addr`** — `SocketAddr` string. IPv4: `"host:port"`; IPv6:
  `"[host]:port"`.
- **`priority`** — ICE-style hint; higher first. Optional; defaults to 0.
- **`sequence`** — server-assigned monotonic counter, scoped to the
  session. Clients use it with the `?since=N` query parameter to fetch
  only candidates they haven't seen.
- **`published_at`** — server timestamp on receipt.

Each candidate is one address. A peer with three usable addresses
publishes three Candidate records.

**Duplicate publish is a no-op.** If a peer publishes a `(kind, transport,
addr)` triple already in its candidate list for this session, the server
does not assign a new `sequence`, does not bump `published_at`, and
returns the existing record. This keeps a poll-publish loop from
producing spurious "new candidates" the other peer has already seen.
Identity is the full tuple — `priority` changes alone do not count as a
new candidate; a peer wishing to update priority must close the session
or wait for a future API revision.

**Polling with no new candidates returns immediately with an empty
array.** `GET /api/v1/sessions/<id>/candidates?since=N` is short-poll, not
long-poll. If no candidates with `sequence > N` exist, the response is
`200` with `{"candidates": []}` and the client decides when to retry.
Long-polling and SSE are out of scope for v1 (see §6).

### 3.4 Error envelope

All non-2xx responses carry a JSON body:

```json
{
  "code": "session_not_found",
  "message": "no session with id 0123abcd…"
}
```

`code` is a stable, machine-parseable string. `message` is human-readable
and may change between versions.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed payload, missing field, wrong charset, candidate field out of bounds |
| `unauthorized` | 401 | Capability hash did not match, capability absent, or `Authorization` header missing |
| `session_not_found` | 404 | No session with that id was ever registered |
| `session_expired` | 404 | Session existed but its TTL elapsed |
| `conflict` | 409 | Duplicate registration of same session id |
| `session_closed` | 409 | Session existed and was explicitly closed by the receiver |
| `payload_too_large` | 413 | Request body exceeded the body-size limit |
| `unsupported_version` | 422 | Client wire version is incompatible with the server |
| `capacity_exceeded` | 503 | Server is at the session-count cap |
| `service_shutting_down` | 503 | Process received SIGTERM and is draining |
| `internal` | 500 | Unexpected server error; details in logs |

`session_expired` and `session_closed` are kept distinct from
`session_not_found` because they imply different client recoveries.
`session_not_found` means "you have the wrong id" — re-pair via QR is
the only path. `session_expired` means "you had the right id but the
window closed" — retry from QR is again required but the diagnostic is
different. `session_closed` is terminal: the receiver explicitly ended
the session, so the sender should stop polling and surface a
"transfer ended" UI rather than re-pair. All three are distinguishable
in logs and metrics regardless of HTTP-status collisions.

The `Authorization` header is mandatory on every endpoint except
`POST /api/v1/sessions` and `GET /api/v1/health`. Its absence is reported
as `401 unauthorized` (with `message: "missing Authorization header"`)
without inspecting the session id — this prevents probing for live
session ids by sending unauthenticated requests.

---

## 4. Runtime behaviour

### 4.1 Receiver flow

1. Receiver client generates `(session_id, receiver_cap, sender_cap)`
   locally (`getrandom`).
2. Receiver client binds its local QUIC listener and notes the address.
3. Receiver client `POST /api/v1/sessions` with
   `Authorization: Bearer <receiver_cap>` and a body containing the
   `session_id`, BLAKE3 hash of `sender_cap`, peer metadata, and a
   `ttl_seconds` request. Server stores the session in `Pending`, hashes
   the `receiver_cap` from the header, and stores both hashes.
4. Receiver client encodes `(rendezvous_url, session_id, sender_cap)`
   into a QR (or other channel) and presents it to the sender.
5. Receiver client `POST /api/v1/sessions/<id>/candidates` for each candidate.
6. Receiver client polls `GET /api/v1/sessions/<id>/candidates?since=N` for
   the sender's candidates. The server returns immediately; client polls
   every 200–500 ms.
7. Once useful candidates appear, receiver attempts QUIC connection
   out-of-band.
8. After connection succeeds or all candidates are exhausted, receiver
   client `DELETE /api/v1/sessions/<id>` to free server state.

### 4.2 Sender flow

1. Sender client decodes the QR or other channel.
2. Sender client `POST /api/v1/sessions/<id>/join` with
   `Authorization: Bearer <sender_cap>` and a body containing peer metadata.
   Server validates the cap hash, marks the session `Joined`, stores
   the sender's metadata.
3. Sender client `POST /api/v1/sessions/<id>/candidates`.
4. Sender client polls `GET /api/v1/sessions/<id>/candidates?since=N` for the
   receiver's candidates.
5. Sender attempts QUIC connection out-of-band.
6. After connection or exhaustion, sender client does not need to call
   `DELETE` — the receiver owns session lifecycle. If the sender emits
   `DELETE`, the server returns `401 unauthorized`.

### 4.3 Authorisation rules

- `POST /api/v1/sessions` requires only that the request body is well-formed.
  Registration is open; the supplied `receiver_cap` defines authority
  going forward.
- `POST /api/v1/sessions/<id>/join` requires the **sender** capability via
  `Authorization: Bearer …`.
- `POST /api/v1/sessions/<id>/candidates` and
  `GET /api/v1/sessions/<id>/candidates` accept **either** capability. The
  role attached to the request (and to any candidates published) is
  determined by which capability was presented.
- `DELETE /api/v1/sessions/<id>` requires the **receiver** capability. Senders
  cannot close a session.

Every capability check happens before any state inspection.

### 4.4 TTL and cleanup

- **Default session TTL**: 300 seconds (5 minutes) from creation,
  refreshed on every successful authenticated request.
- **Client-requested TTL**: clients may set `ttl_seconds` in the
  registration body. Capped server-side at 1800 seconds (30 minutes) for
  v1. Lower client requests are honoured.
- **Background sweep**: a single `tokio::spawn` task wakes every 30
  seconds and removes expired sessions. The task is simple and
  non-panicking by construction (every fallible call is matched, no
  `unwrap`s). If the sweep ever stops, logs show it and the process is
  expected to be restarted by systemd.
- **Opportunistic expiry**: every state-layer read checks
  `expires_at < now` and treats the session as not-found if so. The
  mutator that observes this removes the entry inline. This guarantees
  correctness between sweep ticks; the sweep is a backstop for slow paths
  that never read again.

There is no internal "watchdog" task that restarts the sweep on panic.
Recovery from sweep failure is the supervisor's responsibility, not the
server's.

### 4.5 Concurrency and time

**Registry concurrency.** The session registry is
`Arc<tokio::sync::RwLock<HashMap<SessionId, Session>>>`. The
`RwLock` choice is deliberate: candidate polls dominate the request mix
and they are read-only against the outer map (they take a shared lock,
look up the session, then take the per-session inner lock to read
candidates). Writes — register, join, publish, close — take the
exclusive lock briefly. v1 expects hundreds of sessions and dozens of
concurrent pollers, well inside what a single `RwLock` handles without
contention. Inner per-session state (candidate vector, metadata) is held
inside the session record under a `tokio::sync::Mutex`; this is enough
granularity to keep one session's publish from blocking another's poll
once the outer read lock is acquired.

A `parking_lot` or `std::sync` lock is *not* used: handlers can be
cancelled while awaiting downstream work, and an async lock makes that
cancellation safe.

**Time discipline.** Two clocks are used and they do not mix.

- `expires_at` and `published_at` on the wire are RFC 3339 wall-clock
  timestamps (`SystemTime`). They are formatted on the way out and
  parsed on the way in; they exist for human inspection and for
  comparison against client clocks.
- TTL math inside the state layer uses `tokio::time::Instant`
  (monotonic). The session record stores both: a wall-clock `expires_at`
  recorded at creation for serialisation, and a monotonic `expires_at`
  used by the sweep and opportunistic expiry. A wall-clock jump (NTP
  step, daylight-saving change on a misconfigured host) does not move
  TTLs around.

The HTTP handler converts between the two only at the boundary; the
state layer sees `Instant` exclusively.

### 4.6 Robustness budget

Failures the v1 server must handle without crashing or unbounded
degradation:

| Failure | Defence in v1 |
|---|---|
| Body exceeds **64 KiB** | `axum::extract::DefaultBodyLimit::max(64 * 1024)`. Returns 413 `payload_too_large`. |
| Malformed JSON | serde returns a deserialisation error; mapped to 400 `invalid_request`. |
| Wrong capability | Constant-time compare on BLAKE3 hashes; 401 `unauthorized`. |
| Session-count cap (**10 000** by default) exceeded | New `POST /api/v1/sessions` returns 503 `capacity_exceeded`. Existing sessions continue. |
| Per-session candidate cap (**32** by default) exceeded | 400 `invalid_request` naming the cap. Already-published candidates kept. |
| Slow client (slow-loris) | Defended by nginx, which sits in front. The Rust binary expects local well-behaved connections. |
| Per-IP storm | Defended by nginx's `limit_req_zone`. Not duplicated in the Rust binary. |
| Process crash | systemd `Restart=on-failure`. In-memory state is lost; clients observe `404 session_not_found` and re-pair. This failure mode is documented and accepted. |
| SIGTERM | `axum::serve(…).with_graceful_shutdown(…)` sets a `shutting_down` atomic flag. New requests arriving after the flag is set get a synchronous `503 service_shutting_down` response so clients can fail fast and retry against the restarted instance; in-flight requests have up to 5 seconds to finish. Restart-time clients see `session_not_found` once the new process is up. |
| Handler panic | Treated as a bug. The fix is to make the handler not panic. Hyper drops the connection; logs record the panic. No deliberate "panic → 500" path. |
| Storage growth from abandoned sessions | Bounded by session-count cap and TTL. |
| TTL sweep failure | Opportunistic expiry on read catches anything the sweep missed. Sweep failure is visible in logs but not catastrophic. |

Defences **explicitly NOT** built into v1:

- TLS termination (nginx).
- Per-IP rate limit (nginx).
- Tokio task / RSS / CPU metrics. `/api/v1/stats` counters are sufficient.

### 4.7 Logging

#### Levels and defaults

| Level | Default? | Shows |
|---|---|---|
| `error` | always | Service-failing errors |
| `warn` | always | Auth failures, capacity-exhausted, anything actor-driven worth alerting on |
| `info` | **yes (default)** | Service lifecycle (started, listening, shutting down); session lifecycle (created, joined, expired, closed) |
| `debug` | opt-in | One line per HTTP request: method, path, status, duration, source IP prefix, session ref |
| `trace` | opt-in, dev only | Detailed control-flow within handlers. **Never request/response bodies** — even redacted-token bodies are a leak surface (source IPs, peer correlations). |

Default filter: `envoix=info,warn`. CLI `--debug` upgrades the envoix
targets to `debug`. `RUST_LOG` overrides everything (standard tracing
env-filter syntax).

#### Required fields on every log line

- Always present (via tracing): `timestamp`, `level`, `target`.
- For session-scoped operations: `session_ref = <first 8 hex chars of session_id>`.
- For HTTP request lines: `method`, `path`, `status`, `duration_ms`,
  `source_prefix` (the source IP truncated to /24 for IPv4 or /48 for
  IPv6; full source IP appears only at trace level).

#### Never logged at any level

- Raw capabilities. Only `cap_hash_ref=<8 hex chars of BLAKE3>` if any
  reference is needed, and only at `debug` or below.
- Full session ids. Truncated to 8 chars (`session_ref`) at every level.
- Request bodies. Response bodies.

The capability newtype overrides `Debug` and `Display` to emit
`<redacted>`. This is enforced at the type level so accidental
`tracing::debug!(?cap, ...)` cannot leak.

### 4.8 Observability endpoints

Two endpoints exist for operators:

- **`GET /api/v1/health`** — unauthenticated, always 200 with body `"ok"`.
  Liveness check for nginx, systemd, and any uptime monitor.
- **`GET /api/v1/stats`** — gated by an admin capability configured via
  `--admin-token` or `ENVOIX_ADMIN_TOKEN`. Returns JSON:

```json
{
  "uptime_seconds": 12345,
  "sessions": {
    "active": 8,
    "created_total": 142,
    "expired_total": 117,
    "closed_total": 17,
    "rejected_capacity_total": 0,
    "rejected_authz_total": 3
  },
  "candidates": {
    "published_total": 318,
    "active": 24
  },
  "requests": {
    "total": 1487,
    "by_status": { "200": 1431, "401": 3, "404": 14, "413": 0, "503": 0 }
  }
}
```

If `--admin-token` is not set, `/api/v1/stats` responds 404 (the route is
effectively disabled). Counter names are chosen Prometheus-compatible so
a future `/metrics` endpoint can be added by translating, not renaming.

No `/admin/sessions` listing in v1. Listing active session ids is not
required by any acceptance criterion and creates an information-disclosure
surface.

### 4.9 Configuration

CLI args (clap-derived) with optional environment-variable fallbacks:

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--listen` | `ENVOIX_LISTEN` | `127.0.0.1:9100` | Override for dev / container / non-nginx deployments. |
| `--admin-token` | `ENVOIX_ADMIN_TOKEN` | unset (`/api/v1/stats` disabled) | Hex string. |
| `--max-sessions` | `ENVOIX_MAX_SESSIONS` | `10000` | Hard cap. |
| `--max-candidates-per-session` | `ENVOIX_MAX_CANDIDATES` | `32` | Hard cap. |
| `--default-ttl-seconds` | `ENVOIX_DEFAULT_TTL` | `300` | Used when client doesn't supply `ttl_seconds`. |
| `--max-ttl-seconds` | `ENVOIX_MAX_TTL` | `1800` | Cap on client-requested TTL. |
| `--debug` | (none) | off | Upgrades envoix targets to `debug` if `RUST_LOG` is unset. |
| `RUST_LOG` | `RUST_LOG` | `envoix=info,warn` | Standard tracing env-filter syntax. |

No configuration file in v1. Adding one (e.g., `envoix-server.toml`) is
straightforward when needed.

---

## 5. Deployment

### 5.1 Reference deployment

The reference deployment is `home.chkxwlyh.com` behind nginx. The binary
binds `127.0.0.1:9100` and is unreachable from the public internet except
via the reverse proxy.

nginx fragment (illustrative; final form in deployment notes):

```nginx
# inside the server { … } block for home.chkxwlyh.com (TLS terminated here)

limit_req_zone $binary_remote_addr zone=envoix:10m rate=20r/s;

location /envoix/ {
    limit_req zone=envoix burst=20 nodelay;

    client_body_timeout 5s;
    client_header_timeout 5s;
    send_timeout 30s;

    # forward to the loopback binary, stripping the /envoix prefix
    proxy_pass http://127.0.0.1:9100/;
    proxy_http_version 1.1;

    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
}
```

The rendezvous URL the client sees is therefore
`https://home.chkxwlyh.com/envoix`. Clients append `/api/v1/...` to that
base.

### 5.2 Trusting nginx's forwarded headers

`observed_http_addr` is computed as:

- If `X-Real-IP` is present, use it.
- Else, if `X-Forwarded-For` is present, use the **leftmost** entry.
- Else, fall back to the immediate TCP source address (i.e., 127.0.0.1
  when running behind nginx — gives no information, but is honest).

The server trusts these headers **only because we know nginx sets them and
nothing else is in the path**. If `--listen 0.0.0.0:…` is used (direct
exposure without a proxy), the operator must understand that any client
can forge these headers and `observed_http_addr` becomes untrustworthy. A
`--trust-forwarded-headers` flag could be added in the future to make
this explicit, but for v1 we document the assumption and leave it on.

### 5.3 Process supervision

For sustained running the deployment uses `systemd --user` with
`Restart=on-failure`. The unit file lives with deployment notes (out of
repo for v1). The binary itself does no self-restart logic and no
self-watchdog.

---

## 6. Out of scope, with future paths

These are intentionally deferred. Each has a clear future path and a
corresponding issue or planned issue.

- **Real UDP/QUIC reflexive discovery** for hole-punching — Issue #10.
  Adds `server_reflexive_udp` as a candidate kind without changing this
  server's wire format incompatibly.
- **Relay session allocation** — Issue #12. The relay binary defines its
  own contract; this server only records `kind: "relay"` candidates
  emitted by clients.
- **WebSocket or SSE push for candidate updates.** Polling is enough for
  v1; an SSE endpoint can be added later without breaking the existing
  poll API.
- **Persistent state across restarts.** Sessions are short-lived; restart
  loss is acceptable. SQLite or similar can be added if multi-instance
  deployment is ever introduced.
- **Multi-instance / horizontally-scaled deployment.** Non-trivial
  redesign (shared state, sticky sessions, or pub-sub fan-out).
- **OpenAPI specification.** `docs/rendezvous-api.md` is hand-written in
  PR 3. OpenAPI can follow if a generated client becomes useful.
- **Per-tenant or per-org quotas.** No multi-tenant concept in v1.

---

## 7. Implementation plan

Three PRs, each independently reviewable. Estimates are approximate.

### PR 1 — `crates/envoix-rendezvous` (≈ 400 LOC + tests)

Adds the library crate. No HTTP. Behaviour delivered at the state-layer
level so that PR 2/3 are mostly thin transport mapping.

Contents:

- `capabilities`: `Capability` newtype with redacted `Debug`/`Display`,
  BLAKE3 hashing, constant-time compare; role-separated `ReceiverCap`,
  `SenderCap`.
- `state`: `Session`, `Candidate`, `PeerMetadata`, `SessionRegistry`.
  Register / join / publish-candidate / poll-candidates / close behavior
  with role-based authorisation. TTL on creation, refresh on access,
  opportunistic expiry on read.
- `error`: typed errors for every variant in §3.4.

Unit tests:

- Successful register → join → publish (both sides) → poll → close.
- Unauthorized join (wrong sender cap hash) → `unauthorized`.
- Unauthorised close (sender attempting close) → `unauthorized`.
- Duplicate registration (same session id) → `conflict`.
- TTL expiry: session past `expires_at` returns `session_expired`,
  distinct from `session_not_found` for an id that never existed.
- Explicit close then re-access → `session_closed`, distinct from
  expiry.
- Capacity cap: 10001st registration → `capacity_exceeded`.
- Candidate cap: 33rd candidate on a session → `invalid_request`.
- Duplicate candidate publish (same `kind`/`transport`/`addr`) is a
  no-op: same `sequence`, no new record.
- Format validation: malformed session id / capability → `invalid_request`.
- Distinctness validation: `session_id == receiver_cap` → `invalid_request`.

### PR 2 — `apps/envoix-server` (≈ 500 LOC + tests)

Adds the binary with the non-candidate HTTP surface. Sets the patterns
PR 3 will reuse.

Contents:

- `main`: clap CLI (§4.9), tracing initialisation (§4.7), axum app
  construction, graceful shutdown via
  `axum::serve(…).with_graceful_shutdown(…)` and a `shutting_down`
  atomic flag consulted by every handler.
- `api`: handlers for `POST /api/v1/sessions`,
  `POST /api/v1/sessions/{id}/join`, `DELETE /api/v1/sessions/{id}`,
  `GET /api/v1/health`. Structured JSON error mapping per §3.4.
- Default body limit (64 KiB), default timeouts where applicable.
- `tower-http::trace::TraceLayer` for the per-request log line at `debug`.

Tests:

- `axum_test` for endpoint-level tests (no port binding, fast):
  successful register, join, close; unauthorised variants; 404 on
  unknown session; 413 on over-sized body; 422 on unsupported version;
  401 on missing `Authorization` header (without leaking session
  existence); 503 on requests after `shutting_down` is set.
- One full `reqwest`-against-a-spawned-server test exercising
  register → join → close end-to-end across the actual TCP loopback.

### PR 3 — Candidate exchange and observability (≈ 400 LOC + tests + docs)

Adds the candidate API surface, the background sweep, the stats
endpoint, and the API reference doc.

Contents:

- `POST /api/v1/sessions/{id}/candidates` (publish).
- `GET /api/v1/sessions/{id}/candidates?since=N` (poll; returns immediately).
- Background TTL sweep task, every 30 s.
- `GET /api/v1/stats` (admin-token gated).
- `docs/rendezvous-api.md` with full per-endpoint request/response
  schema and examples.

Tests:

- All acceptance integration tests from Issue #6: registration, join,
  candidate exchange across both peers (each side polls and sees the
  other's published candidates), TTL expiry (with the background sweep
  active), unauthorized join, session close.
- `since=N` correctness (no duplicates, no skipped sequences).
- Empty-poll behaviour: `GET …/candidates?since=N` returns `200`
  with `{"candidates": []}` immediately when nothing newer exists.
- Candidate cap behavior under HTTP.
- Stats counters increment correctly.

After PR 3 lands, Issue #6 is closeable.

---

## 8. Future evolution

Future-compatible additions to `/api/v1` that do **not** break old clients:

- New candidate `kind` variants (e.g., `server_reflexive_udp`, `relay`).
- New `transport` values (e.g., `tcp`).
- New fields in `PeerMetadata` (additive only).
- New fields on `Candidate` (additive only).
- New error codes (added to §3.4).
- New endpoints under `/api/v1/...`.

Changes that would require `/api/v2`:

- Renaming or removing JSON fields.
- Changing existing endpoint URL shapes.
- Changing capability format (length, charset) without supporting both.
- Changing the authorisation scheme (e.g., adding mandatory request
  signing).

The server refuses `/api/v2/*` paths until `/api/v2` actually exists,
with a 404. Clients must not assume `/api/v2` is a fallback for
`/api/v1` and vice versa.

---

## 9. Open decisions for implementation

These have a working position in this document but are not load-bearing
on the wire format or architecture. They are decided in the PR that first
touches the relevant code, not gated on further design review.

- **Exact session-id encoding.** Working position: lowercase hex of 16
  random bytes (`^[0-9a-f]{32}$`). Base64url is functionally equivalent;
  hex was chosen for QR readability and copy-paste resilience.
- **Default session TTL.** Working position: 300 s, client-requestable
  up to 1800 s. 600 s may be kinder for cross-internet pairing flows;
  revisit after first user testing.
- **Polling interval recommendation for clients.** Working position:
  document `200–500 ms` as a non-normative recommendation in
  `docs/rendezvous-api.md`. Not enforced by the server.
- **Exact active-session cap.** Working position: 10 000, configurable
  via `--max-sessions`. The number is a soft guess at "more than a
  course-deployment ever sees" rather than a calculated capacity.
- **Exact candidate priority semantics.** Working position: pass-through
  integer, higher first, no normalisation. ICE-style normalisation may
  be added when there is a connection strategy to drive it.
- **Admin token configuration name.** Working position: `--admin-token`
  CLI and `ENVOIX_ADMIN_TOKEN` env. Naming subject to deployment
  conventions once a unit file exists.
- **HTTP testing crate.** Working position: `axum_test` for in-process,
  one `reqwest`-against-spawned-server smoke test. Switch is local to
  the test module if a better option appears.
- **`X-Forwarded-For` trust policy.** Working position: trust
  unconditionally in v1 because the reference deployment always sits
  behind nginx. Adding `--trust-forwarded-headers <ip-allowlist>` later
  is non-breaking.

Items deliberately *not* open — these have firm positions:

- Capability format (32-hex), hashing (BLAKE3), comparison (constant
  time): §3.1.
- Candidate tagged-union shape with `kind` discriminator: §3.3.
- `session_expired` and `session_closed` as distinct error codes:
  §3.2, §3.4.
- Library-crate + binary-crate split: §2.

---

## 10. Sign-off log

| Reviewer | Role | Status |
|---|---|---|
| Yuhao Li | design author, implementer | drafting |
| Sun Qizhen | tech-manager review of architecture and PR plan | requested via PR 1 |
| Parallel-design reviewer (merged into this document) | cross-review | absorbed |
