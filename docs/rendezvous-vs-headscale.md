# Rendezvous Design vs. Headscale — Reference Comparison

Status: reference only
Scope: cross-check of `docs/rendezvous-design.md` against Headscale's
coordination server, for future-reference. **No changes to our design
are implied by this document.** If a future revision of the design wants
to revisit a decision, this is the prior-art it should cite.

Headscale source: `github.com/juanfont/headscale`, examined at HEAD
`8f75ee5` (2026-06-08). Citations below are to that revision; line
numbers will drift.

## Why Headscale and not Tailscale itself

The Tailscale client (`github.com/tailscale/tailscale`) is BSD-3-Clause,
but the **coordination server** — the part most analogous to our
rendezvous server — is proprietary. Headscale is a clean-room
open-source reimplementation of the same coordination protocol, BSD
licensed, and is the only readable reference for how a Tailscale-style
coordinator is structured.

Headscale is a *persistent mesh-VPN* coordinator (long-lived nodes,
hours-to-months sessions, ACLs, DERP routing, OIDC). Our rendezvous
server is *one-shot pairing* (minutes-long sessions, ephemeral bearer
caps, no relay allocation). Many of Headscale's surfaces — ACLs, DERP
map, packet filter, OIDC, multi-user tenancy — are out of universe for
us and not compared here.

---

## Axis 1 — Identity and capability handling

| | Headscale | Our design (§3.1) |
|---|---|---|
| Token style | Bearer pre-auth key, presented per-request | Bearer cap, presented per-request |
| Hash at rest | bcrypt (`db/preauth_keys.go:124`) | BLAKE3 |
| Constant-time compare | via `bcrypt.CompareHashAndPassword` | explicit, on BLAKE3 output |
| Role separation | machine-key vs. node-key (device role) | receiver_cap vs. sender_cap (peer role) |
| Lookup strategy | 12-char prefix indexes DB row, then bcrypt verify | session_id is the key, one stored hash per role |

Headscale enforces machine→node binding on every authenticated request
(`noise.go:802-804`):

```go
if ns.machineKey != nv.MachineKey() {
    return types.NodeView{}, NewHTTPError(
        http.StatusNotFound,
        "node key in request does not match the one associated with this machine key",
        nil,
    )
}
```

**Assessment.** Same bearer pattern, same at-rest-hash discipline. The
hash-algorithm divergence is deliberate and correct: bcrypt is for
*password-strength* secrets (user-chosen, brute-forceable); BLAKE3 is
for *high-entropy random tokens* we generate ourselves (128 bits from
`getrandom`). Using bcrypt on a 128-bit random cap would slow
registration without changing security.

Their role binding is per-*device*; ours is per-*peer-role*. Different
bindings, same shape — both check authority before inspecting state.

---

## Axis 2 — Endpoint / candidate model

Headscale stores endpoints as a **flat slice with no classification**
(`types/node.go:123`):

```go
Endpoints AddrPorts `gorm:"serializer:json"`
```

The coordinator passes raw `netip.AddrPort` strings through; the
Tailscale client (which is sophisticated, with built-in STUN, DERP, and
hole-punching) does all classification itself. DERP preference is
tracked separately as an integer region id in `Hostinfo.NetInfo`.

Our design (§3.3): tagged-union `Candidate` with `kind ∈ {"host",
"ipv6_global"}`, `transport`, `priority`, `sequence`, `published_at`.

**Assessment.** The divergence is justified by the client model.
Headscale's flat list works because the Tailscale client is a heavy
network agent that can probe an endpoint and discover what it is. Our
peer is a thinner Rust file-transfer client; the `kind` tag carries
information the client can use *without* probing — "both peers have a
`host` candidate in `10.0.0.0/8`, try LAN first" is one cheap
comparison. Without the tag, the same logic moves into IP-string
parsing, which is worse.

Our `priority` field overlaps with Headscale's "client sorts however it
likes" — we keep it advisory (pass-through, no normalisation), matching
their de-facto behaviour.

---

## Axis 3 — Coordination protocol shape

| | Headscale | Our design |
|---|---|---|
| Pattern | Long-poll / streaming via `Stream=true` flag on `POST /map` | Short-poll `GET …/candidates?since=N` |
| Heartbeat | `MapResponse{KeepAlive: true}` every ~50s (`poll.go:292-304`) | None (poll is short, retried by client) |
| Lite mode | Same endpoint, `Stream=false, OmitPeers=true` returns 200 no-body (`poll.go:136`) | N/A |
| Wire encoding | JSON, optionally zstd-compressed | JSON |
| Transport | HTTP/2 over Noise encryption | HTTP/1.1 over TLS terminated at nginx |

Route registration (`noise.go:174`):

```go
r.Post("/map", ns.PollNetMapHandler)
```

The same handler serves both lite endpoint-update and streaming-peer-map
modes, distinguished by request fields. This is the pattern worth
remembering — one URL, mode by query/body, non-breaking evolution.

**Assessment.** Our short-poll is right for v1; Headscale's
long-poll is right for theirs. They pay the heartbeat and
connection-management cost because sessions are hours-long. Ours are
minutes, so polling cost is bounded and the simpler API wins.

When (if) we add a streaming variant later, Headscale's
same-URL-with-toggle pattern is the precedent — see the future-reference
note at the bottom of this document.

---

## Axis 4 — Lifecycle and expiry

Headscale has **no per-session TTL**. Node departure is detected by:

1. Explicit logout — `RegisterRequest` with past `Expiry`
   (`auth.go:34-62`)
2. Long-poll disconnect with a 10-second reconnect grace
   (`poll.go:177-205`)
3. Auth-cache TTL (15 min), but only on the auth-flow side
   (`state.go:45-46`)

The long-poll *is* the heartbeat — absence of a live connection is the
signal of departure.

Our design (§4.4): TTL on creation, refreshed on authenticated request,
swept every 30 s, opportunistically expired on read. No persistent
connection.

**Assessment.** Different problems, both correct. Their lifecycle
question is "is the node currently online?" Ours is "is the pairing
still valid for the window?" The 10-second reconnect-grace pattern is
worth borrowing *if* we ever add long-poll — clients can re-establish
without losing the session.

---

## Axis 5 — Concurrency

Headscale uses a **single-writer / copy-on-write snapshot** pattern
(`node_store.go:105-119`):

```go
type NodeStore struct {
    data       atomic.Pointer[Snapshot]
    writeQueue chan work
    batchSize    int           // 100 ops
    batchTimeout time.Duration // 500ms
}
```

All writes are queued, batched, applied to a copy of the snapshot, then
atomically swapped. Reads are lock-free (`atomic.Load`). No per-node
mutex; the single writer serialises all mutations.

Our design (§4.5): `Arc<tokio::sync::RwLock<HashMap<...>>>` plus per-
session inner `Mutex`.

**Assessment.** Their pattern is justified by scale: peer-map
recomputation on every update would be catastrophic under a coarse
lock, and broadcast fan-out to many long-poll subscribers benefits
hugely from lock-free reads. At our scale (hundreds of sessions, dozens
of concurrent short-pollers, no broadcast fan-out), `RwLock` is the
right choice and far simpler. The COW pattern is the documented escape
hatch if we ever fan out to many subscribers — see the future-reference
note at the bottom.

---

## Axis 6 — Error envelope and observability

Headscale has **no stable error-code taxonomy**. From
`handlers.go:95-108`:

```go
type HTTPError struct {
    Code int    // HTTP response code
    Msg  string // User message
    Err  error  // Server-side error for logging
}
```

Clients distinguish errors by HTTP status + string-match on the message.
Handlers contain bare literals like `"invalid pre auth key"` and
`"extending key is not allowed"`.

Our design (§3.4): `{ "code": "session_expired", "message": "…" }`
with a frozen `code` vocabulary.

**Assessment.** Our position is the more mature one. Without stable
codes, clients cannot programmatically distinguish `session_expired`
from `session_closed`, and any rewording of `Msg` silently breaks
downstream consumers. Tailscale's own newer endpoints have started
adding error codes for exactly this reason. Hold firm.

**Secret redaction.** Headscale uses Go struct tags
(`Password string \`json:"-"\``), which catches JSON serialisation
only. Our redacting `Debug`/`Display` on the `Capability` newtype is
strictly stronger: `tracing::debug!(?cap, ...)` is safe at the type
level, even outside a serialisation path.

**Metrics.** Headscale exposes Prometheus directly (counters,
histograms; `metrics.go:25-41`). We expose JSON stats with
Prometheus-compatible counter names and document the upgrade path. The
divergence matches our smaller scope.

---

## Axis 7 — Robustness

| | Headscale | Our design |
|---|---|---|
| Body limit | 1 MiB on `/map` (`noise.go:73`), 4 KiB on `/verify` | 64 KiB on all endpoints |
| Per-IP rate limit | None in-process; expected at proxy | None in-process; nginx |
| Shutdown timeout | 30 s (`HTTPShutdownTimeout`) | 5 s |
| Shutdown semantics | `Shutdown` stops accepting; `mapBatcher.Close()` interrupts long-polls via channel close | New requests get 503 `service_shutting_down`; in-flight finish within 5 s |

**Assessment.** Sizing differences are appropriate. Their 1 MiB
accommodates DERP maps and packet filters. Our 64 KiB is comfortably
above a worst-case publish payload (32 IPv6 candidates + metadata is
~3 KiB). Their 30 s timeout accommodates long-poll drain; our 5 s is
fine because short-poll requests are sub-second.

---

## Summary table

| Axis | Our position | Headscale's position | Verdict |
|---|---|---|---|
| Auth hashing | BLAKE3 | bcrypt | Both correct; entropy model differs |
| Role separation | receiver/sender caps | machine/node keys | Same pattern, different bindings |
| Candidate model | tagged union by `kind` | flat `[]AddrPort` | Ours fits a thinner client |
| Update channel | short-poll | long-poll/stream | Ours fits a shorter session |
| Lifecycle signal | TTL + sweep + refresh | long-poll liveness | Different questions |
| Concurrency | RwLock + per-session Mutex | COW snapshot, single writer | Ours fits v1 scale |
| Error envelope | stable `code` vocabulary | HTTP status + free text | Ours is more mature |
| Secret redaction | type-level `Debug`/`Display` | struct-tag JSON omit | Ours catches more leak paths |
| Metrics | JSON stats, Prometheus-compatible names | Prometheus directly | Both reasonable for scale |
| Body limit | 64 KiB | 1 MiB | Both sized for payload |
| Rate limit | nginx | reverse proxy | Same pattern |

---

## Three points to remember for future revisions

The three items below are the *only* things worth carrying forward from
this comparison. They do not motivate a v1 design change; they are
notes for when the v1 assumptions stop holding.

### 1. Streaming-upgrade URL shape

**When we add SSE or long-poll**, do it as `?stream=1` on the existing
`GET /api/v1/sessions/{id}/candidates` endpoint, **not** a separate
`/stream` route. Headscale's precedent (`Stream=true` toggle on
`POST /map`, `poll.go:81`) shows the pattern works: one URL, mode by
query/body, non-breaking for short-poll clients that omit the flag.
Inventing `/api/v1/sessions/{id}/candidates/stream` later would
fragment the API surface for no gain.

### 2. Registry-scaling escape hatch

**If we ever fan out to many long-poll subscribers per session**, the
documented path is to replace `Arc<RwLock<HashMap<...>>>` with a
copy-on-write atomic-swap snapshot — single writer goroutine, batched
writes, `atomic.Pointer<Snapshot>` for lock-free reads. Reference:
`/tmp/headscale/hscontrol/node_store.go:105`. This is *not* a
near-term concern: our v1 scale (hundreds of sessions, dozens of
concurrent pollers) is well inside what `RwLock` handles. The note
exists so the future-us doesn't redesign from scratch.

### 3. Candidate tag-vs-flat reconsideration trigger

**Hold the tagged-union `Candidate` until the client model changes.**
Headscale ships a flat endpoint list because the Tailscale client does
its own STUN/DERP/host classification. Our `kind` tag carries
information our thinner client uses without probing. The day our
client absorbs Tailscale-grade probing logic, the `kind` field becomes
redundant overhead and the flat-list precedent applies. Trigger:
"client now does its own endpoint classification." Until then, keep
the tag.
