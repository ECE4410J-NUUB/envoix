# Relay Fallback — Design

Status: draft
Scope: Issue #12 — server relay fallback for peers that cannot connect
directly (symmetric NAT / CGNAT, blocked UDP, failed hole punch)
Branch: `feat/relay` (off `server-dev`)
Owner: chkxw
Adjacent docs: `docs/rendezvous-design.md` (the session registry this
attaches to), `docs/reflexive-discovery-design.md` (the probe service;
shares the stateless keyed-MAC token and silent-drop patterns),
`docs/rendezvous-api.md` (client contract).

This document fixes the architecture, wire model, and runtime semantics
of the envoix relay **before** code is written, following the same drill
as the rendezvous and reflexive-discovery designs. Reviewers should push
back here, not on the PRs.

---

## 1. Scope

### 1.1 What the relay does

When two peers cannot establish a direct QUIC path — neither LAN, IPv6,
nor hole-punched — the relay forwards their (still end-to-end encrypted)
QUIC datagrams through a third box on the public internet. It is the
last-resort transport: slower and bandwidth-metered, but it works when
nothing else does.

The relay has two planes:

- **Control plane** (allocation): an authenticated HTTP endpoint that
  hands a peer a relay endpoint + a short-lived token. Lives at home,
  `envoix.chkxwlyh.us/relay/...`, behind Cloudflare like the rest of the
  rendezvous API.
- **Data plane** (forwarding): a dumb UDP forwarder on a VPS. Validates
  each datagram's token, pairs the two peers of a session by their
  observed addresses, and cross-forwards the payloads. Knows nothing of
  envoix's protocol, never decrypts, holds no per-token state.

### 1.2 What the relay does NOT do

- **It never decrypts.** The forwarded payload is opaque QUIC; SPAKE2 +
  QUIC's own encryption remain strictly end-to-end. The relay is not a
  trust party (same invariant as the rendezvous server, design §1.2).
- **It runs no envoix protocol logic.** No sessions-in-the-envoix-sense,
  no candidates, no metadata. Just byte forwarding by token.
- **It is not a general-purpose TURN server.** A datagram is forwarded
  only if its token validates against a relay allocation that was issued
  through the authenticated control plane.
- **It does not talk to the rendezvous server at runtime.** The home
  allocation endpoint and the VPS forwarder share a secret key out of
  band; the VPS validates tokens locally with that key and never calls
  home. (Failure isolation, and the VPS needs no HTTP stack at all.)

### 1.3 Non-goals for v1

- Multiple relay instances / DERP-style region selection. Single VPS.
- TCP fallback for UDP-blocked paths. (If even the relay's UDP is
  blocked, the transfer fails; a TCP relay is a separate future issue.)
- Per-session bandwidth fairness / token-bucket shaping. v1 caps total
  concurrent sessions; per-session rate is an off-by-default knob.
- Persisting relay state across restart. The forwarding table is
  in-memory; a relay restart drops in-flight transfers (they re-pair or
  fail, same recovery story as a rendezvous restart).

---

## 2. Background

### 2.1 Why a relay is required, not optional

Empirically (fleet tests, June 2026): **中国移动 mobile-data CGNAT is
endpoint-dependent (symmetric)** — the NAT mapping differs per
destination, so the reflexive address a peer learns from the probe
service is useless to the other peer. Hole punching via reflexive
addresses is *mathematically* impossible for such a peer; no amount of
client cleverness fixes it. For any transfer where one side is on a
symmetric NAT, the relay is the only path that connects.

Mobile data is plausibly the single most common consumer environment.
So relay is not a rare fallback — it is the required path for a large
class of real transfers.

Other cases the relay also covers: UDP hole-punch that fails for timing
or filtering reasons even between two endpoint-independent NATs;
networks that block inbound UDP entirely but allow outbound to a known
host.

### 2.2 Why this shape (vs. full TURN)

TURN (RFC 8656) is the standard, but most of it is scope we do not need:
allocation lifetimes with refresh, permissions, channels, multiple
transport protocols, long-term credential mechanism. We borrow only the
core idea — a server that forwards between two peers by their observed
addresses — and reuse our own stateless keyed-MAC token pattern (from the
probe service) for auth instead of TURN's credential machinery. The
result is ~a few hundred lines, not a TURN stack.

### 2.3 The forwarding model

The relay binds one UDP socket. Both peers send to it. Each datagram
carries a token that identifies `(session, role)`. The relay keeps an
in-memory table keyed by session id, with a slot for each role's most
recently observed source address. On a valid datagram it (a) records the
sender's address in its role slot, (b) looks up the *other* role's
address, (c) strips the relay header and forwards the bare payload from
its own socket.

Because the relay forwards from its own socket, each peer's QUIC sees a
coherent remote at the relay endpoint — exactly the address that peer is
sending to. NAT rebinding is handled for free: each valid datagram
refreshes the address slot, so a mid-transfer remap just updates where
the relay forwards.

```
Peer A ──[magic|tokenA|quic]──► relay:9104 ──[quic]──► Peer B
                                   │  table[session]:
                                   │    receiver_addr ← A (on A's packets)
                                   │    sender_addr   ← B (on B's packets)
Peer B ──[magic|tokenB|quic]──► relay:9104 ──[quic]──► Peer A
```

The token flows only peer→relay; the relay forwards bare payload, never
echoing the token. The header (magic+token) is stripped, so the output
datagram is strictly smaller than the input — no amplification.

---

## 3. Wire model

### 3.1 Relay token

Issued by the home allocation endpoint, echoed by the client in every
data-plane datagram, validated locally by the VPS forwarder.

```
payload = session_id ‖ role ‖ expires_at
          [16 bytes ] [1 B ] [8 B u64 BE unix-seconds]   = 25 bytes
tag     = keyed_BLAKE3(relay_key, payload)                = 32 bytes
token   = payload ‖ tag                                  = 57 bytes
```

Identical layout to the probe token (reflexive-discovery §3.1) — but the
key differs in a critical way:

- **`relay_key` is a shared, persistent deployment secret**, configured
  identically in the home server (issuer) and the VPS forwarder
  (validator). Contrast the probe token's per-process random key: there,
  one process both issued and validated, so the key could be ephemeral.
  Here, issuance (home) and validation (VPS) are different machines, so
  the key must be shared and survive restarts.
- `role`: `0x01` receiver, `0x02` sender.
- `expires_at`: the rendezvous session's expiry at allocation time. The
  relay refuses tokens past expiry — bounding how long an allocation can
  be used without any relay↔home communication.

Validation is stateless: split, recompute tag, constant-time compare,
check expiry. Any failure ⇒ silent drop (no reply, no log at normal
level).

**This follows established practice.** The shared-static-key + local
keyed-MAC validation pattern is exactly the **TURN REST API** model
(draft-uberti-behave-turn-rest, RFC 7635) used across WebRTC: a
signaling server and a separate TURN relay share one secret; the
signaling server mints time-limited MAC credentials the relay validates
locally **without any runtime call back**. coturn (the most-deployed
TURN server) ships this as `use-auth-secret`. Online validation
(relay calls home per token) was considered and rejected: it would
relocate rather than remove the secret (the relay would need its own
credential to call home), couple relay uptime to home reachability, and
add a round trip per session — for an "instant revocation" benefit that
short token expiry + idle eviction already approximate.

### 3.2 Data-plane datagram (peer → relay)

```
offset  size      field
0       4         magic    = 3F 45 56 59   ("?EVY"; first byte 0x3F keeps top
                                            two bits 00 so it is distinguishable
                                            from QUIC on the shared socket — same
                                            lesson as the probe magic, distinct
                                            last byte so the two protocols never
                                            alias)
4       57        token    — §3.1, verbatim from the allocation response
61      N         payload  — one opaque QUIC datagram
```

Header overhead is 61 bytes. The client MUST reduce its QUIC max-datagram
size by 61 bytes on a relayed path so the wrapped datagram still fits the
path MTU (client guidance §6).

### 3.3 Forwarded datagram (relay → peer)

Bare payload only — the relay strips magic+token and sends the `N`
payload bytes from its own socket to the other peer's recorded address.
The receiving peer's QUIC sees a normal datagram from the relay endpoint;
no envoix header to strip on ingress.

### 3.4 New candidate kind

`relay` joins the candidate `kind` union (reserved since rendezvous
design §3.3, never shipped until now). A `relay` candidate's `addr` is
the relay endpoint; its presence tells the peer "reach me through the
relay." Additive, non-breaking.

### 3.5 Allocation API (control plane, home)

`POST /api/v1/sessions/{id}/relay-allocation`, authenticated by either
peer's capability (same auth as candidate publish). Returns the relay
endpoint and that peer's role-bound token:

```json
{
  "relay_endpoint": "67.230.187.238:9104",
  "relay_token": "<114 hex chars>",
  "expires_at": "2026-06-13T09:20:00Z"
}
```

The endpoint comes from home-server configuration
(`--relay-advertise`); like the probe endpoints it travels in-band so a
VPS change never needs a client or DNS update. Absent the relay feature
(home not configured with a relay key + endpoint), the route returns
`404` — same disabled-feature convention as `/api/v1/stats`.

**Advertise a raw IP, not a hostname.** The endpoint is delivered to the
client inside the already-authenticated HTTPS allocation response and
dialed directly over UDP — the client never types it. Putting a hostname
there would force every client to resolve it via DNS before dialing, and
for the China-facing case that re-introduces GFW DNS poisoning as a
failure mode for exactly the path with no Cloudflare resilience behind
it. The secure in-band channel already delivers the address; re-deriving
it over (less trustworthy) DNS is strictly worse. A grey-cloud DNS name
for the box is fine for SSH/admin, but kept separate from
`--relay-advertise`.

The peer then publishes a `relay` candidate so the other side learns to
use it. (Or the client may treat the allocation response as sufficient
and dial the relay directly — both are valid; publishing keeps the
symmetric "everything is a candidate" model.)

---

## 4. Runtime behaviour

### 4.1 Allocation flow (lazy)

1. Client exhausts direct strategies (LAN, IPv6, hole punch) — all time
   out (client-side, #10).
2. Client `POST …/relay-allocation` with its capability. Home mints a
   role-bound relay token (shared key) and replies with the endpoint.
3. Client publishes a `relay` candidate (and/or dials directly).
4. Peer polls, sees the `relay` candidate, requests its *own* allocation
   (its own role-bound token), and dials the same relay endpoint.
5. Both peers send QUIC-over-relay; the relay pairs them by session and
   cross-forwards. QUIC handshake + SPAKE2 run end-to-end across the
   relay exactly as they would on a direct path.

Lazy means the VPS carries bytes only when direct genuinely failed —
protecting the metered link. The cost is one extra HTTP round trip on the
fallback path, negligible against the seconds already spent failing
direct attempts.

### 4.2 Forwarding (data plane)

Per datagram, cheapest checks first:

```
len ≥ 61 ?  → magic ok ?  → token MAC valid (constant-time) ?
  → expires_at in the future ?
       any "no" ⇒ drop silently (count invalid)
       all "yes" ⇒ record sender addr in its role slot;
                   look up other role's addr;
                     known   → strip header, forward payload, count bytes
                     unknown → drop (peer will retransmit via QUIC)
```

No locks until validity is established. The forwarding table is an
`RwLock<HashMap<SessionId, RelayPair>>`; a `RelayPair` holds two
`Option<SocketAddr>` slots and last-activity timestamps. Reads
(forwarding) dominate; writes happen only when an address slot changes
(first packet, or NAT rebind).

### 4.3 Lifecycle

A `RelayPair` is created on the first valid datagram for a session and
removed when:

- **idle**: no valid datagram for either slot within
  `--relay-idle-timeout` (default 60 s). A periodic sweep evicts idle
  pairs (same pattern as the rendezvous TTL sweep).
- **token expiry**: once both slots' tokens are past `expires_at`, the
  pair is unreachable anyway; the sweep collects it.

The relay never hears "session closed" from home (no runtime coupling).
Idle timeout + token expiry are the only lifecycle signals — sufficient,
because a finished transfer stops sending and idles out.

### 4.4 Capacity and bandwidth

The relay is a **tightly-boxed guest** on a VPS whose primary purpose is
unrelated (a personal bridge). The defaults are therefore conservative —
the relay must never threaten the box's main use. Two hard byte caps,
enforced on the bytes the relay already counts:

- **`--relay-monthly-byte-limit`** (default **200 GB**): cumulative bytes
  forwarded this calendar month. On exceed, forwarding is **disabled**
  (datagrams dropped, counted as `quota_exceeded`), a loud warning is
  logged, and it **auto-resets at the month boundary**. The counter is
  **persisted** (`/var/lib/envoix-relay/usage.json`, `{month, bytes}`)
  so a restart — or a restart loop — cannot bypass it. This guarantees
  the relay physically cannot exceed its slice of the VPS's transfer
  quota, with zero operator babysitting.

- **`--relay-max-bytes-per-session`** (default **1.2 GB**): once a single
  pair forwards more than this, the pair is **cut off mid-stream** (the
  transfer fails). The relay cannot reject a large transfer *up front* —
  it forwards opaque QUIC and never sees a "file size" — so enforcement
  is a mid-stream cutoff once the wire-byte budget is crossed. The
  default ~1.2 GB lets a legitimate ~1 GB file complete (≈ 1 GB data +
  QUIC overhead + ACKs) while killing anything genuinely larger.
  Wire-bytes ≠ file-size, so the line is approximate by nature; tune to
  taste.

- **`--relay-max-sessions`** (default **64**): refuse to create new pairs
  past the cap; existing pairs continue. Bounds memory and concurrency.

- **`--relay-max-rate-per-session`** (default unlimited): optional
  token-bucket per pair. Off by default — QUIC congestion control plus
  the two byte caps above are the first-line bound.

- **Bandwidth accounting**: per-pair byte/packet counters feed the stats
  block (§4.6); the monthly total is the persisted counter above.

**Optional courtesy pre-check** (depends on the client, not a security
boundary): a client *may* declare the file size when requesting a relay
allocation, and home *may* refuse to allocate for declared sizes > 1 GB
— saving the up-to-1.2 GB the mid-stream cutoff would otherwise spend on
an honest oversized transfer. A hostile client that lies is still caught
by `--relay-max-bytes-per-session`. This pre-check lands with the client
work, not v1 server-side.

### 4.5 Robustness

| Failure | Defence |
|---|---|
| Forged / replayed token | MAC validation, constant-time; silent drop. Stolen token only injects garbage a peer's QUIC rejects. |
| Amplification abuse | Output (bare payload) < input (payload + 61 B header); never amplifies. Unknown-peer datagrams dropped, not buffered. |
| Oversized datagram | Bounded by recv buffer; QUIC datagrams are ≤ path MTU. Anything larger is malformed → dropped. |
| Memory growth | `--relay-max-sessions` cap + idle sweep. |
| NAT rebind mid-transfer | Each valid datagram refreshes the address slot; forwarding follows the new address. |
| Relay restart | In-memory table lost; transfers stall and either re-pair (client retries allocation) or fall back to failure. Documented, accepted. |
| Home/VPS clock skew on `expires_at` | `expires_at` is wall-clock; a few seconds' skew only shifts the expiry boundary slightly. TTLs are minutes; immaterial. |

Explicitly NOT in v1: in-process DDoS mitigation beyond the cap (the VPS
provider's network + the control-plane gate are the front line); TCP
fallback; geo-distribution.

### 4.6 Observability and dynamic log control

**Normal mode** (default): counters only, **no peer IP addresses in
logs**. Matches the rendezvous server's redaction discipline.

```json
"relay": {
  "forwarding_enabled": true,
  "active_pairs": 3,
  "pairs_created_total": 41,
  "bytes_forwarded_total": 1290419233,
  "datagrams_forwarded_total": 1043221,
  "month_bytes": 41203992011,
  "month_byte_limit": 214748364800,
  "invalid_total": 87,
  "quota_exceeded_total": 0,
  "session_cap_cutoff_total": 2,
  "rejected_capacity_total": 0
}
```

`forwarding_enabled` reflects the combined state (manual pause, central
gate, or quota guard); `month_bytes` vs `month_byte_limit` is the
at-a-glance quota burn.

(Exposed via the relay binary's own admin-token-gated stats endpoint, or
a local stats socket — see Open decisions.)

**Debug mode** (toggled at runtime, no restart): logs everything useful
for diagnosing a specific transfer —

- per-pair peer source addresses (both roles),
- per-pair throughput (bytes/s) and datagram rate,
- per-datagram forward-processing time (relay-internal recv→send
  latency),
- address-slot changes (NAT rebinds).

Honest scope note: the relay **cannot** observe true end-to-end peer RTT
— the payload is opaque QUIC and the relay is mid-path, so it sees only
its own processing time and the two one-way streams. End-to-end latency
is a client-side metric. Debug mode logs what is actually measurable and
does not pretend otherwise.

**Toggle mechanism**: `SIGUSR1` cycles normal ↔ debug. No network
surface, works over SSH (`kill -USR1 <pid>` / `systemctl kill -s USR1`),
and a flipped boolean gates the verbose paths so normal-mode forwarding
pays nothing. (Alternative: a `tracing` reload layer driven by the same
signal — decided at implementation.)

### 4.7 Enable / disable controls

Three independent ways to stop the relay, for different situations. The
relay is **not** an open relay (every datagram needs a token minted by
the authenticated control plane), so the threat is *legitimate heavy
use* eating the VPS quota — not anonymous abuse. These controls bound
that.

1. **Hard off (VPS):** `systemctl stop envoix-relay`. Two convenience
   wrappers ship alongside the unit — `relay-off` and `relay-on` (thin
   `systemctl` aliases) — so toggling is one word over SSH. Immediate;
   drops in-flight transfers (acceptable for the abuse case).

2. **Graceful pause (VPS):** `SIGUSR2` flips a `forwarding_enabled`
   boolean — the process stays up, byte counters and stats are
   preserved, datagrams are dropped while paused. `systemctl kill -s
   USR2 envoix-relay`. Use when you want to pause without losing the
   monthly counter.

3. **Central gate (home):** the relay feature is off unless home has both
   `--relay-key` and `--relay-advertise` set. Unsetting them makes
   `/relay-allocation` return `404` — no new tokens issued, relay use
   stops at the source without touching the VPS.

4. **Automatic (quota guard):** the §4.4 monthly limit disables
   forwarding on its own when the byte budget is hit, no human action.

Default posture for the course project: relay **off** when not demoing
(`relay-off`), the §4.4 caps in force, flipped on with `relay-on` only
for testing. The box's primary (personal) use is fully insulated.

---

## 5. Deployment

### 5.1 Topology

```
                         envoix.chkxwlyh.us  (home, Cloudflare orange)
peer ──HTTP allocation──►  /api/v1/.../relay-allocation
                              │  mints token with shared relay_key
                              │  advertises 67.230.187.238:9104
peer ──UDP QUIC-over-relay──────────────────────────────► VPS :9104
                                                            envoix-relay-server
                                                            validates token (same key)
                                                            forwards bare payload
```

- **Home server** (`apps/envoix-server`): gains the `/relay-allocation`
  endpoint and two settings — `--relay-key` (shared secret) and
  `--relay-advertise` (the VPS `host:port`). Feature off unless both set.
- **VPS** (`apps/envoix-relay-server`): new standalone binary. Binds
  `0.0.0.0:9104/udp` (inside the already-open 9100-9105 range,
  AlmaLinux firewalld). Configured with the same `--relay-key`. No HTTP,
  no TLS, no Cloudflare — raw UDP, directly exposed (Cloudflare cannot
  proxy UDP anyway).
- **Shared key distribution**: a 32-byte secret in both env files
  (`/etc/envoix/server.env` at home, `/etc/envoix/relay.env` on the
  VPS), mode 600. Rotating it is a coordinated restart of both;
  acceptable for v1.

### 5.2 VPS specifics (already provisioned)

`67.230.187.238`, AlmaLinux 9.8, 2 vCPU / 1 GB, BandwagonHost CN2 GIA-E
(LA / DC9). firewalld open on UDP 9100-9105; key-only SSH; fail2ban.
Off-peak baseline Shanghai 移动 → VPS: 132 ms, 0 % loss (June 2026).
systemd unit + `DynamicUser`, `Restart=on-failure`, mirroring the home
server's hardening.

### 5.3 The relay binary is the only thing that runs on the VPS for envoix

The rendezvous server stays home. The VPS runs solely the data-plane
forwarder (plus whatever unrelated personal use the box has). This keeps
the trust/failure boundary clean: a VPS compromise exposes opaque
forwarded bytes and the relay key (which only lets an attacker forward
traffic a peer's QUIC would reject), not the rendezvous state or any
capability.

---

## 6. Client guidance (non-normative, for #12's client half)

- Request a relay allocation **only after** direct strategies fail
  (lazy). The allocation is one HTTP round trip.
- On a relayed path, **prepend `magic ‖ token`** to every outgoing QUIC
  datagram and send to `relay_endpoint`; received datagrams from the
  relay are bare QUIC (nothing to strip).
- **Reduce QUIC max-datagram size by 61 bytes** on the relayed path so
  the wrapped datagram fits the path MTU. (QUIC's conservative 1200-byte
  default + 61 = 1261, still under 1500, but a lower path MTU needs the
  adjustment.)
- Both peers dial the **same** relay endpoint; each uses its **own**
  role-bound token (tokens are not interchangeable).
- Treat absence of relay fields / a `404` from the allocation endpoint
  as "relay disabled," not an error — fall through to "transfer failed"
  with a clear message.
- SPAKE2 + QUIC run end-to-end across the relay unchanged; the relay
  path is just a slower, metered transport.

---

## 7. Out of scope, with future paths

- **Multi-region relays / DERP-style selection.** v1 is one VPS. The
  allocation response already returns an endpoint, so multiple relays
  slot in by having home choose among several `--relay-advertise`
  entries — additive.
- **TCP / TLS relay** for fully UDP-blocked paths. Separate transport,
  separate issue.
- **Per-session bandwidth fairness** beyond the optional rate cap.
- **Relay↔home runtime coupling** (e.g. push "session closed" to evict
  immediately). Idle timeout suffices; a control channel can be added if
  eviction latency ever matters.
- **Token rotation without coordinated restart.**

---

## 8. Implementation plan

Two PRs into `server-dev` from this branch, mirroring the #6 / #10
splits.

### PR 1 — `crates/envoix-relay`: pure logic (no sockets)

- `token`: `RelayTokenKey` (from a shared 32-byte secret, **not**
  random), mint(session_id, role, expires_at) → 57 bytes, verify →
  `Result<(SessionId, Role, SystemTime)>`, constant-time tag compare.
  Shared by the home issuer and the VPS validator.
- `frame`: datagram encode/decode (magic, token, payload split); the
  61-byte header constant; QUIC-demux magic invariant.
- `table`: `RelayTable` — `RwLock<HashMap<SessionId, RelayPair>>`,
  record-address / lookup-peer / sweep-idle, byte/packet counters, and
  the **per-session byte cap** (cut off a pair past
  `max_bytes_per_session`).
- `quota`: `MonthlyUsage` — pure counting + month-rollover logic for the
  monthly byte limit (the file persistence is the binary's job; the lib
  holds the count/compare/reset logic so it is unit-testable).
- Unit tests: token mint→verify round-trip, tamper/expiry/wrong-key
  rejection, frame round-trip + reject (short, bad magic), table
  pairing (A then B both forward; unknown-peer drop; rebind updates
  slot; idle sweep), **per-session cap cutoff**, **monthly quota
  exceed + month-rollover reset**, amplification invariant (output <
  input).

### PR 2 — `apps/envoix-relay-server` + home allocation endpoint

- New VPS binary: UDP recv loop → validate → forward, the idle sweep
  task, `SIGUSR1` debug toggle, **`SIGUSR2` forwarding pause**, stats,
  the **persisted monthly counter** (`/var/lib/envoix-relay/usage.json`,
  flush periodically + on shutdown, load-and-maybe-reset on startup),
  clap config (`--relay-listen`, `--relay-key`,
  `--relay-monthly-byte-limit`, `--relay-max-bytes-per-session`,
  `--relay-max-sessions`, `--relay-idle-timeout`,
  `--relay-max-rate-per-session`, admin token).
- `relay-off` / `relay-on` convenience scripts + the systemd unit
  (`DynamicUser`, `Restart=on-failure`, `StateDirectory=envoix-relay`
  for the usage file).
- Home (`apps/envoix-server`): `POST …/relay-allocation` handler,
  `--relay-key` + `--relay-advertise` config, `relay` candidate kind
  accepted on the publish endpoint, relay stats surfaced if desired.
- Tests: tokio UDP loopback — two synthetic peers send wrapped
  datagrams, assert cross-forwarding + payload integrity + header
  stripped; invalid token → silence + counter; unknown-peer → drop;
  rebind → forwarding follows; **per-session cap cuts a pair off**;
  **monthly limit disables forwarding, persists, reloads**; `SIGUSR2`
  pauses/resumes; allocation endpoint mints a verifiable token and
  404s when disabled.

### Fleet validation (no client code needed)

Extend the existing `udp-punch`-style synthetic tooling to a
`relay-test` that allocates via HTTP, wraps a payload, and checks
round-trip through the VPS:

| Pair | Purpose |
|---|---|
| this machine ↔ ac68u via VPS | baseline relay forwarding US ↔ CN |
| **phone hotspot (symmetric) ↔ anything via VPS** | the headline: the case that direct/punch could NOT do, now working through the relay |
| evening-peak throughput | iperf3-style sustained-rate + loss through the relay at 20:00-23:00 Beijing |

Results recorded as an Issue #12 comment (draft for the user's approval
first — never post unprompted).

---

## 9. Open decisions for implementation

Working positions, decided in-PR unless review objects:

- **Relay stats exposure**: the VPS binary has no HTTP stack. Options:
  (a) a tiny admin-token-gated UDP stats request on the same socket;
  (b) a separate loopback HTTP port; (c) log-only (debug mode dumps the
  snapshot). Lean: (a) — reuse the socket, one more magic byte, no new
  surface.
- **Magic last byte `0x59`** for the relay (vs `0x58` probe) so the two
  UDP protocols never alias if a deployment ever co-locates them.
  Bikeshed in review.
- **Idle timeout 60 s** default — long enough to survive a QUIC
  handshake stall, short enough to free memory promptly.
- **`relay` candidate priority** — lowest of all kinds (it is the
  last-resort path); client tries it only after others. Advisory.
- **One allocation per peer** (each role gets its own token) vs. one
  shared per session. Lean: per-peer — role-bound tokens mean a stolen
  token can only impersonate one role, and it mirrors the probe token
  model.
- **Keyed-BLAKE3 as the MAC** (consistent with probe tokens) vs.
  HMAC-SHA256. Lean: keyed-BLAKE3, already a dependency.

---

## 10. Sign-off log

| Reviewer | Role | Status |
|---|---|---|
| Yuhao Li | design author, implementer | drafting |
| Sun Qizhen | tech-manager review | pending |
