# Reflexive UDP Discovery — Design

Status: draft
Scope: server half of Issue #10 — discovery of server-reflexive UDP
addresses for QUIC hole punching
Branch: `feat/reflexive-discovery` (off `server-dev`)
Owner: chkxw
Adjacent docs: `docs/rendezvous-design.md` (the HTTP rendezvous this
extends), `docs/rendezvous-api.md` (wire contract), RFC 8489 (STUN —
used as gold-standard reference, not implemented).

This document fixes the wire format, token scheme, and server behaviour
**before** code is written, following the same drill as the rendezvous
design. Reviewers should push back here, not on the PRs.

---

## 1. Scope

### 1.1 What this adds

A UDP probe service: a client sends one datagram from its QUIC socket;
the server replies with the source `ip:port` it observed — the client's
NAT mapping, i.e. its *server-reflexive address* — and simultaneously
publishes that address as a candidate into the client's rendezvous
session, where the peer finds it on its next poll.

The reflexive address is the missing ingredient for #10's hole
punching: both peers must learn the other's public UDP mapping through
a third party. This service is that third party.

### 1.2 What this does NOT do

- **No punch choreography.** Simultaneous-open timing, retries, the
  attempt state machine — all client-side (#10's client half, after
  #21). The server only supplies addresses.
- **No relay.** Issue #12.
- **No NAT behaviour discovery beyond the two-port mapping check**
  (§4.6). Full RFC 5780-style behaviour discovery is out of scope.
- **No STUN protocol compatibility.** We borrow STUN's lessons
  (§2.2), not its wire format. A client wanting public-STUN fallback
  can query public STUN servers *in addition* — nothing here prevents
  that.

### 1.3 The physics constraint everything follows from

NAT mappings are **per-5-tuple**: the mapping exists for
`(client socket → destination)` and only that socket. Therefore:

1. The client MUST probe **from the same UDP socket its QUIC endpoint
   uses** — a reflexive address learned from any other socket is
   useless for the later connection.
2. Probes cannot ride HTTPS, nginx, or Cloudflare (all TCP/HTTP). The
   probe service is raw UDP, directly exposed.
3. For NATs with endpoint-**dependent** mapping (symmetric NAT, most
   CGNAT), the mapping to our server differs from the mapping to the
   peer — the reflexive address is then NOT punch-usable. We cannot
   fix this; we *detect* it (§4.6) so the client can skip doomed
   punch attempts and go to relay fallback.

---

## 2. Background

### 2.1 Why a custom protocol instead of STUN

We control both endpoints; we want every probe bound to a live
rendezvous session (STUN Binding has no usable auth for that); and the
full frame logic is ~100 lines with zero new dependencies. STUN
compatibility buys us nothing server-side that a client can't get from
public STUN servers anyway.

### 2.2 Lessons taken from RFC 8489 (the gold standard)

These shaped the frame format in §3. Each was a real deployment scar
for STUN; we inherit the fix without rediscovering the wound.

| # | RFC 8489 lesson | Where it lands here |
|---|---|---|
| 1 | §5: top two bits of the first byte MUST be `00`, so the protocol can share a socket with others. Every QUIC packet sets one of the top two bits (RFC 9000 long-header `0x80` / fixed bit `0x40`) — a magic starting with an ASCII letter ≥ `0x40` would be misparsed as QUIC on the client socket. | Magic first byte `0x3F` (§3.2) |
| 2 | §14.2: some NATs run "well-meaning but misguided" generic ALGs that scan payloads for their own public IP in raw binary and rewrite it, corrupting the response. | Reply address is XOR-obfuscated (§3.3) |
| 3 | §6: client-chosen random transaction ID, echoed by the server — correlates retransmits and stops off-path response spoofing (attacker can't echo bytes it never saw). | 8-byte `txid` in both frames |
| 4 | §6.2.1: retransmission with RTO ≥ 500 ms, exponential backoff (0/500/1500/3500/7500 ms…), Karn's algorithm (no RTT samples from retransmitted transactions). | Client guidance §6 |
| 5 | §12: a basic STUN server is stateless. | HMAC token (§3.1) keeps our responder stateless too |
| 6 | FINGERPRINT (CRC) exists to disambiguate multiplexing where there is no stronger check. | Skipped — the HMAC tag is strictly stronger |

### 2.3 Trust model

Same as deployed STUN (RFC 8489 §16 analysis): an **on-path** attacker
(can observe probes) can spoof replies; such an attacker could already
observe the client's traffic, so this adds little. **Off-path**
attackers are defeated by the random `txid`. The reflexive address is
not secret material — it is published to the session anyway; the QUIC
connection that follows authenticates the *peer* end-to-end via SPAKE2
regardless of how addresses were learned.

---

## 3. Wire model

### 3.1 Probe token

Issued inside the (TLS-protected, capability-authenticated)
register/join HTTP responses. Echoed verbatim by the client in UDP
probes. **The bearer capabilities never appear in UDP** — plaintext
datagrams get only this low-value token.

```
payload = session_id ‖ role ‖ expires_at
          [16 bytes ] [1 B ] [8 B u64 BE unix-seconds]   = 25 bytes
tag     = HMAC-BLAKE3(server_key, payload)               = 32 bytes
token   = payload ‖ tag                                  = 57 bytes
```

- `role`: `0x01` receiver, `0x02` sender.
- `expires_at`: the session's wall-clock expiry at issuance time.
- `server_key`: 32 random bytes generated at process start, held only
  in memory. A restart invalidates tokens — and also the sessions they
  reference, so nothing of value is lost.
- BLAKE3's keyed mode serves as the HMAC (already a dependency; keyed
  BLAKE3 is its documented MAC construction).
- All fields fixed-width ⇒ concatenation is unambiguous (no
  canonicalization attacks).
- Encoding in JSON responses: lowercase hex (114 chars), consistent
  with every other binary field on the API.

Validation is stateless: split at fixed offsets, recompute the tag,
constant-time compare, check expiry. Any failure ⇒ **silent drop** (no
reply: scanners and reflection probes get nothing).

### 3.2 Probe request (client → server, UDP)

```
offset  size  field
0       4     magic    = 3F 45 56 58            ("?EVX"; first byte < 0x40, lesson 1)
4       1     version  = 0x01
5       8     txid     — client-chosen random bytes, echoed in reply
13      57    token    — §3.1, verbatim
                                                 total = 70 bytes exactly
```

Datagrams that are not exactly 70 bytes, or fail magic/version, are
silently dropped before any cryptography runs.

### 3.3 Probe reply (server → client, UDP, to the request's source)

```
offset  size   field
0       4      magic    (same constant)
4       1      version  = 0x01
5       8      txid     (echoed verbatim from the request)
13      1      family   = 0x01 IPv4 / 0x02 IPv6
14      2      xport    = observed port XOR magic[0..2]
16      4|16   xaddr    = observed addr XOR (magic ‖ txid)[0..addr_len]
                                                 total = 20 (v4) / 32 (v6) bytes
```

- The XOR keystream `magic ‖ txid` is 12 bytes — enough for IPv6's 16?
  No: it covers 12; the remaining 4 bytes XOR against `magic` again
  (`keystream = magic ‖ txid ‖ magic`). Spelled out so both ends agree:

  ```
  keystream = magic(4) ‖ txid(8) ‖ magic(4)      = 16 bytes
  xaddr[i]  = addr[i] XOR keystream[i]
  xport     = port XOR u16::from_be(magic[0..2])
  ```

- **Amplification safety by construction**: max reply (32 B) < request
  (70 B) — no padding rules needed, and invalid requests get silence.
  The reply : request byte ratio is at most 0.46.

### 3.4 New candidate kind

`server_reflexive_udp` joins the candidate `kind` union. Per
`rendezvous-design.md` §8 this is an additive, non-breaking change.
The HTTP publish endpoint also accepts it (a client may publish
reflexive addresses learned elsewhere, e.g. public STUN); `transport`
remains `quic`.

### 3.5 HTTP API additions (additive only)

Register and join responses gain two fields when the probe service is
enabled (absent when disabled — clients must treat them as optional):

```json
{
  "session_id": "…",
  "expires_at": "…",
  "probe_token": "<114 hex chars>",
  "probe_endpoints": ["73.47.70.209:9101", "73.47.70.209:9102"]
}
```

`probe_endpoints` comes from server configuration (§5). Delivering the
address in-band means deployment changes never require DNS or client
updates.

---

## 4. Server behaviour

### 4.1 Validation pipeline (per datagram)

```
len == 70?  → magic/version ok?  → recompute HMAC (constant-time eq)
  → expires_at in the future?  → session still live in the registry?
       any "no" ⇒ drop silently, count in stats
       all "yes" ⇒ reply + auto-publish
```

Cost of a garbage datagram: a few comparisons. Cost of a forged token:
one keyed-BLAKE3 over 25 bytes. No locks touched until full validity.

### 4.2 Auto-publish

On a valid probe, the server inserts
`(kind=server_reflexive_udp, transport=quic, addr=observed, priority=50)`
into the token's session for the token's role, through the existing
`SessionRegistry::publish_candidate` path. Consequences inherited for
free:

- **Retransmits are idempotent** — same observed mapping ⇒ duplicate
  `(kind, transport, addr)` ⇒ no-op per the dedup rule.
- The candidate cap, sequence numbering, TTL refresh, and the peer's
  `since`-cursor poll all behave identically to HTTP-published
  candidates.
- The peer needs **no new API** — reflexive candidates simply appear
  in poll responses.

The reply is still sent (the client needs its own mapping for the
symmetric-NAT check and diagnostics) — "auto-publish AND reply".

### 4.3 Sessions and roles

The token pins `(session_id, role)`. A receiver's token can only ever
publish receiver-side candidates. Token theft therefore lets the thief
publish *their own* observed address into the victim's session for a
few minutes — an annoyance (one bogus candidate among real ones, and
the QUIC+SPAKE2 layer rejects impostors) rather than a compromise.

### 4.4 Statistics (additive to `/api/v1/stats`)

```json
"probes": {
  "received_total": 0,
  "invalid_total": 0,
  "published_total": 0
}
```

`invalid_total` counts silent drops; a spike is a scanner or a broken
client, visible without packet captures.

### 4.5 Concurrency

One `tokio` task per probe socket (two sockets ⇒ two tasks), each a
`recv_from` loop calling pure validation functions and (on success)
the same async registry methods HTTP handlers use. Non-panicking by
construction; supervision identical to the TTL sweep.

### 4.6 Two ports — symmetric NAT detection

The server binds two UDP ports with identical behaviour. A client
probes both **from the same socket**:

- same observed `ip:port` from both ⇒ endpoint-independent mapping ⇒
  the reflexive address is punch-usable;
- different ⇒ endpoint-dependent (symmetric/CGNAT) ⇒ punching via
  this address will not work; the client should proceed to relay.

The server stays oblivious — both ports just answer. The comparison is
client logic. (When symmetric, auto-publish inserts two different
reflexive candidates; the peer may waste one bounded punch attempt on
them. Accepted for v1 — see Open decisions.)

---

## 5. Configuration and deployment

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--probe-listen` | `ENVOIX_PROBE_LISTEN` | unset (disabled) | Comma-separated bind addrs, e.g. `0.0.0.0:9101,0.0.0.0:9102` |
| `--probe-advertise` | `ENVOIX_PROBE_ADVERTISE` | unset | Comma-separated public `host:port` pairs put into `probe_endpoints`. Required if `--probe-listen` is set (the server cannot know its own public address behind NAT). |

Feature entirely off unless configured: no sockets bound, no fields in
HTTP responses, no behaviour change for existing deployments.

Reference deployment: binary binds `0.0.0.0:9101-9102/udp` directly
(unlike the HTTP port, which hides behind nginx on loopback); router
port-forwards UDP 9101→9101 and 9102→9102; firewall (`ufw allow
9101:9102/udp`) opened on the host. Cloudflare is not involved — the
probe addresses travel inside the HTTPS response, so the advertised
host can be a raw IP or any grey-DNS name.

---

## 6. Client guidance (non-normative, for #10's client half)

- Probe **from the QUIC endpoint's socket** — anything else yields a
  useless mapping (§1.3).
- Retransmit per RFC 8489 §6.2.1: send at 0 / 500 / 1500 / 3500 /
  7500 ms, give up after ~5 attempts; do not derive RTT from
  retransmitted transactions.
- Fresh random `txid` per transaction; ignore replies whose `txid`
  does not match one in flight.
- Probe both endpoints in `probe_endpoints`; compare mappings (§4.6).
  On mismatch, skip hole punching and proceed to relay fallback.
- Treat absence of `probe_token`/`probe_endpoints` in the register
  response as "service disabled" — not an error.

---

## 7. Out of scope, with future paths

- **Punch choreography / signaling** (e.g. a "start punching now"
  message). v1 relies on candidate exchange plus the client's bounded
  retry loop; an explicit sync primitive can be added to the HTTP API
  later if punching success rates demand it.
- **RFC 5780 NAT behaviour discovery** (filtering behaviour, hairpin,
  lifetime probing). The two-port mapping check covers the decision
  that matters (punch vs relay).
- **Probe-token refresh endpoint.** Tokens inherit the session expiry
  at issuance; punching happens in the first seconds of a session, so
  refresh is speculative. Revisit only if a real flow needs it.

---

## 8. Implementation plan

Two PRs into `server-dev` from this branch, mirroring the #6 split.

### PR 1 — `envoix-rendezvous`: probe logic (pure, no sockets)

- `probe.rs`: frame constants, request/reply encode/decode, XOR
  keystream, all fixed-offset parsing.
- `token.rs` (or extend `capabilities.rs`): `ProbeTokenKey` (random at
  construction), mint(session_id, role, expires_at) → 57 bytes,
  verify(bytes) → `Result<(SessionId, Role, SystemTime)>` with
  constant-time tag comparison.
- Unit tests: encode/decode round-trips (v4+v6), XOR vectors with
  fixed bytes, wrong-length/magic/version rejection, token
  mint→verify round-trip, tag tamper detection (flip each byte class),
  expiry rejection, truncated token.

### PR 2 — `envoix-server`: UDP task + API surface

- Probe socket task(s): recv loop → validate → reply + auto-publish.
- CLI flags (§5); `probe_token` + `probe_endpoints` in register/join
  responses (issued only when enabled).
- `server_reflexive_udp` accepted by the HTTP candidate endpoint.
- `probes` stats block.
- Tests: tokio UDP loopback integration (valid probe → correct XOR'd
  reply + candidate visible in peer poll; invalid → silence + counter;
  retransmit → dedup), register response carries fields only when
  enabled.

### Fleet validation (no client code needed)

A ~40-line Python probe script (socket, struct) driven over SSH:

| From | Expectation |
|---|---|
| this machine (same LAN as server) | observed = LAN/public addr; baseline correctness |
| `personal-laptop` (CERNET) | real reflexive mapping; both ports agree? |
| `csl` / `unity` (US universities) | institutional NAT behaviour |
| `ac68u` (Shanghai 移动, suspected CGNAT) | **the headline experiment**: do the two ports report different mappings? First empirical symmetric-NAT data point, directly informing #12's priority |

Results recorded as an Issue #10 comment (same pattern as the #9
validation).

---

## 9. Open decisions for implementation

Working positions, decided in-PR unless review objects:

- **Auto-published candidate priority = 50** (below typical host/LAN
  at 100). Advisory anyway; client re-ranks.
- **Symmetric-NAT double-publish accepted** (§4.6): the peer may burn
  one bounded punch attempt on a dead reflexive candidate. An
  "unpublish" or "mark stale" API is not worth its surface in v1.
- **Per-source rate limiting on the UDP path: none in v1.** Invalid
  traffic is near-free to drop; valid-token traffic is bounded by
  session caps. Revisit if `invalid_total` says otherwise.
- **Magic constant `3F 45 56 58`** — any value with first byte < 0x40
  works; bikeshed in PR review if desired.
- **Keyed-BLAKE3 as the MAC** rather than HMAC-SHA256: already a
  dependency, documented MAC mode, one less crate. Swap is trivial if
  review prefers textbook HMAC.

---

## 10. Sign-off log

| Reviewer | Role | Status |
|---|---|---|
| Yuhao Li | design author, implementer | drafting |
| Sun Qizhen | tech-manager review | pending |
