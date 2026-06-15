# Self-hosted relay - design

Status: draft for review (extends the "self-hosted forwarding" future-path
note in `relay-design.md`).

## 1. Goal

Let a non-expert run their own relay forwarder on common Linux without
touching the rendezvous operator's infrastructure. Success: someone who is
not a sysadmin can install, start, and confirm a working relay in a few
minutes, and when something is wrong the tool tells them exactly what and
how to fix it.

Two independent pillars:

- **Trust / key model** - how a self-hosted relay is authorized without
  handing its secret to the rendezvous.
- **Operational UX** - packaging, a management CLI, and self-diagnostics.

The data-plane binary itself does not change; both pillars are control-path
and tooling.

## 2. Trust and key model

### 2.1 Two secrets, opposite rules

- **Master key**: the 32-byte secret a relay validates tokens with. Whoever
  holds it can mint unlimited tokens, i.e. full control of that relay.
- **Token**: a short-lived, single-session pass signed by the master key
  (`session_id || role || expires_at || tag`).

Each peer only ever needs a token. Neither peer needs the master key unless
it owns the relay. This is distinct from the pairing passphrase: the
passphrase is deliberately low-entropy and protected by the PAKE (online
guessing only); the master key is offline-exposed and must be high entropy.

### 2.2 Why the master key must be high entropy

Tokens are observable - they pass through the rendezvous and reach peers.
An attacker who sees one token can mount an offline key-recovery attack:
guess a key, recompute the tag over the known plaintext fields, compare. No
network, no rate limit. A random 256-bit key makes this infeasible; a
low-entropy key (passphrase, short string) is brute-forceable, and recovery
means the attacker can mint tokens at will. The key's only protection is
being unguessable, so it is machine-generated, never human-chosen.

### 2.3 Self-hosted authorization flow

1. The relay owner holds the master key (their own relay).
2. After direct/punch fails, the owner mints two tokens with its key - one
   for itself, one (opposite role) for the peer. Role is only a pairing
   discriminator for the relay's forwarding table, separate from who sends
   the file.
3. The owner advertises a relay candidate carrying the endpoint and the
   peer's token. The rendezvous passes this through opaquely; it never holds
   the key or mints anything.
4. The peer uses that token to wrap its datagrams (`magic || token ||
   payload`). It never sees the master key.

`session_id` in the token is the rendezvous session id (the shared value
both peers already know - a natural pairing key). `expires_at` comes from
the session TTL the owner received at register/join.

### 2.4 Token confidentiality (v1 decision)

The rendezvous sees the token in transit. For v1 this is accepted: the relay
is untrusted, the token is session-scoped and short-lived, and the worst a
malicious rendezvous gains is relay access for that one session. Optional
future hardening: encrypt the token to the peer with a passphrase-derived
key so the rendezvous shuttles only ciphertext.

## 3. Control-path changes

| Component | Change |
|---|---|
| `envoix-relay-server` (data plane) | none - validates with its key, forwards |
| `envoix-relay` crate | expose `mint` for client use (already pure) |
| Rendezvous candidate model + API | relay candidate carries an opaque `relay_token`; passed through |
| Client / CLI | config, mint two tokens, advertise, consume, wrap datagrams |
| Rendezvous | new reachability-probe capability (see 5.3) |

The only protocol change is an optional `relay_token` field on relay
candidates. Everything else is client-side wiring plus tooling.

## 4. Packaging and install

- **Universal static binary** (`x86_64-unknown-linux-musl`, already built):
  works on any Linux, no dependencies. The fallback for every system.
- **`.deb` (Debian/Ubuntu)** via `cargo-deb`: installs the binary, a systemd
  unit (`DynamicUser`, `Restart=on-failure`, `StateDirectory`), the config
  directory, and a `postinst` that generates the master key (0600) if
  missing. This is the easy path for the most common case.
- **Other formats** (`.rpm`, OpenWrt `.ipk`, AUR, brew): deferred, added by
  demand. Not maintained from day one.

systemd owns the service lifecycle (start/stop, boot-persistence, logging,
restart). The CLI does not reimplement this.

## 5. Management CLI

One binary with subcommands. `run` is the server process systemd invokes;
the rest are operator tools that wrap systemd and add value.

### 5.1 `config`

Read/write `/etc/envoix-relay/config.toml`: listen port, advertised
address, monthly/per-session caps, key-file path, and logging settings
(level, stats-log interval, sweep and usage-flush intervals). Validation on
write. `config init` generates a key and sensible defaults. A user-supplied
key is
rejected if obviously weak (not 32 bytes, low unique-byte count, repetition,
all-zeros); entropy cannot be measured from the value alone, so this is
best-effort and the guidance is "paste a generated key, do not type one".

The master key never appears on the command line (argv is world-readable via
`ps` / `/proc` and leaks into shell history). It lives only in the key file.

### 5.2 `up` / `down` / `status`

- `up` / `down`: wrap `systemctl start/stop` (+ `enable` for boot), then run
  a quick post-start reachability check.
- `status`: running state plus live stats (active pairs, quota used, error
  counters) and a one-line health verdict.

### 5.3 `test` (doctor / preflight)

Checklist with `PASS / WARN / FAIL` and the exact remediation command.

Local checks (the relay self-determines):
- bind test on the configured UDP port;
- firewall: detect the active backend (ufw / firewalld / nftables /
  iptables / cloud security group), confirm the UDP port is allowed, and on
  failure print the literal fix (e.g. `sudo ufw allow 9104/udp`);
- key-file and state-dir permissions;
- clock skew (token `expires_at` is wall-clock; large NTP drift silently
  breaks validation).

External reachability (needs a helper - a host cannot self-prove its UDP
port is open to the internet): the relay asks the rendezvous to send a UDP
probe to its advertised address and confirm receipt. This single check
proves the port is open end-to-end, detects NAT (local IP vs the public IP
the rendezvous observed), and verifies the advertised address is correct.
This reuses the rendezvous reflexive-address mechanism already used for
clients.

## 6. Observability

Today the relay's counters (`active_pairs`, `bytes_forwarded_total`,
`month_bytes`, `invalid_total`, `quota_exceeded_total`,
`session_cap_cutoff_total`, `rejected_capacity_total`) only surface as a
periodic tracing log line - useful for the public operator who tails logs,
useless for a casual self-hoster. The improvement is exposing and presenting
the data already collected, not collecting more.

### 6.1 Local stats access

A self-hoster is on the machine, so stats are local-first with no network
exposure and no admin token: the daemon serves a snapshot over a
permission-restricted Unix socket (or writes a periodic snapshot file
alongside `usage.json`). `status` reads it. The rendezvous keeps its
admin-token HTTP `/stats` because it is a public, remote-queried server; the
self-hosted relay does not need that surface.

### 6.2 Human-friendly summary

`status` formats the snapshot for a non-expert: uptime, active transfers,
total forwarded (GB), quota used/remaining with a percentage, error summary,
last activity, and a one-line health verdict - not raw counters.

### 6.3 Flow localization

The same counters double as a "where is it blocked" diagnosis:

- valid datagrams from one peer, none from the other -> the other peer
  cannot reach the relay (its firewall/NAT or a wrong advertised address);
- datagrams arriving but tokens invalid -> key mismatch or clock skew with
  the client;
- quota tripped -> monthly cap reached.

Most of the diagnosis comes from data already collected.

### 6.4 Metrics export (optional)

A Prometheus `/metrics` endpoint for power users who already run Grafana.
Cheap because the counters exist, but secondary to the noob path and off by
default. A bundled time-series database or dashboard is out of scope.

### 6.5 Privacy

The relay forwards opaque encrypted traffic and sees peer source addresses.
Stats stay aggregate: no content is ever logged, and peer addresses are not
retained in persisted stats. This matches the project's end-to-end privacy
posture.

### 6.6 Logging

PR #22 already made the sweep and housekeeping intervals configurable
(`--sweep-interval-secs`, `--housekeeping-interval-secs`), and the
housekeeping interval drives the periodic stats log line. Self-hosting adds:

- decouple the stats-log interval from the usage-flush interval (one knob
  drives both today);
- a first-class log-level setting rather than only the `RUST_LOG` env var;
- quiet by default - with on-demand `status` (6.1), the periodic stats line
  is mostly journald noise, so it defaults low or off and is opt-in.
