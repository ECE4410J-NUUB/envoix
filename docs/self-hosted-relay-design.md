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
