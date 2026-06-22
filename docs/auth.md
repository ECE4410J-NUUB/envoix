# Pairing Authentication

Status: prototype

`envoix` now authenticates a QUIC session before transfer frames are sent. The
transfer layer remains responsible only for file metadata, chunks, resume state,
and BLAKE3 whole-file integrity. Pairing lives in `envoix-auth` and is run by
`envoix-session` immediately after QUIC stream setup.

## Model

The current pairing method is `Spake2SharedToken`. Both peers enter the same
ASCII token with `--token`. Empty, non-ASCII, and tokens shorter than 12 bytes
are rejected.

The token is not sent over the network. Both sides run SPAKE2 and then exchange
confirmation MACs before the sender sends `Hello` or `FileHeader`. If pairing
fails, the session closes and the receiver does not create a final file, temp
file, or resume sidecar.

## Channel Binding

SPAKE2 confirmation is bound to Quinn exporter material:

- exporter label: `envoix-auth-spake2-v1`;
- exporter context: `pairing`;
- exporter length: 32 bytes.

The confirmation transcript includes:

- domain label and protocol version;
- fixed sender and receiver identities;
- sender and receiver nonces;
- sender and receiver SPAKE2 messages;
- QUIC exporter bytes;
- role-specific confirmation labels.

This prevents a peer from proving token possession for one QUIC channel while
silently completing confirmation on another channel. Transports that cannot
provide channel binding fail authentication.

## SPAKE2 Caveat

This SPAKE2 backend is experimental. The available Rust `spake2` crate used here
is not independently audited, so this should be treated as prototype pairing
security rather than production assurance.

The current security goal is narrower than full end-to-end file encryption:
QUIC provides transport encryption, pairing authenticates this session, and
BLAKE3 verifies whole-file integrity after transfer.
