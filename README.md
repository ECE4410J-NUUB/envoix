# envoix

Minimal CLI-first secure file transfer walking skeleton for VE441.

## Minimal Usage

Run the receiver:

```bash
cargo run -p envoix-cli -- receive --listen "[::1]:9000" --output ./received --token "shared-token-123"
```

In another terminal, send one file:

```bash
cargo run -p envoix-cli -- send --peer "[::1]:9000" --token "shared-token-123" ./hello.txt
```

The receiver writes the file into the output directory using the original file name.
If a transfer is interrupted before completion, restart both commands with the same
source file and output directory. The receiver resumes from its deterministic
`.part` file and JSON sidecar state, then verifies the whole-file BLAKE3 hash
before final rename.

See [docs/auth.md](docs/auth.md) for the pairing model and SPAKE2 prototype
security caveat.

## Current Scope

Implemented:

- one-file transfer over a manually supplied address;
- QUIC transport;
- required experimental SPAKE2 shared-token pairing before file metadata;
- minimal length-prefixed JSON frame protocol;
- sequential resumable chunks with progress events;
- deterministic temp output file plus resume sidecar state;
- whole-file BLAKE3 verification before final rename;
- public CLI-facing facade through `envoix-client`.

Not implemented in this walking skeleton:

- end-to-end file encryption;
- discovery, QR pairing, relay, or server fallback;
- interactive pause, folder transfer, or multi-file manifests;
- per-chunk hashes, parallel chunk transfer, or out-of-order chunk recovery.

QUIC currently uses generated self-signed certificates with an explicitly
insecure no-auth verifier. Peer/session authentication is provided by the
required pairing layer before transfer metadata is sent.
