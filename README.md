# envoix

Minimal CLI-first secure file transfer walking skeleton for VE441.

## Usage

### QR invite flow (recommended)

The receiver generates a random pairing token and prints a QR code plus an
invite string to the terminal. No manual token or address exchange is needed.

```bash
# Terminal 1 — receiver
cargo run -p envoix-cli -- receive --auto --output ./received
# prints QR code and: invite: envoix:<base64url>

# Terminal 2 — sender (paste the invite string printed above)
cargo run -p envoix-cli -- send --invite "envoix:<base64url>" ./hello.txt
```

The invite encodes the pairing token, receiver address, and a 5-minute expiry.
The sender validates the invite before attempting a connection.

### Manual flow

Supply the shared token and address explicitly. The receiver prints its
OS-assigned port after binding.

```bash
# Terminal 1 — receiver
cargo run -p envoix-cli -- receive --output ./received --token "shared-token-123"
# prints: listening on 0.0.0.0:<port>

# Terminal 2 — sender (use the receiver's reachable IP and printed port)
cargo run -p envoix-cli -- send --peer "192.168.1.5:<port>" --token "shared-token-123" ./hello.txt
```

Use `--ip-version ipv6` on `receive` to bind an IPv6 socket instead.

The receiver writes the file into the output directory using the original file
name. If a transfer is interrupted, restart both sides with the same source file
and output directory. The receiver resumes from its `.part` file and JSON sidecar
state, then verifies the whole-file BLAKE3 hash before the final rename.

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
- automatic LAN discovery, relay, or server fallback;
- interactive pause, folder transfer, or multi-file manifests;
- per-chunk hashes, parallel chunk transfer, or out-of-order chunk recovery;
- mobile camera scanning (QR invite requires manual paste on CLI).

QUIC currently uses generated self-signed certificates with an explicitly
insecure no-auth verifier. Peer/session authentication is provided by the
required pairing layer before transfer metadata is sent.
