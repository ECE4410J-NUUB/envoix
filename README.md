# envoix

Minimal CLI-first secure file transfer walking skeleton for VE441.

## Minimal Usage

Run the receiver:

```bash
cargo run -p envoix-cli -- receive --listen "[::1]:9000" --output ./received
```

In another terminal, send one file:

```bash
cargo run -p envoix-cli -- send --peer "[::1]:9000" ./hello.txt
```

The receiver writes the file into the output directory using the original file name.

## Current Scope

Implemented:

- one-file transfer over a manually supplied IPv6 TCP address;
- minimal length-prefixed JSON frame protocol;
- sequential chunks with progress events;
- temp output file followed by final rename;
- public CLI-facing facade through `envoix-client`.

Not implemented in this walking skeleton:

- real encryption or authentication;
- discovery, QR pairing, relay, or server fallback;
- resume, pause, folder transfer, or multi-file manifests;
- hash verification or corruption recovery.
