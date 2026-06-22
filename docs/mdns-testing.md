# mDNS Testing Checklist

Use this checklist after changes to LAN discovery, auto send/receive, QR invites,
or transfer progress reporting.

## 1. Local Validation

Run these before every commit:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected result:

- Formatting check passes.
- Clippy reports no warnings.
- All non-ignored tests pass.
- `client_send_auto_emits_events_in_order` is ignored by default because it
  needs local network access.

If `cargo test` fails with `Operation not permitted` or loopback tests hang,
rerun outside a restricted sandbox. The CLI loopback tests need local QUIC
sockets.

## 2. Ignored Network Test

Run this on a development machine with local networking enabled:

```bash
cargo test -- --ignored
```

Expected result:

- The ignored client auto-send event test runs.
- `AutoConnectionStarted` is emitted before `LanDiscoveryStarted`.
- Discovery failure is reported cleanly when no receiver is available.

## 3. Same-LAN mDNS Transfer

Use two terminals on machines connected to the same local network. The sender
and receiver can also be two terminals on the same machine if mDNS loopback works
on that OS.

Terminal 1:

```bash
cargo run -p envoix-cli -- receive --auto --output ./received --token "shared-token-123"
```

Terminal 2:

```bash
cargo run -p envoix-cli -- send --auto --token "shared-token-123" ./hello.txt
```

Expected result:

- Receiver prints that it is listening and advertising.
- Sender reports at least one LAN candidate.
- Transfer completes successfully.
- `./received/hello.txt` matches the original file.
- Progress events are visible during transfer.

## 4. Wrong Token mDNS Flow

Terminal 1:

```bash
cargo run -p envoix-cli -- receive --auto --output ./received-wrong --token "receiver-token-123"
```

Terminal 2:

```bash
cargo run -p envoix-cli -- send --auto --token "sender-token-456" ./hello.txt
```

Expected result:

- Sender may discover the receiver because mDNS records are not token-filtered.
- SPAKE2 authentication fails before file data is accepted.
- No final output file is created.
- No resume sidecar is left in the output directory.
- Terminal error clearly indicates authentication or pairing failure.

## 5. Multiple Receivers

Start two receivers on the same LAN:

```bash
cargo run -p envoix-cli -- receive --auto --output ./received-a --token "shared-token-123"
cargo run -p envoix-cli -- receive --auto --output ./received-b --token "different-token-456"
```

Then send with the first token:

```bash
cargo run -p envoix-cli -- send --auto --token "shared-token-123" ./hello.txt
```

Expected result:

- Sender can handle more than one discovered candidate.
- At most one receiver completes the transfer.
- The wrong-token receiver does not finalize a file.
- Failed attempts do not duplicate transfer progress output.

## 6. QR Invite Across Devices

Terminal 1:

```bash
cargo run -p envoix-cli -- receive --auto --output ./received-qr
```

Copy or scan the printed `invite: envoix:...` value on a second device:

```bash
cargo run -p envoix-cli -- send --invite "envoix:..." ./hello.txt
```

Expected result:

- The invite candidate is a reachable LAN address, not `127.0.0.1`.
- The sender validates the invite before dialing.
- Transfer completes across devices.
- Expired invites fail before any connection attempt.

## 7. Platform Coverage

Before release, repeat the local validation and at least one real LAN transfer
on each supported platform:

- macOS
- Linux
- Windows, if Windows support is in scope

Record any platform-specific firewall prompts, mDNS permissions, or required
network settings in the release notes.

## 8. Troubleshooting Signals

Common failure modes:

- `LAN discovery timed out`: receiver advertisement was not visible, mDNS was
  blocked, or sender and receiver are not on the same multicast-capable network.
- `Operation not permitted`: local socket creation is blocked by sandbox or OS
  permissions.
- No candidates found on public or enterprise Wi-Fi: multicast DNS may be
  disabled by the network.
- Invite contains `0.0.0.0`, `[::]`, or `127.0.0.1` for a cross-device test:
  candidate address generation is wrong for that environment.
