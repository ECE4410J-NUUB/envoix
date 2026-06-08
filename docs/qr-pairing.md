# QR Pairing Bootstrap — Roadmap

Tracks: Issue #5  
Branch: `feat/qr-pairing`  
Status: in progress

---

## Goal

Replace the manual token + address copy-paste workflow with a single QR code that the receiver prints to the terminal. The sender pastes the encoded invite string (or scans the QR image on mobile in a future milestone) and connects automatically.

**Before:**
```
envoix receive --output ./recv --token my-secret-token --ip-version ipv4
# user manually copies printed port, then on sender machine:
envoix send --peer 192.168.1.5:54321 --token my-secret-token ./file.bin
```

**After:**
```
envoix receive --output ./recv --auto
# terminal prints QR + one-line invite string

envoix send --invite <string> ./file.bin
```

---

## Architecture

### New crate: `crates/envoix-qr`

Pure data and serialization — no network, no filesystem, no async.

```
apps/envoix-cli
      ↓
envoix-qr        (new)
      ↓
envoix-types     (existing — PROTOCOL_VERSION)
```

`envoix-qr` must not depend on `envoix-auth`, `envoix-transport`, or anything network-facing.

### Payload format

```
QrInvitePayload  →  JSON  →  base64url  →  QR matrix  →  terminal art
```

base64url is chosen over raw JSON because:
- QR encodes URL-safe alphanumeric characters at higher density (fewer modules per byte)
- The encoded string is easy to paste in a terminal or share as plain text

### Invite string prefix

All invite strings are prefixed with `envoix:` to allow future format versioning and to
make the string recognisable at a glance:

```
envoix:eyJ2ZXJzaW9uIjoxLCJ0b2tlbiI6Ii4uLiJ9...
```

---

## Step-by-step Roadmap

### Step 1 — `envoix-qr` crate scaffold

- [ ] Add `crates/envoix-qr/Cargo.toml` to the workspace
- [ ] Define `QrInvitePayload`:

```rust
pub struct QrInvitePayload {
    pub version: u32,            // payload schema version, currently 1
    pub token: String,           // SPAKE2 shared token (≥12 ASCII bytes)
    pub candidates: Vec<String>, // socket addresses, e.g. ["192.168.1.5:54321"]
    pub expires_at: u64,         // Unix timestamp (seconds); receiver sets +5 min
    pub flags: u32,              // feature flags, 0 for now
}
```

- [ ] Define `QrError` with variants: `VersionMismatch`, `Expired`, `NoCandidates`,
  `WeakToken`, `MalformedAddress`, `DecodeError(String)`
- [ ] Implement `QrInvitePayload::encode() -> Result<String, QrError>`
  - serialize to JSON via `serde_json`
  - base64url-encode (no padding)
  - prepend `envoix:` prefix
- [ ] Implement `QrInvitePayload::decode(s: &str) -> Result<Self, QrError>`
  - strip `envoix:` prefix
  - base64url-decode
  - deserialize JSON
- [ ] Implement `QrInvitePayload::validate(&self) -> Result<(), QrError>`
  - reject `version != PAYLOAD_VERSION`
  - reject `expires_at` in the past (caller supplies current Unix time)
  - reject empty `candidates`
  - reject `token.len() < 12` or non-ASCII token
  - parse each candidate as `SocketAddr`, reject malformed
- [ ] Implement `QrInvitePayload::first_candidate() -> Result<SocketAddr, QrError>`

**Verify:** unit tests cover round-trip, expired payload, version mismatch, weak token, bad address.

---

### Step 2 — Terminal QR rendering

- [ ] Add `render_terminal_qr(data: &str) -> String` in `envoix-qr`
  - use `qrcode` crate to build the QR matrix
  - render with Unicode half-block characters (`▀`, `▄`, `█`, ` `) — two rows per
    character row, giving compact output
- [ ] Add a narrow quiet zone (2 cells) around the matrix so scanners can read it

**Verify:** `cargo test -- --nocapture` prints a readable QR to stdout.

---

### Step 3 — Random token generation helper

- [ ] Add `generate_token() -> Result<String, QrError>` in `envoix-qr`
  - fill 9 random bytes with `getrandom`
  - hex-encode → 18-char ASCII string (satisfies the ≥12 byte requirement)
- [ ] This is only used when `--auto` is set; manual `--token` still works

---

### Step 4 — CLI receiver: `--auto` path

File: `apps/envoix-cli/src/main.rs` (and `commands/receive.rs` if extracted)

- [ ] When `--auto` is set on `receive`:
  1. call `generate_token()`
  2. bind the QUIC listener (existing `receive_file_with_bound_addr`)
  3. collect bound address into `candidates`
  4. build `QrInvitePayload { version: 1, token, candidates, expires_at: now+300, flags: 0 }`
  5. call `encode()` → print the invite string (`envoix:...`)
  6. call `render_terminal_qr()` → print QR to stderr (keeps stdout clean for scripts)
  7. proceed with `authenticate_receiver` + transfer as usual, using the generated token
- [ ] `--auto` and `--token` are mutually exclusive; return an error if both are set

**Verify:** running `envoix receive --auto --output /tmp/r` prints a QR and invite string,
then waits for a connection.

---

### Step 5 — CLI sender: `--invite` argument

File: `apps/envoix-cli/src/main.rs`

- [ ] Add `--invite <STRING>` argument to the `send` subcommand
- [ ] `--invite`, `--peer`, and `--auto` are mutually exclusive
- [ ] When `--invite` is set:
  1. call `QrInvitePayload::decode(s)`
  2. call `validate()` with `now` as Unix timestamp
  3. call `first_candidate()` to get peer `SocketAddr`
  4. extract `token` from payload
  5. call `EnvoixClient::send_file()` with extracted peer + token (existing flow)
- [ ] Print a one-line summary of the decoded payload before connecting
  (e.g. `connecting to 192.168.1.5:54321, invite expires in 4m 52s`)

**Verify:** full loopback: `receive --auto` in one terminal, copy invite string, `send --invite <string> <file>` in another.

---

### Step 6 — Integration test

File: `apps/envoix-cli/tests/cli_loopback.rs` (existing test file)

- [ ] Add test `qr_invite_loopback`:
  1. spawn receiver with `--auto`
  2. capture printed invite string from stderr
  3. decode invite string to get port + token
  4. spawn sender with `--invite <string>` and a temp file
  5. assert both processes exit successfully
  6. assert received file bytes equal sent file bytes
- [ ] Add test `invite_expired_is_rejected`:
  - construct a payload with `expires_at` in the past
  - assert `decode` + `validate` returns `QrError::Expired`
- [ ] Add test `invite_version_mismatch_is_rejected`

**Verify:** `cargo test --workspace` passes.

---

### Step 7 — Docs and cleanup

- [ ] Rustdoc on all public items in `envoix-qr`
- [ ] Update `README.md` with the new `--auto` / `--invite` usage example
- [ ] Update `docs/auth.md` to note the QR bootstrap flow

---

## Out of scope for this issue

- Mobile camera scanning (future `envoix-ffi` / mobile milestone)
- QR image file output (`.png`) — terminal art is sufficient for CLI
- mDNS candidate discovery (Issue #8)
- Server rendezvous URL in payload (Issue #9)
- E2E encryption (Issue #11)

---

## Dependencies to add

| crate | version | used in | reason |
|---|---|---|---|
| `base64` | `0.22` | `envoix-qr` | base64url encode/decode |
| `qrcode` | `0.14` | `envoix-qr` | QR matrix generation |
| `getrandom` | already in workspace | `envoix-qr` | random token bytes |
| `serde_json` | already in workspace | `envoix-qr` | payload serialization |
