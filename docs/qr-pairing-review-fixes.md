# QR Pairing — Review Fixes Report

Branch: `feat/qr-pairing`
Date: 2026-06-08
Context: post-implementation review of Issue #5 (QR pairing bootstrap),
applied per the karpathy-guidelines (style / efficiency / readability).

This report records what the review found and what was changed, so work can be
resumed or extended later. The original roadmap is in
[`qr-pairing.md`](qr-pairing.md).

---

## Summary

9 findings (1 HIGH, 5 MEDIUM, 3 LOW) were identified and **all fixed**.
Tests after fixes: workspace green, 0 warnings, clippy clean.

- `envoix-qr`: 25 unit tests pass (was 24; +1 for protocol-version check).
- `envoix-cli`: 8 unit + 5 integration tests pass.

---

## Findings and fixes

### 🔴 A — `detect_local_ip` silently produced an unusable invite on offline LANs

- **File:** `apps/envoix-cli/src/main.rs` (`build_candidates`)
- **Problem:** on a LAN with no default route, the `connect("8.8.8.8")` probe
  fails and the code fell back to the bound address `0.0.0.0` / `[::]`, which a
  sender cannot dial — with no warning to the user. This is the project's
  primary target environment.
- **Fix:** after resolving the IP, if it `is_unspecified()`, print a warning
  telling the user the invite is not dialable and to share a reachable address
  out of band. The probe and fallback are unchanged; only the silent-failure
  case now surfaces.

### 🟠 B — `qr_invite_loopback` lacked the retry guard, risking flakiness

- **File:** `apps/envoix-cli/tests/cli_loopback.rs`
- **Problem:** the manual loopback test wraps send in `run_send_with_retries`
  to absorb the listener-startup race ("Connection refused"). The QR test hit
  the same race (invite is printed from the same `on_bound_addr` callback) but
  sent once, with no retry.
- **Fix:** extracted the retry loop into a generic `retry_send(impl FnMut() ->
  Output)`. `run_send_with_retries` now delegates to it, and `qr_invite_loopback`
  wraps its `--invite` send in `retry_send(...)` too.

### 🟠 C — `protocol_version` was carried in the payload but never validated

- **File:** `crates/envoix-qr/src/lib.rs` (`QrInvitePayload::validate`)
- **Problem:** a version-skewed peer would only fail later in the Hello/auth
  exchange with a more confusing error; the field was write-only.
- **Fix:** `validate()` now rejects `protocol_version != PROTOCOL_VERSION` with
  a new `QrError::ProtocolVersionMismatch { found, expected }`. Added unit test
  `protocol_version_mismatch_is_rejected`.

### 🟠 D — `QrError::DecodeError` was misused for non-decode failures

- **File:** `crates/envoix-qr/src/lib.rs`
- **Problem:** `encode()` reported serialization failure as a `DecodeError`, and
  `generate_token()` reported entropy failure as a `DecodeError`.
- **Fix:**
  - `encode()` is now infallible: returns `String`, with
    `serde_json::to_string(self).expect(...)` (the struct holds only primitives /
    `String` / `Vec<String>`, so serialization cannot fail). Matches the
    codebase's documented-`.expect()` style.
  - `generate_token()` keeps `Result` (entropy failure is genuinely possible)
    but now returns a dedicated `QrError::Entropy(String)`.
  - All call sites updated (lib tests, `main.rs`, integration tests).

### 🟠 E — Triple-duplicated `map_err` closure in the send path

- **File:** `apps/envoix-cli/src/main.rs`
- **Problem:** decode / validate / first_candidate each repeated the same
  `|e| PublicError::InvalidInput(format!("invalid invite: {e}"))`.
- **Fix:** added `resolve_invite(&str) -> Result<ResolvedInvite, PublicError>`
  (struct holds `peer_addr`, `token`, `expires_in`). The send branch calls it
  once; the error is mapped in one place via a local `to_err` closure.

### 🟠 F — Inconsistent conflict/required checking between send and receive

- **File:** `apps/envoix-cli/src/main.rs`
- **Problem:** send's `--token` used clap-level `required_unless_present` /
  `conflicts_with`, but receive's `--token` had no clap constraints and relied
  on two runtime checks instead.
- **Fix:** receive's `--token` is now
  `#[arg(long, required_unless_present = "auto", conflicts_with = "auto")]`.
  The two runtime checks were removed; the `else` branch uses
  `token.expect("clap requires --token unless --auto is set")`. Behavior now
  matches send (parse-time errors).

### 🟡 G — Magic number `300` for invite expiry

- **File:** `apps/envoix-cli/src/main.rs`
- **Fix:** introduced `const INVITE_TTL_SECS: u64 = 300;` and a small
  `unix_now()` helper (also reused by `resolve_invite`).

### 🟡 H — `render_terminal_qr` empty-string sentinel + redundant allocations

- **File:** `crates/envoix-qr/src/lib.rs`
- **Problem:** returned `String::new()` to signal an encode failure (conflated
  with valid output), and allocated three buffers (`colors` → `modules` →
  padded `grid`).
- **Fix:** signature is now `-> Option<String>` (`None` = too long to encode).
  The intermediate `modules` and `grid` buffers were removed; rendering indexes
  `colors` directly through an `is_dark(row, col)` closure that treats the quiet
  zone as light. `main.rs` prints the QR via `if let Some(qr) = ...`.

### 🟡 I — Expiry/version tests relied on an implicit ordering

- **File:** `apps/envoix-cli/tests/cli_loopback.rs`
- **Fix:** added a comment explaining that `"ignored.txt"` is intentional —
  invite validation must reject the invite before the file is opened or the
  peer is dialed.

---

## Public API changes (for downstream code)

| Item | Before | After |
|---|---|---|
| `QrInvitePayload::encode` | `-> Result<String, QrError>` | `-> String` |
| `render_terminal_qr` | `-> String` (`""` on failure) | `-> Option<String>` |
| `QrError` | — | added `ProtocolVersionMismatch { found, expected }`, `Entropy(String)` |
| `QrInvitePayload::validate` | no protocol-version check | rejects `protocol_version` mismatch |

---

## Verification

```bash
cargo test --workspace      # all green, 0 warnings
cargo clippy -p envoix-qr -p envoix-cli   # clean
```

## Not changed (deliberately)

- The UDP-connect IP-detection technique itself (standard approach; only the
  silent-failure path was addressed).
- Send's pre-existing `--auto` placeholder and its `--auto`/`--peer` runtime
  check (predates this feature; out of scope for surgical changes).
- `flags` field on the payload — spec-mandated reserved field, kept at 0.

## Possible follow-ups (not done)

- Enumerate local interfaces for multi-candidate invites instead of a single
  probed IP (would also feed Issue #8 mDNS work).
- Carry multiple candidates (LAN + IPv6) in one invite once discovery lands.
