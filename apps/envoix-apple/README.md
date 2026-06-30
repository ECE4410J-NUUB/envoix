# Envoix — macOS app

Native SwiftUI desktop client for envoix. The UI is a thin layer over the Rust
core (`envoix-client`), reached through the `EnvoixCore` Swift package generated
from `crates/envoix-ffi` (uniffi). The same Swift sources are intended to port to
iOS later.

## Prerequisites

- Xcode 16+
- [`cargo-swift`](https://github.com/antoniusnaumann/cargo-swift): `cargo install cargo-swift`
- [`xcodegen`](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`

## Build & run

1. Generate the Rust↔Swift bridge package (run after any change to
   `crates/envoix-ffi`):

   ```bash
   cd crates/envoix-ffi
   cargo swift package --platforms macos --name EnvoixCore --accept-all
   ```

   This writes `crates/envoix-ffi/EnvoixCore/` (xcframework + Swift bindings).
   It is git-ignored and must be regenerated locally.

2. Generate the Xcode project and run:

   ```bash
   cd apps/envoix-apple
   xcodegen generate
   open Envoix.xcodeproj   # then ⌘R in Xcode
   ```

   Or build/run from the command line:

   ```bash
   xcodebuild -project Envoix.xcodeproj -scheme Envoix \
     -configuration Debug -derivedDataPath build build
   open build/Build/Products/Debug/Envoix.app
   ```

## Using it

Each tab has two pairing modes:

- **Same network (token)**: both sides enter the same shared token (12+ chars);
  the peer is discovered automatically over mDNS. No address/link exchange.
  Requires both devices on the same LAN.
- **Invite link**: the receiver publishes an `envoix:…` invite (QR + text,
  hidden behind *Show Address*); the sender pastes it.

The receive folder defaults to `~/Downloads` until you pick another (remembered
across launches). The first transfer may trigger a macOS "allow local network
access" prompt.

Quality-of-life:

- **Token mode** has a *Generate* button (and *Copy*) so you don't have to
  invent a token; it is shared between the Send and Receive tabs.
- **Send** accepts a file by drag-and-drop or *Paste Path* (from the clipboard),
  as well as the file panel.
- During a transfer the status line shows live throughput and an ETA based on a
  short rolling average; on completion the receiver gets *Reveal in Finder* and
  a copyable absolute path.
- A **menu-bar item** shows transfer status and an *Open Envoix* action; closing
  the main window keeps the app running there. The window is resizable and
  supports full screen.

## Roadmap (not yet implemented)

Planned follow-ups, captured here so they are not lost:

- Multi-file / folder transfer (near-term: app-side zip; later: core manifest).
- Global hotkey to send a chosen file fast.
- Saved peers: fixed token per known machine, so reconnecting needs no re-entry.
- Launch-at-login option.
- Proper code signing + notarization for distribution beyond the build machine.

## Notes

- `project.yml` is the source of truth; `Envoix.xcodeproj` is generated and
  git-ignored.
- The Rust static library links several Apple frameworks
  (`SystemConfiguration`, `Security`, `SecurityFoundation`, `CoreWLAN`); these
  are set in `project.yml` under `OTHER_LDFLAGS`. `CoreWLAN` in particular is
  resolved dynamically at runtime, so it must be linked even though it produces
  no link-time error when missing.
