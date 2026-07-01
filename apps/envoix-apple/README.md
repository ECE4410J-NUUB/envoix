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

## UI iteration workflow

For layout and visual work, use Xcode previews instead of repeatedly launching
the whole app:

1. Open `apps/envoix-apple/Envoix.xcodeproj`.
2. Open `Sources/PreviewFixtures.swift`.
3. Use the canvas previews for app shell, send progress, receive invite,
   completed receive, and failure states.

Only regenerate `EnvoixCore` when the Rust FFI surface changes. Pure SwiftUI
edits under `apps/envoix-apple/Sources` should refresh through the preview
canvas or Xcode's incremental build. If the canvas stalls, use **Editor >
Canvas > Reload Canvas** before doing a full app rebuild.

## Using it

Each tab has three pairing modes:

- **Room Code**: the default path. The receiver generates a short code and
  waits; the sender enters that code. The rendezvous broker only pairs devices,
  and the file still moves over the encrypted transfer path.
- **Link / QR**: the receiver publishes an `envoix:…` invite as QR + text; the
  sender scans or pastes it.
- **Shared Token**: both sides enter the same shared token (12+ chars); the peer
  is discovered automatically over mDNS. This is best for same-LAN transfers.

The receive folder defaults to `~/Downloads` until you pick another (remembered
across launches). The first transfer may trigger a macOS "allow local network
access" prompt.

Quality-of-life:

- **Room Code** starts ready on the receive side with *Generate* and *Copy*.
  The send side only asks for the receiver's code.
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
