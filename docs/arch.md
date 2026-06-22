# envoix Architecture

Status: draft  
Scope: minimal CLI-first architecture and intended final architecture  
Primary design rule: **applications depend on the core; the core must not depend on applications.**

Update note: the current implementation is QUIC-only and requires pairing
authentication before transfer metadata. See `docs/auth.md` for the current
pairing model and SPAKE2 risk caveat.

---

## 1. Project intent

`envoix` is a cross-platform secure file transfer system. The eventual product set is:

- native desktop/mobile clients;
- one CLI;
- one self-hostable server binary;
- shared Rust protocol/transfer core;
- multiple connection strategies: LAN, IPv6 direct, p2p, relay, server fallback;
- end-to-end encryption and verified, resumable transfer.

The first engineering target is deliberately much smaller:

> Build a CLI that transfers one file over a manually supplied IPv6 address using a minimal frame protocol. Discovery, encryption, authentication, relay, server fallback, QR codes, and mobile bindings are represented by interfaces and placeholder implementations, not full implementations.

This is a **walking skeleton**: a small vertical slice that proves the shape of the system.


## 2. Architectural principles

### 2.1 Application crates are not core crates

The CLI is an application. It must depend on the public client-facing core API, not on low-level protocol internals.

Correct dependency direction:

```text
apps/envoix-cli
        ↓
crates/envoix-client
        ↓
crates/envoix-session
        ↓
crates/envoix-transfer
        ↓
lower-level core crates
```


Application crates may choose UI, terminal output, process exit codes, and user-facing formatting. Core crates should expose typed APIs and events.


### 2.2 Public APIs should be explicit

Each crate should expose its public API through `src/lib.rs`.

Internal modules should remain crate-private where possible:

```rust
mod internal_parser;
mod state_machine;

pub use public_types::{TransferId, ChunkId};
pub use engine::{TransferEngine, SendRequest, ReceiveRequest};
```

Avoid this pattern:

```rust
pub mod everything;
pub mod internal;
pub mod experimental;
```

That leaks implementation details and makes later refactors painful.

### 2.3 Placeholder implementations are allowed; fake interfaces are not

For the minimal version, `encrypt_chunk()` may return the input unchanged. But the interface should already contain the information real encryption will need later.

Good:

```rust
pub trait CryptoProvider: Send + Sync {
    fn encrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}
```

Bad:

```rust
pub fn encrypt(bytes: Vec<u8>) -> Vec<u8> {
    bytes
}
```

The first design can evolve into nonce-based authenticated encryption. The second design will need to be torn out.


### 2.4 The transfer engine talks to abstract transports

The transfer engine should not know whether bytes are moving over TCP, QUIC, relay, WebSocket, or server-backed object storage.

The dependency should be:

```text
envoix-transfer → envoix-transport
```

not:

Concrete transport selection happens in `envoix-session`.


## 3. Minimal version: goal and non-goals

### 3.1 Minimal goal

Support:

```bash
envoix receive --listen "[::1]:9000" --output ./received
envoix send --peer "[::1]:9000" ./hello.txt
```

and later:

```bash
envoix receive --listen "[::]:9000" --output ./received
envoix send --peer "[receiver-global-ipv6]:9000" ./large.bin
```

The minimal version should transfer exactly one file from sender to receiver.

### 3.2 Minimal non-goals

The minimal version intentionally does **not** implement:

- real encryption;
- peer authentication;
- QR pairing;
- automatic discovery;
- LAN mDNS;
- relay;
- server fallback;
- resumability;
- pause/resume;
- folder transfer;
- multi-file manifests;
- mobile bindings;
- WebRTC (optional);

However, the crate interfaces should make these features possible later. 

---

## 4. Minimal workspace layout

Use a Cargo workspace.

```text
envoix/
├── Cargo.toml
├── README.md
├── arch.md
├── apps/
│   └── envoix-cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── commands/
│           │   ├── mod.rs
│           │   ├── send.rs
│           │   └── receive.rs
│           ├── output.rs
│           └── progress.rs
├── crates/
│   ├── envoix-client/
│   ├── envoix-session/
│   ├── envoix-transfer/
│   ├── envoix-transport/
│   ├── envoix-transport-tcp/
│   ├── envoix-protocol/
│   ├── envoix-discovery/
│   ├── envoix-storage/
│   ├── envoix-crypto/
│   ├── envoix-types/
│   └── envoix-error/
├── docs/
│   ├── protocol-v0.md
│   ├── crate-map.md
│   └── transfer-v0.md
└── tests/
    ├── cli_loopback.rs
    └── transfer_memory.rs
```

The conceptual boundary is important:

```text
apps/      binaries and user-facing applications
crates/    reusable libraries
docs/      protocol and design documentation
tests/     workspace-level integration tests
```

`apps/envoix-cli` is not a core crate. It is a binary application.

---

## 5. Minimal dependency graph

```text
                            ┌──────────────────┐
                            │ apps/envoix-cli  │
                            └────────┬─────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │ envoix-client    │
                            └────────┬─────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │ envoix-session   │
                            └────┬─────┬───────┘
                                 │     │
              ┌──────────────────┘     └─────────────────┐
              ▼                                           ▼
     ┌──────────────────┐                       ┌─────────────────────┐
     │ envoix-discovery │                       │ envoix-transport-tcp│
     └────────┬─────────┘                       └──────────┬──────────┘
              │                                            │
              ▼                                            ▼
     ┌──────────────────┐                       ┌─────────────────────┐
     │ envoix-transport │◄──────────────────────│ envoix-protocol     │
     └────────┬─────────┘                       └──────────┬──────────┘
              │                                            │
              └──────────────┬─────────────────────────────┘
                             ▼
                    ┌──────────────────┐
                    │ envoix-transfer  │
                    └────┬──────┬──────┘
                         │      │
                         ▼      ▼
              ┌─────────────┐ ┌─────────────┐
              │ envoix-crypto│ │ envoix-storage│
              └──────┬──────┘ └──────┬──────┘
                     │               │
                     ▼               ▼
              ┌────────────────────────────┐
              │ envoix-types / envoix-error│
              └────────────────────────────┘
```

More precise rules:

- `envoix-cli` should depend on `envoix-client`, not on `envoix-transfer`, `envoix-protocol`, or `envoix-transport-tcp`.
- `envoix-client` is the public facade used by CLI now and by mobile/FFI later.
- `envoix-session` is allowed to know concrete transports and placeholder implementations.
- `envoix-transfer` must depend only on abstract transport traits, not concrete transport crates.
- `envoix-protocol` must not open sockets.
- `envoix-crypto` must not know files, sockets, CLI, or server.
- `envoix-storage` must not know protocol semantics beyond transfer IDs, chunks, and file paths.


## 6. Minimal crate responsibilities and public interfaces

Contents in this section are subject to changes. No need to stick to the current design of interfaces if you have a better design. 

### 6.1 `envoix-types`

Purpose: shared domain types.

Public interface:

```rust
pub struct TransferId(pub String);
pub struct FileId(pub String);
pub struct ChunkId(pub u64);
pub struct ChunkSize(pub u64);
pub struct ByteCount(pub u64);

pub enum TransferDirection {
    Send,
    Receive,
}

pub enum ConnectionMode {
    TcpIpv6,
    QuicDirect,
    Relay,
    ServerFallback,
}
```

Should expose:

- identifiers;
- small value types;
- protocol version type;
- shared enums.

Should not expose:

- networking;
- crypto implementation;
- filesystem logic;
- CLI-specific formatting.

### 6.2 `envoix-error`

Purpose: shared error categories.

Public interface:

```rust
pub enum CoreError {
    InvalidInput(String),
    Io(String),
    Protocol(String),
    Transport(String),
    Crypto(String),
    Storage(String),
    Discovery(String),
    Transfer(String),
    Cancelled,
}
```

In the minimal version, lower crates may keep local errors and convert upward. By the final architecture, the public facade should expose a stable `PublicError`.

Recommendation:

- use `thiserror` in library crates;
- use `anyhow` only at binary edges if desired.


### 6.3 `envoix-crypto`

Purpose: cryptographic interface and placeholder implementation.

Minimal public interface:

```rust
pub trait CryptoProvider: Send + Sync {
    fn encrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

pub struct InsecureNoopCryptoProvider;
```

Minimal behavior:

- `InsecureNoopCryptoProvider::encrypt_chunk()` returns the input bytes.
- `InsecureNoopCryptoProvider::decrypt_chunk()` returns the input bytes.
- The type name must include `InsecureNoop` to prevent accidental production use.

Final behavior:

- authenticated encryption for chunks;
- manifest encryption;
- identity key handling;
- session key derivation;
- signing/verification;
- secure random generation;
- secret zeroization.


### 6.4 `envoix-protocol`

Purpose: wire messages and frame codec.

Minimal public interface:

```rust
pub enum Frame {
    Hello(Hello),
    Ready(Ready),
    FileHeader(FileHeader),
    ResumeStatus(ResumeStatus),
    Chunk(Chunk),
    Complete(Complete),
    CompleteAck(CompleteAck),
    Error(ErrorFrame),
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtocolError>
where
    R: AsyncRead + Unpin;

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin;
```

Minimal protocol flow:

```text
sender   → receiver: Hello
receiver → sender:   Ready
sender   → receiver: FileHeader
receiver → sender:   ResumeStatus
sender   → receiver: Chunk*
sender   → receiver: Complete
receiver → sender:   CompleteAck
```

Should expose:

- frame types;
- encoder/decoder;
- protocol version constants;
- maybe a tiny state validator.

Should not expose:

- TCP sockets;
- file I/O;
- encryption internals;
- CLI commands.

### 6.5 `envoix-transport`

Purpose: abstract transport traits.

Public interface:

```rust
pub enum ConnectionCandidate {
    TcpIpv6 { addr: SocketAddr },
}

#[async_trait]
pub trait FrameConnection: Send {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError>;
    async fn recv_frame(&mut self) -> Result<Frame, TransportError>;
    async fn close(&mut self) -> Result<(), TransportError>;
}

#[async_trait]
pub trait TransportDialer: Send + Sync {
    async fn dial(
        &self,
        candidate: ConnectionCandidate,
    ) -> Result<Box<dyn FrameConnection>, TransportError>;
}

#[async_trait]
pub trait TransportListener: Send + Sync {
    async fn accept(&self) -> Result<Box<dyn FrameConnection>, TransportError>;
}
```

Should expose:

- transport traits;
- connection candidates;
- transport diagnostics;
- connection mode metadata.

Should not expose:

- concrete TCP implementation;
- QUIC implementation;
- relay implementation;
- app-specific command handling.

Remarks: We choose to implement the application level protocol ourselves for better flexibility. 

### 6.6 `envoix-transport-tcp`

Purpose: minimal IPv6 TCP implementation.

Public interface:

```rust
pub struct TcpIpv6Dialer;

impl TransportDialer for TcpIpv6Dialer { ... }

pub struct TcpIpv6Listener;

impl TcpIpv6Listener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError>;
}

impl TransportListener for TcpIpv6Listener { ... }
```

Should expose:

- concrete `TcpIpv6Dialer`;
- concrete `TcpIpv6Listener`.

Should not expose:

- transfer logic;
- CLI commands;
- crypto logic.

This crate is replaceable. Later, `envoix-transport-quic`, `envoix-transport-relay`, and `envoix-transport-server` should implement compatible abstractions.

### 6.6.1 `envoix-transport-quic`

Current implementation:

- `QuicDialer`;
- `QuicListener`;
- one bidirectional QUIC stream per transfer;
- length-prefixed protocol frames over that stream.

Security caveat:

- generated self-signed certificates;
- explicitly insecure no-auth verifier;
- suitable only for the current unauthenticated skeleton, not production security.


### 6.7 `envoix-discovery`

Purpose: find connection candidates.

Minimal public interface:

```rust
pub struct ManualPeerDiscovery {
    peer_addr: SocketAddr,
}

impl ManualPeerDiscovery {
    pub fn new(peer_addr: SocketAddr) -> Self;
}

pub trait DiscoveryProvider: Send + Sync {
    fn discover(&self) -> Result<Vec<ConnectionCandidate>, DiscoveryError>;
}
```

Minimal behavior:

- return exactly the manually supplied IPv6 address.

Final behavior:

- LAN discovery;
- mDNS/Bonjour;
- IPv6 candidate discovery;
- server rendezvous candidate exchange;
- relay candidate generation;
- candidate ranking.

Should not transfer files.

---

### 6.8 `envoix-storage`

Purpose: local file and transfer-state storage.

Minimal public interface:

```rust
pub struct LocalFileStorage;

impl LocalFileStorage {
    pub async fn open_source(path: &Path) -> Result<tokio::fs::File, StorageError>;

    pub async fn create_temp_destination(
        output_dir: &Path,
        file_name: &str,
    ) -> Result<(PathBuf, tokio::fs::File), StorageError>;

    pub async fn finalize_temp_file(
        temp_path: &Path,
        final_path: &Path,
    ) -> Result<(), StorageError>;
}
```

For the minimal version, this can be concrete rather than trait-heavy.

Final public interface should include traits:

```rust
#[async_trait]
pub trait SourceFileStore { ... }

#[async_trait]
pub trait DestinationFileStore { ... }

#[async_trait]
pub trait TransferStateStore { ... }
```

Final behavior:

- safe temp-file creation;
- atomic finalize where possible;
- transfer-state persistence;
- chunk bitmap persistence;
- peer/device/key storage;
- platform-specific storage adapters for mobile.


### 6.9 `envoix-transfer`

Purpose: sender/receiver file-transfer state machine.

Minimal public interface:

```rust
pub struct TransferEngine<C> {
    crypto: C,
    chunk_size: usize,
}

impl<C> TransferEngine<C>
where
    C: CryptoProvider,
{
    pub async fn send_file(
        &self,
        connection: &mut dyn FrameConnection,
        path: PathBuf,
        events: &dyn EventSink,
    ) -> Result<TransferSummary, TransferError>;

    pub async fn receive_file(
        &self,
        connection: &mut dyn FrameConnection,
        output_dir: PathBuf,
        events: &dyn EventSink,
    ) -> Result<TransferSummary, TransferError>;
}
```

Minimal behavior:

- one file;
- sequential chunks;
- no resume;
- no hash verification;
- no parallelism;
- temp file then final rename;
- progress events.

Should expose:

- transfer requests;
- transfer summaries;
- transfer events;
- sender/receiver engine.

Should not expose:

- concrete transport types;
- CLI formatting;
- server routes.

### 6.10 `envoix-session`

Purpose: orchestration.

Minimal public interface:

```rust
pub struct SessionConfig {
    pub chunk_size: usize,
}

pub async fn send_file_manual_ipv6(
    peer_addr: SocketAddr,
    file_path: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError>;

pub async fn receive_file_ipv6(
    listen_addr: SocketAddr,
    output_dir: PathBuf,
    config: SessionConfig,
    events: Box<dyn EventSink>,
) -> Result<TransferSummary, SessionError>;
```

Minimal behavior:

- create manual discovery provider;
- create TCP IPv6 dialer/listener;
- create insecure noop crypto provider;
- create transfer engine;
- invoke send/receive flow.

Final behavior:

- create receive sessions;
- generate invites;
- run candidate races;
- select transport fallback;
- call transfer engine;
- surface public events.

This is the crate that is allowed to assemble concrete implementations.

### 6.11 `envoix-client`

Purpose: public app-facing facade.

The CLI should depend on this crate.

Minimal public interface:

```rust
pub struct EnvoixClient {
    config: ClientConfig,
}

impl EnvoixClient {
    pub fn new(config: ClientConfig) -> Self;

    pub async fn send_file(
        &self,
        request: SendFileRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError>;

    pub async fn receive_file(
        &self,
        request: ReceiveFileRequest,
        events: Box<dyn EventSink>,
    ) -> Result<TransferSummary, PublicError>;
}
```

This facade should convert low-level errors into stable public errors.

The CLI should not know about:

- `Frame`;
- `Hello`;
- `Chunk`;
- `TcpIpv6Dialer`;
- `InsecureNoopCryptoProvider`;
- `TransferEngine`.

### 6.12 `apps/envoix-cli`

Purpose: command-line application.

Minimal public behavior:

```bash
envoix send --peer "[::1]:9000" ./file.bin
envoix receive --listen "[::1]:9000" --output ./received
```

Responsibilities:

- parse command-line arguments;
- call `envoix-client`;
- render progress;
- render errors;
- set process exit code;
- configure logging.

Should not:

- implement transfer protocol;
- implement encryption;
- implement discovery;
- implement TCP framing.

## 7. How the minimal system chains together

### 7.1 Send flow

```text
User runs:
  envoix send --peer "[::1]:9000" ./hello.txt

apps/envoix-cli
  parses args with clap
  builds SendFileRequest
  creates ConsoleEventSink
  calls EnvoixClient::send_file()

envoix-client
  validates public request
  calls envoix-session::send_file_manual_ipv6()

envoix-session
  constructs ManualPeerDiscovery
  receives ConnectionCandidate::TcpIpv6
  constructs TcpIpv6Dialer
  dials receiver
  constructs InsecureNoopCryptoProvider
  constructs TransferEngine
  calls TransferEngine::send_file()

envoix-transfer
  sends protocol frames through FrameConnection
  reads source file in chunks
  calls crypto.encrypt_chunk()
  emits progress events
  sends Complete frame

envoix-transport-tcp
  writes frames to tokio TcpStream

receiver
  receives frames and writes file
```

### 7.2 Receive flow

```text
User runs:
  envoix receive --listen "[::1]:9000" --output ./received

apps/envoix-cli
  parses args
  creates ReceiveFileRequest
  calls EnvoixClient::receive_file()

envoix-client
  calls envoix-session::receive_file_ipv6()

envoix-session
  binds TcpIpv6Listener
  accepts one connection
  constructs InsecureNoopCryptoProvider
  constructs TransferEngine
  calls TransferEngine::receive_file()

envoix-transfer
  receives Hello
  sends Ready
  receives FileHeader
  creates temp output file
  sends FileHeaderAck
  receives Chunk frames
  calls crypto.decrypt_chunk()
  writes chunks sequentially
  receives Complete
  finalizes temp file
```

## 8. Minimal frame protocol

The initial protocol should be intentionally simple.

Recommended v0 frames:

```rust
pub enum Frame {
    Hello(Hello),
    Ready(Ready),
    FileHeader(FileHeader),
    FileHeaderAck(FileHeaderAck),
    Chunk(Chunk),
    Complete(Complete),
    Error(ErrorFrame),
}
```

Recommended fields:

```rust
pub struct Hello {
    pub protocol_version: u32,
    pub role: PeerRole,
}

pub struct FileHeader {
    pub transfer_id: TransferId,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u64,
}

pub struct Chunk {
    pub transfer_id: TransferId,
    pub index: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
}
```

For v0, chunks may arrive only in order. Later, when pause/resume and parallel chunk transfer are added, `Chunk` already has `index` and `offset`, so the protocol can evolve.

## 9. File transfer design

### 9.1 Minimal transfer

Minimal sender:

```text
open source file
send FileHeader
read chunk
encrypt_chunk()        // noop for v0
send Chunk
repeat
send Complete
```

Minimal receiver:

```text
receive FileHeader
create temp file
receive Chunk
decrypt_chunk()        // noop for v0
write chunk
repeat
receive Complete
flush temp file
rename temp file to final file
```

This gives a working pipeline.

### 9.2 Final transfer

Final sender:

```text
build manifest
derive session keys
encrypt manifest
send encrypted manifest
wait for receiver acceptance
read source chunks
hash chunks
encrypt chunks
send chunks according to scheduler
respond to missing-chunk requests
finalize transfer
```

Final receiver:

```text
receive encrypted manifest
decrypt manifest
ask user to accept
check disk space
create temp files
load previous chunk bitmap if resuming
request missing chunks
verify each chunk
write verified chunk
persist chunk bitmap
verify final root hash
atomically finalize files
```

### 9.3 Pause/resume

Pause/resume should be chunk-based, not byte-offset-only.

Receiver should persist:

```text
transfer_id
manifest_hash
file_id
chunk_size
verified_chunk_bitmap
bytes_completed
temp_file_path
final_file_path
```

On reconnect:

```text
receiver sends transfer_id + manifest_hash + verified chunk bitmap
sender sends only missing chunks
receiver verifies each incoming chunk
```

A future resumable protocol should add frames like:

```rust
pub enum Frame {
    ResumeRequest(ResumeRequest),
    MissingChunks(MissingChunks),
    ChunkAck(ChunkAck),
}
```

Do not add this in v0 unless needed.

### 9.4 Integrity

Current implementation:

- sender computes a whole-file BLAKE3 hash before sending `FileHeader`;
- receiver verifies the completed temp file before final rename;
- receiver sends `CompleteAck` only after final verification succeeds.

Deferred:

- per-chunk hash;
- chunk verification before write or before marking complete.

The final version should add:

- encrypted manifest containing expected hashes;
- root hash or hash tree;
- chunk-level verification;
- final root verification.

## 10. Final architecture

The final architecture expands the minimal workspace instead of replacing it.

```text
envoix/
├── apps/
│   ├── envoix-cli/
│   ├── envoix-server/
│   ├── envoix-ios/
│   └── envoix-android/
├── crates/
│   ├── envoix-client/
│   ├── envoix-ffi/
│   ├── envoix-session/
│   ├── envoix-transfer/
│   ├── envoix-manifest/
│   ├── envoix-protocol/
│   ├── envoix-identity/
│   ├── envoix-crypto/
│   ├── envoix-storage/
│   ├── envoix-discovery/
│   ├── envoix-transport/
│   ├── envoix-transport-tcp/
│   ├── envoix-transport-quic/
│   ├── envoix-transport-relay/
│   ├── envoix-transport-server/
│   ├── envoix-server-core/
│   ├── envoix-types/
│   ├── envoix-error/
│   └── envoix-testkit/
├── bindings/
│   ├── swift/
│   └── kotlin/
├── docs/
│   ├── protocol.md
│   ├── threat-model.md
│   ├── server-api.md
│   ├── mobile-integration.md
│   └── wire-format.md
└── tests/
    ├── transfer_loopback.rs
    ├── transfer_flaky.rs
    ├── resume.rs
    ├── crypto_vectors.rs
    ├── quic_lan.rs
    └── server_fallback.rs
```

Final dependency direction:

```text
apps/envoix-cli       ─┐
apps/envoix-ios       ├──► envoix-client
apps/envoix-android   ┘          │
                                 ▼
                           envoix-session
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
 envoix-discovery        envoix-transfer          concrete transports
        │                        │                        │
        ▼                        ▼                        ▼
 envoix-transport        envoix-protocol          quic/relay/server
                                 │
          ┌──────────────────────┼─────────────────────┐
          ▼                      ▼                     ▼
   envoix-crypto          envoix-manifest        envoix-storage
          │                      │                     │
          └──────────────┬───────┴──────────────┬──────┘
                         ▼                      ▼
                    envoix-types          envoix-error
```

Server side:

```text
apps/envoix-server
        ↓
envoix-server-core
        ↓
envoix-protocol / envoix-identity / envoix-storage / envoix-transport-relay
```

Mobile side:

```text
Swift UI / Kotlin UI
        ↓
generated bindings
        ↓
envoix-ffi
        ↓
envoix-client
        ↓
same core as CLI
```


## 11. Final crate additions

Contents in this part are subject to future changes.

### 11.1 `envoix-manifest`

Purpose:

- multi-file manifests;
- folder layout;
- encrypted metadata;
- chunk specs;
- hash roots;
- resume metadata.

Public API:

```rust
pub struct PlainManifest { ... }
pub struct EncryptedManifest { ... }
pub struct FileEntry { ... }
pub struct ChunkSpec { ... }

pub fn build_manifest(...) -> Result<PlainManifest, ManifestError>;
pub fn validate_manifest(...) -> Result<(), ManifestError>;
```

### 11.2 `envoix-identity`

Purpose:

- device identity;
- known peers;
- QR invite payload;
- signed receive offers;
- key-change detection.

Public API:

```rust
pub struct LocalDevice { ... }
pub struct TrustedPeer { ... }
pub struct ReceiveInvite { ... }

pub fn create_receive_invite(...) -> Result<ReceiveInvite, IdentityError>;
pub fn parse_receive_invite(...) -> Result<ReceiveInvite, IdentityError>;
pub fn verify_receive_invite(...) -> Result<(), IdentityError>;
```

### 11.3 `envoix-transport-quic`

Purpose:

- direct LAN/IPv6 QUIC transport;
- stream multiplexing;
- future replacement for minimal TCP path.

Public API:

```rust
pub struct QuicDialer;
pub struct QuicListener;
```

It should implement `TransportDialer` and `TransportListener`.


### 11.4 `envoix-transport-relay`

Purpose:

- relay-streaming fallback;
- encrypted traffic relay;
- connection tickets.

Public API:

```rust
pub struct RelayDialer;
pub struct RelayListener;
pub struct RelayTicket;
```

### 11.5 `envoix-transport-server`

Purpose:

- encrypted server-backed upload/download;
- store-and-forward fallback;
- background-friendly mobile transfer.

This may not fit exactly into `FrameConnection`. It may need a separate trait:

```rust
#[async_trait]
pub trait ObjectTransferBackend {
    async fn put_chunk(...);
    async fn get_chunk(...);
    async fn list_chunks(...);
}
```

Do not force server fallback into a live socket abstraction if it becomes unnatural.

### 11.6 `envoix-ffi`

Purpose:

- Swift/Kotlin bridge;
- mobile-safe public API;
- callback/event bridge;
- async runtime bridge.

Public API should be coarse:

```rust
pub struct MobileClient;

impl MobileClient {
    pub fn create_receive_invite(&self) -> Result<String, MobileError>;
    pub fn send_files(&self, request: MobileSendRequest) -> Result<String, MobileError>;
    pub fn cancel_transfer(&self, transfer_id: String) -> Result<(), MobileError>;
}
```

Do not expose protocol frames to mobile.

### 11.7 `envoix-testkit`

Purpose:

- fake transports;
- flaky connections;
- in-memory storage;
- deterministic test keys;
- corruption injection;
- integration-test helpers.

Public API:

```rust
pub struct MemoryFrameConnection;
pub struct FlakyConnection;
pub struct InMemoryStorage;
pub fn assert_files_equal(...);
```

This crate is critical for testing pause/resume and corruption handling.

## 12. Recommended crates and tools

This section is advisory. Pin exact versions in `Cargo.toml` after testing.

### 12.1 Workspace and build

Use Cargo workspaces because the project has multiple related packages developed together.

Recommended:

- `cargo` workspace;
- one root `Cargo.lock`;
- shared dependency versions in `[workspace.dependencies]`;
- CI that runs `cargo fmt`, `cargo clippy`, and `cargo test --workspace`.

Reason:

- keeps core crates and app crates in one repo;
- makes dependency versions consistent;
- supports clean application/core separation.


### 12.2 Async runtime and networking

Recommended now:

- `tokio`

Reason:

- async TCP;
- async file I/O;
- timers;
- task spawning;
- broad ecosystem support.

Minimal version:

- `tokio::net::TcpListener`;
- `tokio::net::TcpStream`;
- `tokio::fs::File`.

Final version:

- keep Tokio as the runtime unless there is a strong reason to switch.

### 12.3 Frame encoding

Recommended minimal option:

- `tokio-util` `LengthDelimitedCodec`;
- `serde`;
- `serde_json` for early debugging or `bincode` for compact binary encoding.

Practical path:

1. Start with `serde_json` if debugging the protocol is more important than efficiency.
2. Move to `bincode` or another compact binary format once the flow is stable.
3. Keep protocol versioning independent of the chosen codec.

Reason:

- length-delimited framing avoids manual buffering bugs;
- Serde lets Rust structs map cleanly to wire messages;
- `bincode` is compact and appropriate for internal Rust-to-Rust protocol messages;
- JSON is larger, but useful during the first week of debugging.

### 12.4 Byte buffers

Recommended:

- `bytes`

Reason:

- useful when protocol and transport layers need efficient byte buffers;
- common in async networking crates.

Minimal version can use `Vec<u8>`. Move to `Bytes`/`BytesMut` when profiling or frame handling requires it.

### 12.5 CLI

Recommended:

- `clap` for command parsing;
- `indicatif` for progress bars/spinners;
- `tracing` + `tracing-subscriber` for logs.

Reason:

- `clap` handles subcommands and help output well;
- `indicatif` gives progress bars without contaminating core transfer logic;
- `tracing` gives structured logs usable across CLI, server, and tests.

CLI should own these dependencies. Do not leak them into transfer/protocol crates.

### 12.6 Errors

Recommended:

- `thiserror` in library crates;
- `anyhow` only in binaries/tests, if desired.

Reason:

- library crates should expose typed errors;
- application binaries can use dynamic errors for top-level plumbing;
- mobile FFI needs finite error categories, not arbitrary error chains.

### 12.7 File I/O and temp files

Recommended:

- `tokio::fs` for async file operations in the minimal version;
- `tempfile` for safe temp files in tests and possibly local writes;
- careful finalization strategy using temp path + rename.

Reason:

- receiver should not expose incomplete files as complete;
- temp files make interruption behavior predictable;
- atomic rename is the right finalization pattern when source and destination are on the same filesystem.

Caveat:

- mobile platforms may require platform-specific file abstractions later.

### 12.8 Hashing and integrity

Recommended:

- `blake3`

Reason:

- fast hashing;
- incremental hashing;
- useful for whole-file and per-chunk verification;
- useful future path toward tree/verified streaming designs.

Minimal version may skip it. The first integrity upgrade should add whole-file BLAKE3, then per-chunk BLAKE3.

### 12.9 Cryptography

Minimal version:

- `InsecureNoopCryptoProvider`.

Final candidates:

- `rand` or OS RNG wrappers for randomness;
- `zeroize` for secret memory cleanup;
- `x25519-dalek` for X25519 key agreement if building custom key exchange;
- AEAD crates such as `chacha20poly1305` or another audited AEAD implementation;
- consider HPKE-style design rather than ad-hoc encryption.

Rule:

- keep all crypto choices behind `envoix-crypto`;
- do not let protocol, transfer, CLI, or mobile code call raw crypto primitives directly.

### 12.10 Direct P2P / QUIC

Final candidates:

- `quinn` if implementing your own QUIC-based direct transport;
- `iroh` if using a higher-level P2P stack with relay/hole-punching support;
- evaluate `iroh-blobs` for verified blob transfer, but do not blindly adopt it until version stability and mobile behavior are tested.

Recommended path:

1. Minimal: IPv6 TCP.
2. Next: `quinn` direct QUIC prototype.
3. Parallel evaluation: `iroh` for final P2P transport.
4. Decide whether `envoix-transfer` remains custom or delegates blob transfer to `iroh-blobs`.

### 12.11 Server

Final candidates:

- `axum` for HTTP API;
- `sqlx` for SQLite/Postgres;
- `reqwest` for client-side HTTP fallback;
- `rustls` for TLS where explicit TLS stack control is needed.

Server should be boring:

- one binary;
- SQLite default;
- Postgres optional;
- filesystem object store default;
- S3-compatible object store optional later.

### 12.12 Mobile bindings

Final candidate:

- `uniffi`

Reason:

- generate Swift/Kotlin bindings from a Rust library;
- keep Swift/Kotlin focused on UI and platform integration;
- share protocol/transfer/session logic.

Mobile should depend on:

```text
Swift/Kotlin UI
  ↓
UniFFI-generated bindings
  ↓
envoix-ffi
  ↓
envoix-client
```

Mobile should not bind directly to `envoix-protocol` or `envoix-transfer`.

## 13. Minimal implementation order

### Step 1: workspace and empty crates

Deliverable:

```text
cargo test --workspace
cargo run -p envoix-cli -- --help
```

### Step 2: protocol frame codec

Deliverable:

- `Frame` enum;
- encode/decode tests;
- max frame size;
- protocol version constant.

### Step 3: transport abstraction and IPv6 TCP

Deliverable:

- `FrameConnection` trait;
- `TcpIpv6Dialer`;
- `TcpIpv6Listener`;
- loopback test over `[::1]`.

### Step 4: noop crypto

Deliverable:

- `CryptoProvider`;
- `InsecureNoopCryptoProvider`;
- explicit warning in docs and type name.

### Step 5: transfer engine

Deliverable:

- sender sends one file;
- receiver writes one file;
- chunked transfer;
- temp file finalization;
- progress events.

### Step 6: session and client facade

Deliverable:

- `EnvoixClient::send_file()`;
- `EnvoixClient::receive_file()`;
- CLI depends only on `envoix-client`.

### Step 7: CLI

Deliverable:

```bash
envoix receive --listen "[::1]:9000" --output ./received
envoix send --peer "[::1]:9000" ./hello.txt
```

### Step 8: integration tests

Deliverable:

- spawn receiver;
- send file;
- compare bytes;
- test large file;
- test connection failure.

## 14. Public/private API policy

Each crate should document:

```text
Public API:
  Types/functions other crates are allowed to use.

Internal API:
  Modules/types that may change without notice.

Forbidden dependencies:
  Crates this crate must not import.
```

Example for `envoix-transfer`:

```text
Public API:
  TransferEngine
  SendRequest
  ReceiveRequest
  TransferSummary
  TransferEvent
  EventSink

Internal API:
  sender loop
  receiver loop
  chunk scheduler
  state validation

Forbidden dependencies:
  envoix-transport-tcp
  envoix-transport-quic
  envoix-cli
  envoix-server
  envoix-ffi
```

This discipline matters more than directory naming.

## 15. What should be stable early

Stabilize early:

- crate dependency direction;
- `envoix-client` facade shape;
- transfer event model;
- basic `FrameConnection` abstraction;
- basic `CryptoProvider` abstraction;
- transfer ID and chunk ID types.

Allowed to change early:

- concrete codec;
- exact frame fields;
- chunk size;
- progress bar formatting;
- CLI flags;
- internal transfer loop implementation.

Do not prematurely stabilize the full wire protocol. Stabilize the layer boundaries first.
