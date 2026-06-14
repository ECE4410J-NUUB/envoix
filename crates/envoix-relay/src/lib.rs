//! Relay data-plane logic - pure, no sockets.
//!
//! See `docs/relay-design.md` for the contract. The relay forwards opaque
//! QUIC datagrams between two peers of a session; it never decrypts and is
//! not a trust party. Module split per design §8:
//!
//! - [`token`] - shared-key HMAC relay tokens (TURN REST API precedent).
//! - [`frame`] - `magic || token || payload` datagram parsing.
//! - [`table`] - in-memory forwarding table: pairing, per-session cap,
//!   idle sweep.
//! - [`quota`] - monthly byte guard (counting + rollover; persistence is
//!   the binary's job).

pub mod frame;
pub mod quota;
pub mod table;
pub mod token;

pub use frame::{RELAY_HEADER_LEN, RELAY_MAGIC, RelayDatagram, encode};
pub use quota::MonthlyUsage;
pub use table::{ForwardOutcome, RelayConfig, RelayTable, RelayTableStats};
pub use token::{RELAY_TOKEN_LEN, RelayRole, RelaySessionId, RelayTokenKey};
