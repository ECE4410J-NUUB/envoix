//! Relay data-plane logic - pure, no sockets.
//!
//! The relay forwards opaque QUIC datagrams between two peers of a session;
//! it never decrypts and is not a trust party. Module split:
//!
//! - [`token`] - shared-key keyed-MAC relay tokens (TURN REST API precedent).
//! - [`frame`] - `magic || token || payload` datagram parsing.
//! - [`table`] - in-memory forwarding table: pairing, per-session cap,
//!   idle sweep.
//! - [`quota`] - monthly byte guard (counting + rollover; persistence is
//!   the binary's job).

pub mod frame;
pub mod quota;
pub mod table;
pub mod token;

pub use frame::{
    RELAY_HEADER_LEN, RELAY_MAGIC, RELAY_PROBE_LEN, RELAY_PROBE_MAGIC, RELAY_PROBE_NONCE_LEN,
    RelayDatagram, encode, encode_probe, parse_probe,
};
pub use quota::MonthlyUsage;
pub use table::{ForwardOutcome, RelayConfig, RelayTable, RelayTableStats};
pub use token::{RELAY_TOKEN_LEN, RelayRole, RelaySessionId, RelayTokenKey};
