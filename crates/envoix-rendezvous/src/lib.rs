//! Room rendezvous broker.
//!
//! Two peers that share a short code both connect to the broker and present the
//! same room id. The broker matches them, tells each its SPAKE2 role
//! ([`Role::Initiator`] / [`Role::Responder`]), then **blindly relays raw bytes**
//! between them. The end-to-end pairing (SPAKE2 + sealed peer descriptors, see
//! `envoix-pairing`) runs *through* this relay, so the broker never sees
//! plaintext and cannot forge or swap a descriptor - it is an untrusted mailbox.
//!
//! Transport-agnostic: a peer connection is a [`PeerConn`] over any
//! `AsyncRead`/`AsyncWrite` halves (iroh streams in production, an in-memory
//! duplex in tests).

mod broker;
mod io;
mod peer;
mod protocol;

pub use broker::RoomRegistry;
pub use io::{read_framed, write_framed};
pub use peer::{CloseWaiter, PeerConn};
pub use protocol::{Join, Paired, Role};

/// Errors from the rendezvous broker.
#[derive(Debug, thiserror::Error)]
pub enum RendezvousError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed control message: {0}")]
    BadMessage(String),
    #[error("control frame exceeds the size limit")]
    FrameTooLarge,
    #[error("pairing window expired before a partner joined the room")]
    Expired,
}
