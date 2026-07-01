//! SPAKE2 peer pairing: turn a short shared code into a confirmed key `K`, then
//! exchange peer descriptors sealed under `K` over an untrusted rendezvous.
//!
//! Two peers share a short, typeable code (the SPAKE2 password). SPAKE2 turns it
//! into a strong shared key `K` that the rendezvous (a blind mailbox) cannot
//! derive: offline guessing is impossible, online guessing is one attempt per
//! pairing, so the verifier caps attempts. Each peer then seals its iroh
//! descriptor under a key derived from `K`, so confidentiality and authenticity
//! come from `K` itself - the rendezvous never sees plaintext and cannot forge a
//! descriptor.
//!
//! Pure logic, no sockets: the caller drives the message exchange over whatever
//! transport carries the rendezvous mailbox.
//!
//! Parts: the SPAKE2 handshake + key confirmation (`handshake`), the sealed
//! bundle (`bundle`), and the length-prefixed framing (`wire`).

mod bundle;
mod handshake;
mod wire;

pub use bundle::{open, open_json, seal, seal_json};
pub use handshake::{
    Confirm, InitiatorConfirming, InitiatorPending, Paired, PakeResponse, PakeStart,
    ResponderConfirming, initiator_start, responder_respond,
};
pub use wire::{MAX_FRAME_BODY, frame, unframe};

/// Errors from the pairing protocol.
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("entropy source unavailable")]
    Entropy,
    #[error("sealed bundle is malformed or truncated")]
    Malformed,
    #[error("decryption failed: wrong pairing code or tampered data")]
    Decrypt,
    #[error("bundle is not valid JSON: {0}")]
    BadJson(String),
    #[error("SPAKE2 failed: {0}")]
    Spake2(String),
    #[error("key confirmation failed: wrong pairing code or tampered handshake")]
    Confirm,
    #[error("malformed handshake message: {0}")]
    BadMessage(String),
}
