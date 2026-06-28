//! SPAKE2 handshake + key confirmation, as a transport-agnostic state machine.
//!
//! The initiator opens (`initiator_start`); the responder replies
//! (`responder_respond`); both derive the shared key `K`. Then each proves
//! possession of `K` with a **keyed-BLAKE3** MAC over a transcript of the
//! handshake (the codebase's keyed-MAC primitive, not HMAC). Proofs are compared
//! with constant-time `blake3::Hash` equality. There is no transport channel
//! binding: confidentiality of what follows comes from `K` (see `bundle`).
//!
//! The caller drives the message exchange over whatever transport carries the
//! rendezvous mailbox; this module never touches sockets.

use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::PairingError;

/// Per-protocol domain separation, woven into the confirmation transcript.
const DOMAIN: &[u8] = b"envoix-pairing-spake2-v1";
/// SPAKE2 identity strings (same order on both sides; role set by start_a/b).
const INITIATOR_ID: &[u8] = b"envoix pairing initiator";
const RESPONDER_ID: &[u8] = b"envoix pairing responder";
/// BLAKE3 KDF context for the confirmation key (distinct from the bundle key).
const CONFIRM_KEY_CONTEXT: &str = "envoix-pairing confirm key v1";
/// Role labels so the two confirmation proofs can't be swapped.
const INITIATOR_CONFIRM_LABEL: &[u8] = b"initiator-confirm";
const RESPONDER_CONFIRM_LABEL: &[u8] = b"responder-confirm";

/// Confirmation nonce length (128 bits).
const NONCE_LEN: usize = 16;

/// Initiator's opening message: its nonce and SPAKE2 message.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PakeStart {
    pub nonce: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Responder's reply: its nonce and SPAKE2 message.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PakeResponse {
    pub nonce: Vec<u8>,
    pub msg: Vec<u8>,
}

/// A key-confirmation proof (a keyed-BLAKE3 tag).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Confirm {
    pub mac: Vec<u8>,
}

/// The confirmed shared key. The caller uses it to seal/open bundles.
pub struct Paired {
    key: Vec<u8>,
}

impl Paired {
    /// The SPAKE2 shared key `K`.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

fn random_nonce() -> Result<Vec<u8>, PairingError> {
    let mut nonce = vec![0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| PairingError::Entropy)?;
    Ok(nonce)
}

/// Length-prefixed transcript over the whole handshake (no exporter).
fn transcript(initiator: &PakeStart, responder: &PakeResponse) -> Vec<u8> {
    let mut t = Vec::new();
    for part in [
        DOMAIN,
        INITIATOR_ID,
        RESPONDER_ID,
        &initiator.nonce,
        &responder.nonce,
        &initiator.msg,
        &responder.msg,
    ] {
        t.extend_from_slice(&(part.len() as u64).to_be_bytes());
        t.extend_from_slice(part);
    }
    t
}

/// keyed-BLAKE3(confirm_key(K), transcript || label).
fn proof(key: &[u8], transcript: &[u8], label: &[u8]) -> blake3::Hash {
    let confirm_key = blake3::derive_key(CONFIRM_KEY_CONTEXT, key);
    let mut h = blake3::Hasher::new_keyed(&confirm_key);
    h.update(transcript);
    h.update(&(label.len() as u64).to_be_bytes());
    h.update(label);
    h.finalize()
}

/// Constant-time check that `received` is the expected proof.
fn verify(
    key: &[u8],
    transcript: &[u8],
    label: &[u8],
    received: &[u8],
) -> Result<(), PairingError> {
    let received: [u8; 32] = received.try_into().map_err(|_| PairingError::Confirm)?;
    // blake3::Hash equality is constant-time.
    if proof(key, transcript, label) == blake3::Hash::from_bytes(received) {
        Ok(())
    } else {
        Err(PairingError::Confirm)
    }
}

// --- initiator ---

/// Begin pairing as the initiator. Send the returned [`PakeStart`] to the peer.
pub fn initiator_start(password: &str) -> Result<(InitiatorPending, PakeStart), PairingError> {
    let nonce = random_nonce()?;
    let (spake, msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(password.as_bytes()),
        &Identity::new(INITIATOR_ID),
        &Identity::new(RESPONDER_ID),
    );
    let start = PakeStart { nonce, msg };
    Ok((
        InitiatorPending {
            spake,
            start: start.clone(),
        },
        start,
    ))
}

/// Initiator state awaiting the responder's [`PakeResponse`].
pub struct InitiatorPending {
    spake: Spake2<Ed25519Group>,
    start: PakeStart,
}

impl InitiatorPending {
    /// Finish SPAKE2 and produce the initiator's [`Confirm`] to send.
    pub fn finish(
        self,
        response: &PakeResponse,
    ) -> Result<(InitiatorConfirming, Confirm), PairingError> {
        if response.nonce.len() != NONCE_LEN {
            return Err(PairingError::BadMessage("responder nonce length".into()));
        }
        let key = self
            .spake
            .finish(&response.msg)
            .map_err(|e| PairingError::Spake2(format!("{e:?}")))?;
        let transcript = transcript(&self.start, response);
        let mac = proof(&key, &transcript, INITIATOR_CONFIRM_LABEL)
            .as_bytes()
            .to_vec();
        Ok((InitiatorConfirming { key, transcript }, Confirm { mac }))
    }
}

/// Initiator state awaiting the responder's confirmation.
pub struct InitiatorConfirming {
    key: Vec<u8>,
    transcript: Vec<u8>,
}

impl InitiatorConfirming {
    /// Verify the responder's [`Confirm`]; on success the key is confirmed.
    pub fn verify(self, responder_confirm: &Confirm) -> Result<Paired, PairingError> {
        verify(
            &self.key,
            &self.transcript,
            RESPONDER_CONFIRM_LABEL,
            &responder_confirm.mac,
        )?;
        Ok(Paired { key: self.key })
    }
}

// --- responder ---

/// Respond to an initiator's [`PakeStart`]. Send the returned [`PakeResponse`].
pub fn responder_respond(
    password: &str,
    start: &PakeStart,
) -> Result<(ResponderConfirming, PakeResponse), PairingError> {
    if start.nonce.len() != NONCE_LEN {
        return Err(PairingError::BadMessage("initiator nonce length".into()));
    }
    let nonce = random_nonce()?;
    let (spake, msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password.as_bytes()),
        &Identity::new(INITIATOR_ID),
        &Identity::new(RESPONDER_ID),
    );
    let key = spake
        .finish(&start.msg)
        .map_err(|e| PairingError::Spake2(format!("{e:?}")))?;
    let response = PakeResponse { nonce, msg };
    let transcript = transcript(start, &response);
    Ok((ResponderConfirming { key, transcript }, response))
}

/// Responder state awaiting the initiator's confirmation.
pub struct ResponderConfirming {
    key: Vec<u8>,
    transcript: Vec<u8>,
}

impl ResponderConfirming {
    /// Verify the initiator's [`Confirm`]; on success return the responder's own
    /// [`Confirm`] to send back and the confirmed key.
    pub fn verify(self, initiator_confirm: &Confirm) -> Result<(Paired, Confirm), PairingError> {
        verify(
            &self.key,
            &self.transcript,
            INITIATOR_CONFIRM_LABEL,
            &initiator_confirm.mac,
        )?;
        let mac = proof(&self.key, &self.transcript, RESPONDER_CONFIRM_LABEL)
            .as_bytes()
            .to_vec();
        Ok((Paired { key: self.key }, Confirm { mac }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_json, seal_json};

    const PW: &str = "42-galaxy-pencil";

    /// Drive a full successful handshake; returns both confirmed keys.
    fn run(initiator_pw: &str, responder_pw: &str) -> Result<(Vec<u8>, Vec<u8>), PairingError> {
        let (initiator, start) = initiator_start(initiator_pw)?;
        let (responder, response) = responder_respond(responder_pw, &start)?;
        let (initiator_confirming, initiator_conf) = initiator.finish(&response)?;
        let (responder_paired, responder_conf) = responder.verify(&initiator_conf)?;
        let initiator_paired = initiator_confirming.verify(&responder_conf)?;
        Ok((
            initiator_paired.key().to_vec(),
            responder_paired.key().to_vec(),
        ))
    }

    #[test]
    fn matching_password_agrees_on_key() {
        let (ik, rk) = run(PW, PW).unwrap();
        assert_eq!(ik, rk);
        assert!(!ik.is_empty());
    }

    #[test]
    fn key_seals_a_bundle_both_ways() {
        let (initiator, start) = initiator_start(PW).unwrap();
        let (responder, response) = responder_respond(PW, &start).unwrap();
        let (initiator_confirming, initiator_conf) = initiator.finish(&response).unwrap();
        let (responder_paired, responder_conf) = responder.verify(&initiator_conf).unwrap();
        let initiator_paired = initiator_confirming.verify(&responder_conf).unwrap();

        // Each side seals a value the other opens with the same confirmed key.
        let from_initiator = vec!["addr-a".to_string()];
        let sealed = seal_json(initiator_paired.key(), b"aad", &from_initiator).unwrap();
        assert_eq!(
            open_json::<Vec<String>>(responder_paired.key(), b"aad", &sealed).unwrap(),
            from_initiator
        );
    }

    #[test]
    fn wrong_password_fails_confirmation() {
        // SPAKE2 finish still succeeds (different K each side); confirmation
        // is what catches the mismatch.
        let (initiator, start) = initiator_start(PW).unwrap();
        let (responder, response) = responder_respond("99-wrong-words-here", &start).unwrap();
        let (_c, initiator_conf) = initiator.finish(&response).unwrap();
        assert!(matches!(
            responder.verify(&initiator_conf),
            Err(PairingError::Confirm)
        ));
    }

    #[test]
    fn tampered_initiator_confirm_rejected() {
        let (initiator, start) = initiator_start(PW).unwrap();
        let (responder, response) = responder_respond(PW, &start).unwrap();
        let (_c, mut initiator_conf) = initiator.finish(&response).unwrap();
        initiator_conf.mac[0] ^= 0x01;
        assert!(matches!(
            responder.verify(&initiator_conf),
            Err(PairingError::Confirm)
        ));
    }

    #[test]
    fn tampered_responder_confirm_rejected_by_initiator() {
        let (initiator, start) = initiator_start(PW).unwrap();
        let (responder, response) = responder_respond(PW, &start).unwrap();
        let (initiator_confirming, initiator_conf) = initiator.finish(&response).unwrap();
        let (_paired, mut responder_conf) = responder.verify(&initiator_conf).unwrap();
        responder_conf.mac[0] ^= 0x01;
        assert!(matches!(
            initiator_confirming.verify(&responder_conf),
            Err(PairingError::Confirm)
        ));
    }

    #[test]
    fn bad_nonce_length_rejected() {
        let (_initiator, mut start) = initiator_start(PW).unwrap();
        start.nonce.truncate(4);
        assert!(matches!(
            responder_respond(PW, &start),
            Err(PairingError::BadMessage(_))
        ));
    }
}
