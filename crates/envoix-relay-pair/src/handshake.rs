//! SPAKE2 handshake + key confirmation, as a transport-agnostic state machine.
//!
//! The client initiates (`start_a`), the relay responds (`start_b`); both
//! derive the shared key `K`. Then each proves possession of `K` with a
//! **keyed-BLAKE3** MAC over a transcript of the handshake (matching the
//! codebase's keyed-MAC primitive, not HMAC). Proofs are compared with
//! constant-time `blake3::Hash` equality. There is no transport channel
//! binding: confidentiality of what follows comes from `K` (see `bundle`).
//!
//! The caller drives the message exchange over whatever transport it likes;
//! this module never touches sockets.

use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::PairError;

/// Per-protocol domain separation, woven into the confirmation transcript.
const DOMAIN: &[u8] = b"envoix-relay-pair-spake2-v1";
/// SPAKE2 identity strings (same order on both sides; role set by start_a/b).
const CLIENT_ID: &[u8] = b"envoix relay pairing client";
const RELAY_ID: &[u8] = b"envoix relay pairing relay";
/// BLAKE3 KDF context for the confirmation key (distinct from the bundle key).
const CONFIRM_KEY_CONTEXT: &str = "envoix-relay-pair confirm key v1";
/// Role labels so the two confirmation proofs can't be swapped.
const CLIENT_CONFIRM_LABEL: &[u8] = b"client-confirm";
const RELAY_CONFIRM_LABEL: &[u8] = b"relay-confirm";

/// Confirmation nonce length (128 bits).
const NONCE_LEN: usize = 16;

/// Client's opening message: its nonce and SPAKE2 message.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PakeStart {
    pub nonce: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Relay's reply: its nonce and SPAKE2 message.
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

/// The confirmed shared key. The caller uses it to seal/open the bundle.
pub struct Paired {
    key: Vec<u8>,
}

impl Paired {
    /// The SPAKE2 shared key `K`.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

fn random_nonce() -> Result<Vec<u8>, PairError> {
    let mut nonce = vec![0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| PairError::Entropy)?;
    Ok(nonce)
}

/// Length-prefixed transcript over the whole handshake (no exporter).
fn transcript(client: &PakeStart, relay: &PakeResponse) -> Vec<u8> {
    let mut t = Vec::new();
    for part in [
        DOMAIN,
        CLIENT_ID,
        RELAY_ID,
        &client.nonce,
        &relay.nonce,
        &client.msg,
        &relay.msg,
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
fn verify(key: &[u8], transcript: &[u8], label: &[u8], received: &[u8]) -> Result<(), PairError> {
    let received: [u8; 32] = received.try_into().map_err(|_| PairError::Confirm)?;
    // blake3::Hash equality is constant-time.
    if proof(key, transcript, label) == blake3::Hash::from_bytes(received) {
        Ok(())
    } else {
        Err(PairError::Confirm)
    }
}

// --- client (initiator) ---

/// Begin pairing as the client. Send the returned [`PakeStart`] to the relay.
pub fn client_start(password: &str) -> Result<(ClientPending, PakeStart), PairError> {
    let nonce = random_nonce()?;
    let (spake, msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(password.as_bytes()),
        &Identity::new(CLIENT_ID),
        &Identity::new(RELAY_ID),
    );
    let start = PakeStart { nonce, msg };
    Ok((ClientPending { spake, start: start.clone() }, start))
}

/// Client state awaiting the relay's [`PakeResponse`].
pub struct ClientPending {
    spake: Spake2<Ed25519Group>,
    start: PakeStart,
}

impl ClientPending {
    /// Finish SPAKE2 and produce the client's [`Confirm`] to send.
    pub fn finish(self, response: &PakeResponse) -> Result<(ClientConfirming, Confirm), PairError> {
        if response.nonce.len() != NONCE_LEN {
            return Err(PairError::BadMessage("relay nonce length".into()));
        }
        let key = self
            .spake
            .finish(&response.msg)
            .map_err(|e| PairError::Spake2(format!("{e:?}")))?;
        let transcript = transcript(&self.start, response);
        let mac = proof(&key, &transcript, CLIENT_CONFIRM_LABEL).as_bytes().to_vec();
        Ok((ClientConfirming { key, transcript }, Confirm { mac }))
    }
}

/// Client state awaiting the relay's confirmation.
pub struct ClientConfirming {
    key: Vec<u8>,
    transcript: Vec<u8>,
}

impl ClientConfirming {
    /// Verify the relay's [`Confirm`]; on success the key is confirmed.
    pub fn verify(self, relay_confirm: &Confirm) -> Result<Paired, PairError> {
        verify(&self.key, &self.transcript, RELAY_CONFIRM_LABEL, &relay_confirm.mac)?;
        Ok(Paired { key: self.key })
    }
}

// --- relay (responder) ---

/// Respond to a client's [`PakeStart`]. Send the returned [`PakeResponse`].
pub fn relay_respond(
    password: &str,
    start: &PakeStart,
) -> Result<(RelayConfirming, PakeResponse), PairError> {
    if start.nonce.len() != NONCE_LEN {
        return Err(PairError::BadMessage("client nonce length".into()));
    }
    let nonce = random_nonce()?;
    let (spake, msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password.as_bytes()),
        &Identity::new(CLIENT_ID),
        &Identity::new(RELAY_ID),
    );
    let key = spake
        .finish(&start.msg)
        .map_err(|e| PairError::Spake2(format!("{e:?}")))?;
    let response = PakeResponse { nonce, msg };
    let transcript = transcript(start, &response);
    Ok((RelayConfirming { key, transcript }, response))
}

/// Relay state awaiting the client's confirmation.
pub struct RelayConfirming {
    key: Vec<u8>,
    transcript: Vec<u8>,
}

impl RelayConfirming {
    /// Verify the client's [`Confirm`]; on success return the relay's own
    /// [`Confirm`] to send back and the confirmed key.
    pub fn verify(self, client_confirm: &Confirm) -> Result<(Paired, Confirm), PairError> {
        verify(&self.key, &self.transcript, CLIENT_CONFIRM_LABEL, &client_confirm.mac)?;
        let mac = proof(&self.key, &self.transcript, RELAY_CONFIRM_LABEL).as_bytes().to_vec();
        Ok((Paired { key: self.key }, Confirm { mac }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_provision, seal_provision, RelayProvision};

    const PW: &str = "42-galaxy-pencil";

    /// Drive a full successful handshake; returns both confirmed keys.
    fn run(client_pw: &str, relay_pw: &str) -> Result<(Vec<u8>, Vec<u8>), PairError> {
        let (client, start) = client_start(client_pw)?;
        let (relay, response) = relay_respond(relay_pw, &start)?;
        let (client_confirming, client_conf) = client.finish(&response)?;
        let (relay_paired, relay_conf) = relay.verify(&client_conf)?;
        let client_paired = client_confirming.verify(&relay_conf)?;
        Ok((client_paired.key().to_vec(), relay_paired.key().to_vec()))
    }

    #[test]
    fn matching_password_agrees_on_key() {
        let (ck, rk) = run(PW, PW).unwrap();
        assert_eq!(ck, rk);
        assert!(!ck.is_empty());
    }

    #[test]
    fn key_seals_the_bundle_both_ways() {
        let (client, start) = client_start(PW).unwrap();
        let (relay, response) = relay_respond(PW, &start).unwrap();
        let (client_confirming, client_conf) = client.finish(&response).unwrap();
        let (relay_paired, relay_conf) = relay.verify(&client_conf).unwrap();
        let client_paired = client_confirming.verify(&relay_conf).unwrap();

        let prov = RelayProvision { key: "ab".repeat(32), ports: Some([9100, 9105]) };
        let sealed = seal_provision(relay_paired.key(), &prov).unwrap();
        assert_eq!(open_provision(client_paired.key(), &sealed).unwrap(), prov);
    }

    #[test]
    fn wrong_password_fails_confirmation() {
        // SPAKE2 finish still succeeds (different K each side); confirmation
        // is what catches the mismatch.
        let (client, start) = client_start(PW).unwrap();
        let (relay, response) = relay_respond("99-wrong-words-here", &start).unwrap();
        let (_c, client_conf) = client.finish(&response).unwrap();
        assert!(matches!(relay.verify(&client_conf), Err(PairError::Confirm)));
    }

    #[test]
    fn tampered_client_confirm_rejected() {
        let (client, start) = client_start(PW).unwrap();
        let (relay, response) = relay_respond(PW, &start).unwrap();
        let (_c, mut client_conf) = client.finish(&response).unwrap();
        client_conf.mac[0] ^= 0x01;
        assert!(matches!(relay.verify(&client_conf), Err(PairError::Confirm)));
    }

    #[test]
    fn tampered_relay_confirm_rejected_by_client() {
        let (client, start) = client_start(PW).unwrap();
        let (relay, response) = relay_respond(PW, &start).unwrap();
        let (client_confirming, client_conf) = client.finish(&response).unwrap();
        let (_paired, mut relay_conf) = relay.verify(&client_conf).unwrap();
        relay_conf.mac[0] ^= 0x01;
        assert!(matches!(client_confirming.verify(&relay_conf), Err(PairError::Confirm)));
    }

    #[test]
    fn bad_nonce_length_rejected() {
        let (_client, mut start) = client_start(PW).unwrap();
        start.nonce.truncate(4);
        assert!(matches!(relay_respond(PW, &start), Err(PairError::BadMessage(_))));
    }
}
