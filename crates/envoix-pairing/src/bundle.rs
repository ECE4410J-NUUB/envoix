//! The sealed bundle.
//!
//! Given the SPAKE2 shared key `K`, derive a one-shot AEAD key with the BLAKE3
//! KDF and seal a payload with ChaCha20-Poly1305. Confidentiality and integrity
//! come from `K`: a party that could not derive `K` (no pairing code) can
//! neither read nor forge the bundle - so the rendezvous mailbox, which only
//! sees ciphertext, cannot read or swap a peer's descriptor.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::PairingError;

/// BLAKE3 KDF context separating this key from any other use of `K`.
const BUNDLE_KEY_CONTEXT: &str = "envoix-pairing bundle key v1";

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// Derive the one-shot AEAD key from the SPAKE2 shared key `k` (BLAKE3 KDF).
fn bundle_key(k: &[u8]) -> Key {
    Key::from(blake3::derive_key(BUNDLE_KEY_CONTEXT, k))
}

/// Seal `plaintext` under a key derived from the SPAKE2 key `k`. The output is
/// `nonce(12) || ciphertext+tag`, safe to send over the cleartext mailbox.
pub fn seal(k: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PairingError> {
    let cipher = ChaCha20Poly1305::new(&bundle_key(k));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| PairingError::Entropy)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| PairingError::Decrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a bundle produced by [`seal`] with the same `k`. Fails if `k` is wrong
/// or the bytes were tampered with.
pub fn open(k: &[u8], sealed: &[u8]) -> Result<Vec<u8>, PairingError> {
    if sealed.len() < NONCE_LEN {
        return Err(PairingError::Malformed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(&bundle_key(k));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| PairingError::Decrypt)
}

/// Seal a serializable `value` (JSON) under `k`.
pub fn seal_json<T: Serialize>(k: &[u8], value: &T) -> Result<Vec<u8>, PairingError> {
    let json = serde_json::to_vec(value).map_err(|e| PairingError::BadJson(e.to_string()))?;
    seal(k, &json)
}

/// Open a value sealed by [`seal_json`] with the same `k`.
pub fn open_json<T: DeserializeOwned>(k: &[u8], sealed: &[u8]) -> Result<T, PairingError> {
    let json = open(k, sealed)?;
    serde_json::from_slice(&json).map_err(|e| PairingError::BadJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &[u8] = b"a 32-byte-ish spake2 shared key!"; // stand-in for SPAKE2 K

    #[test]
    fn round_trips_bytes() {
        let sealed = seal(K, b"hello peer").unwrap();
        // nonce(12) + ciphertext + 16-byte tag, never the plaintext in clear.
        assert!(sealed.len() >= NONCE_LEN + 16);
        assert!(!sealed.windows(10).any(|w| w == b"hello peer"));
        assert_eq!(open(K, &sealed).unwrap(), b"hello peer");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(K, b"secret").unwrap();
        assert!(matches!(
            open(b"a different 32-ish wrong key!!!!", &sealed),
            Err(PairingError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(K, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(open(K, &sealed), Err(PairingError::Decrypt)));
    }

    #[test]
    fn truncated_fails() {
        assert!(matches!(open(K, &[0u8; 4]), Err(PairingError::Malformed)));
    }

    #[test]
    fn fresh_nonce_each_seal() {
        // Same key + plaintext must not produce identical ciphertext.
        assert_ne!(seal(K, b"x").unwrap(), seal(K, b"x").unwrap());
    }

    #[test]
    fn json_round_trips() {
        let value = ("endpoint-id-abc".to_string(), vec!["10.0.0.1:9000".to_string()]);
        let sealed = seal_json(K, &value).unwrap();
        let got: (String, Vec<String>) = open_json(K, &sealed).unwrap();
        assert_eq!(got, value);
    }
}
