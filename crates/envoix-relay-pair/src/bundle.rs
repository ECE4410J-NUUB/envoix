//! The sealed credential bundle.
//!
//! Given the SPAKE2 shared key `K`, derive a one-shot AEAD key with the BLAKE3
//! KDF and seal the relay's credentials with ChaCha20-Poly1305. Confidentiality and
//! integrity come from `K`: an attacker who could not derive `K` (no pairing
//! code) can neither read nor forge the bundle.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

use crate::PairError;

/// BLAKE3 KDF context separating this key from any other use of `K`.
const BUNDLE_KEY_CONTEXT: &str = "envoix-relay-pair bundle key v1";

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// Relay credentials delivered to a client over the confirmed pairing
/// channel - the secret deliberately kept out of the QR/word-code.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RelayProvision {
    /// 64-hex relay master key the client uses to mint relay tokens.
    pub key: String,
    /// Inclusive `[first, last]` data-port range, or `None` for a single port.
    pub ports: Option<[u16; 2]>,
}

/// Derive the one-shot AEAD key from the SPAKE2 shared key `k` (BLAKE3 KDF).
fn bundle_key(k: &[u8]) -> Key {
    Key::from(blake3::derive_key(BUNDLE_KEY_CONTEXT, k))
}

/// Seal `plaintext` under a key derived from the SPAKE2 key `k`. The output is
/// `nonce(12) || ciphertext+tag`, safe to send over a cleartext channel.
pub fn seal(k: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PairError> {
    let cipher = ChaCha20Poly1305::new(&bundle_key(k));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| PairError::Entropy)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| PairError::Decrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a bundle produced by [`seal`] with the same `k`. Fails if `k` is wrong
/// or the bytes were tampered with.
pub fn open(k: &[u8], sealed: &[u8]) -> Result<Vec<u8>, PairError> {
    if sealed.len() < NONCE_LEN {
        return Err(PairError::Malformed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(&bundle_key(k));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| PairError::Decrypt)
}

/// Seal a [`RelayProvision`] (JSON) under `k`.
pub fn seal_provision(k: &[u8], provision: &RelayProvision) -> Result<Vec<u8>, PairError> {
    let json = serde_json::to_vec(provision).map_err(|e| PairError::BadJson(e.to_string()))?;
    seal(k, &json)
}

/// Open a [`RelayProvision`] sealed by [`seal_provision`] with the same `k`.
pub fn open_provision(k: &[u8], sealed: &[u8]) -> Result<RelayProvision, PairError> {
    let json = open(k, sealed)?;
    serde_json::from_slice(&json).map_err(|e| PairError::BadJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &[u8] = b"a 32-byte-ish spake2 shared key!"; // stand-in for SPAKE2 K

    #[test]
    fn round_trips_bytes() {
        let sealed = seal(K, b"hello relay").unwrap();
        // nonce(12) + ciphertext + 16-byte tag, never the plaintext in clear.
        assert!(sealed.len() >= NONCE_LEN + 16);
        assert!(!sealed.windows(11).any(|w| w == b"hello relay"));
        assert_eq!(open(K, &sealed).unwrap(), b"hello relay");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(K, b"secret").unwrap();
        assert!(matches!(open(b"a different 32-ish wrong key!!!!", &sealed), Err(PairError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(K, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(open(K, &sealed), Err(PairError::Decrypt)));
    }

    #[test]
    fn truncated_fails() {
        assert!(matches!(open(K, &[0u8; 4]), Err(PairError::Malformed)));
    }

    #[test]
    fn fresh_nonce_each_seal() {
        // Same key + plaintext must not produce identical ciphertext.
        assert_ne!(seal(K, b"x").unwrap(), seal(K, b"x").unwrap());
    }

    #[test]
    fn provision_round_trips() {
        let p = RelayProvision {
            key: "ab".repeat(32),
            ports: Some([9100, 9105]),
        };
        let sealed = seal_provision(K, &p).unwrap();
        assert_eq!(open_provision(K, &sealed).unwrap(), p);
        // single-port variant.
        let p2 = RelayProvision { key: "cd".repeat(32), ports: None };
        assert_eq!(open_provision(K, &seal_provision(K, &p2).unwrap()).unwrap(), p2);
    }
}
