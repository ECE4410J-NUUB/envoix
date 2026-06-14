//! Relay authorization tokens: stateless, shared-key keyed MAC.
//!
//! Design pointers (`docs/relay-design.md`):
//! - §3.1 - byte layout; the key is a **shared, persistent** secret
//!   configured identically in the home issuer and the VPS validator
//!   (TURN REST API / coturn `use-auth-secret` precedent). This is the
//!   one difference from the probe token, whose key is per-process random.
//! - §4.2 - verification is silent-drop: failures return `None`.
//!
//! The token authorises *relay use* for a session+role. It is unrelated
//! to the transfer's end-to-end encryption key, which the relay never
//! possesses (the relay forwards opaque QUIC).

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SESSION_LEN: usize = 16;
/// payload = session_id(16) || role(1) || expires_at(8, u64 BE unix-seconds)
const PAYLOAD_LEN: usize = SESSION_LEN + 1 + 8;
const TAG_LEN: usize = 32;
pub const RELAY_TOKEN_LEN: usize = PAYLOAD_LEN + TAG_LEN; // 57

/// Opaque pairing key. The relay treats the session id as 16 bytes with
/// no semantics of its own - it is only a HashMap key for pairing the two
/// peers. The home server supplies the rendezvous session's bytes.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct RelaySessionId([u8; SESSION_LEN]);

impl RelaySessionId {
    pub fn from_bytes(bytes: [u8; SESSION_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_LEN] {
        &self.0
    }
}

impl fmt::Debug for RelaySessionId {
    /// First 8 hex chars only - a stable short ref for logs (not secret,
    /// just tidy and consistent with the rendezvous `session_ref`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelaySessionRef({:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Which peer a token (and thus a forwarding slot) belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayRole {
    Receiver,
    Sender,
}

impl RelayRole {
    fn to_byte(self) -> u8 {
        match self {
            RelayRole::Receiver => 0x01,
            RelayRole::Sender => 0x02,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(RelayRole::Receiver),
            0x02 => Some(RelayRole::Sender),
            _ => None,
        }
    }

    /// The slot a datagram of this role should be forwarded *to*.
    pub fn peer(self) -> RelayRole {
        match self {
            RelayRole::Receiver => RelayRole::Sender,
            RelayRole::Sender => RelayRole::Receiver,
        }
    }
}

/// MAC key for relay tokens. Shared between the home issuer and the VPS
/// validator; persistent (configured, not random) so a token minted at
/// home validates on the VPS and survives restarts of either.
pub struct RelayTokenKey {
    key: [u8; 32],
}

impl RelayTokenKey {
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Parse a 64-char hex secret (the deployment config form).
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self { key })
    }

    pub fn mint(
        &self,
        session: &RelaySessionId,
        role: RelayRole,
        expires_at: SystemTime,
    ) -> [u8; RELAY_TOKEN_LEN] {
        let secs = expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let mut token = [0u8; RELAY_TOKEN_LEN];
        token[..SESSION_LEN].copy_from_slice(session.as_bytes());
        token[SESSION_LEN] = role.to_byte();
        token[SESSION_LEN + 1..PAYLOAD_LEN].copy_from_slice(&secs.to_be_bytes());
        let tag = blake3::keyed_hash(&self.key, &token[..PAYLOAD_LEN]);
        token[PAYLOAD_LEN..].copy_from_slice(tag.as_bytes());
        token
    }

    /// Verify a token from a data-plane datagram. `None` on any failure
    /// (length, tag, unknown role, expiry past) - callers drop silently.
    pub fn verify(&self, token: &[u8]) -> Option<(RelaySessionId, RelayRole, SystemTime)> {
        if token.len() != RELAY_TOKEN_LEN {
            return None;
        }
        let (payload, claimed_tag) = token.split_at(PAYLOAD_LEN);

        // Tag first: nothing in the payload is trusted until the MAC
        // passes. blake3::Hash equality is constant-time.
        let real_tag = blake3::keyed_hash(&self.key, payload);
        let claimed = blake3::Hash::from_bytes(claimed_tag.try_into().ok()?);
        if real_tag != claimed {
            return None;
        }

        let mut sid = [0u8; SESSION_LEN];
        sid.copy_from_slice(&payload[..SESSION_LEN]);
        let role = RelayRole::from_byte(payload[SESSION_LEN])?;
        let secs = u64::from_be_bytes(payload[SESSION_LEN + 1..PAYLOAD_LEN].try_into().ok()?);
        let expires_at = UNIX_EPOCH + Duration::from_secs(secs);
        if expires_at <= SystemTime::now() {
            return None;
        }
        Some((RelaySessionId::from_bytes(sid), role, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RelayTokenKey {
        RelayTokenKey::from_bytes([7u8; 32])
    }

    fn sid() -> RelaySessionId {
        RelaySessionId::from_bytes([0x11; 16])
    }

    fn far_future() -> SystemTime {
        SystemTime::now() + Duration::from_secs(600)
    }

    #[test]
    fn token_len_is_57() {
        assert_eq!(RELAY_TOKEN_LEN, 57);
    }

    #[test]
    fn mint_verify_round_trip() {
        let k = key();
        let token = k.mint(&sid(), RelayRole::Sender, far_future());
        let (got_sid, got_role, _) = k.verify(&token).expect("valid");
        assert_eq!(got_sid, sid());
        assert_eq!(got_role, RelayRole::Sender);
    }

    #[test]
    fn shared_key_validates_across_instances() {
        // The defining property: a token minted by one key instance
        // verifies on a *separate* instance built from the same bytes
        // (home mints, VPS validates).
        let home = RelayTokenKey::from_bytes([42u8; 32]);
        let vps = RelayTokenKey::from_bytes([42u8; 32]);
        let token = home.mint(&sid(), RelayRole::Receiver, far_future());
        assert!(vps.verify(&token).is_some());
    }

    #[test]
    fn wrong_key_rejected() {
        let token =
            RelayTokenKey::from_bytes([1u8; 32]).mint(&sid(), RelayRole::Sender, far_future());
        assert!(
            RelayTokenKey::from_bytes([2u8; 32])
                .verify(&token)
                .is_none()
        );
    }

    #[test]
    fn tamper_any_byte_rejected() {
        let k = key();
        let token = k.mint(&sid(), RelayRole::Receiver, far_future());
        for i in 0..RELAY_TOKEN_LEN {
            let mut bad = token;
            bad[i] ^= 0x01;
            assert!(k.verify(&bad).is_none(), "tampered byte {i} accepted");
        }
    }

    #[test]
    fn expired_rejected() {
        let k = key();
        let token = k.mint(
            &sid(),
            RelayRole::Sender,
            SystemTime::now() - Duration::from_secs(1),
        );
        assert!(k.verify(&token).is_none());
    }

    #[test]
    fn wrong_length_rejected() {
        let k = key();
        let token = k.mint(&sid(), RelayRole::Sender, far_future());
        assert!(k.verify(&token[..56]).is_none());
        assert!(k.verify(&[]).is_none());
    }

    #[test]
    fn from_hex_round_trips() {
        let hex: String = (0..32).map(|_| "ab".to_string()).collect();
        let k = RelayTokenKey::from_hex(&hex).expect("valid hex");
        let token = k.mint(&sid(), RelayRole::Sender, far_future());
        // Same key from the same hex verifies.
        assert!(
            RelayTokenKey::from_hex(&hex)
                .unwrap()
                .verify(&token)
                .is_some()
        );
        assert!(RelayTokenKey::from_hex("tooshort").is_none());
    }

    #[test]
    fn role_peer_is_the_other_side() {
        assert_eq!(RelayRole::Receiver.peer(), RelayRole::Sender);
        assert_eq!(RelayRole::Sender.peer(), RelayRole::Receiver);
    }
}
