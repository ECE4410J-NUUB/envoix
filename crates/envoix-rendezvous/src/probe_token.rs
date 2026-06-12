//! Stateless probe tokens binding UDP probes to rendezvous sessions.
//!
//! Design pointers (`docs/reflexive-discovery-design.md`):
//! - §3.1 — byte layout, keyed-BLAKE3 tag, fixed-width fields.
//! - §4.1 — verification is silent-drop: failures return `None`, never a
//!   reply.
//!
//! The token is minted inside authenticated HTTPS responses and echoed
//! verbatim in plaintext UDP probes. It deliberately contains no secret
//! material — bearer capabilities never travel over UDP.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::state::SessionId;

/// payload = session_id(16) ‖ role(1) ‖ expires_at(8, u64 BE unix-seconds)
const PAYLOAD_LEN: usize = 16 + 1 + 8;
const TAG_LEN: usize = 32;
pub const PROBE_TOKEN_LEN: usize = PAYLOAD_LEN + TAG_LEN; // 57

/// Which peer a probe token (and thus an auto-published candidate)
/// belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeRole {
    Receiver,
    Sender,
}

impl ProbeRole {
    fn to_byte(self) -> u8 {
        match self {
            ProbeRole::Receiver => 0x01,
            ProbeRole::Sender => 0x02,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(ProbeRole::Receiver),
            0x02 => Some(ProbeRole::Sender),
            _ => None,
        }
    }
}

/// MAC key for probe tokens. Generated once per process; a restart
/// invalidates outstanding tokens together with the in-memory sessions
/// they reference, so nothing of value is lost.
pub struct ProbeTokenKey {
    key: [u8; 32],
}

impl ProbeTokenKey {
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("OS randomness unavailable");
        Self { key }
    }

    /// Mint a token for `(session, role)` expiring at `expires_at`.
    pub fn mint(
        &self,
        session_id: &SessionId,
        role: ProbeRole,
        expires_at: SystemTime,
    ) -> [u8; PROBE_TOKEN_LEN] {
        let unix_secs = expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let mut token = [0u8; PROBE_TOKEN_LEN];
        token[..16].copy_from_slice(session_id.as_bytes());
        token[16] = role.to_byte();
        token[17..25].copy_from_slice(&unix_secs.to_be_bytes());
        let tag = blake3::keyed_hash(&self.key, &token[..PAYLOAD_LEN]);
        token[PAYLOAD_LEN..].copy_from_slice(tag.as_bytes());
        token
    }

    /// Verify a token received in a UDP probe.
    ///
    /// Returns `None` on any failure — wrong length, bad tag, unknown
    /// role byte, or expiry in the past. Callers drop silently per
    /// design §4.1; no failure detail leaves this function.
    pub fn verify(&self, token: &[u8]) -> Option<(SessionId, ProbeRole, SystemTime)> {
        if token.len() != PROBE_TOKEN_LEN {
            return None;
        }
        let (payload, claimed_tag) = token.split_at(PAYLOAD_LEN);

        // Tag first: nothing about the payload is trusted until the MAC
        // passes. blake3::Hash::eq is constant-time.
        let real_tag = blake3::keyed_hash(&self.key, payload);
        if real_tag != *blake3::Hash::from_bytes(claimed_tag.try_into().ok()?).as_bytes() {
            return None;
        }

        let mut sid = [0u8; 16];
        sid.copy_from_slice(&payload[..16]);
        let role = ProbeRole::from_byte(payload[16])?;
        let unix_secs = u64::from_be_bytes(payload[17..25].try_into().ok()?);
        let expires_at = UNIX_EPOCH + Duration::from_secs(unix_secs);

        if expires_at <= SystemTime::now() {
            return None;
        }
        Some((SessionId::from_bytes(sid), role, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn far_future() -> SystemTime {
        SystemTime::now() + Duration::from_secs(600)
    }

    fn test_session_id() -> SessionId {
        SessionId::from_hex("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn mint_verify_round_trip() {
        let key = ProbeTokenKey::random();
        let sid = test_session_id();
        let token = key.mint(&sid, ProbeRole::Receiver, far_future());

        let (got_sid, got_role, _) = key.verify(&token).expect("valid token");
        assert_eq!(got_sid, sid);
        assert_eq!(got_role, ProbeRole::Receiver);
    }

    #[test]
    fn token_is_exactly_57_bytes() {
        assert_eq!(PROBE_TOKEN_LEN, 57);
    }

    #[test]
    fn tamper_any_byte_fails() {
        let key = ProbeTokenKey::random();
        let token = key.mint(&test_session_id(), ProbeRole::Sender, far_future());

        // Flipping one bit anywhere — session id, role, expiry, or tag —
        // must invalidate the token.
        for i in 0..PROBE_TOKEN_LEN {
            let mut bad = token;
            bad[i] ^= 0x01;
            assert!(key.verify(&bad).is_none(), "tampered byte {i} accepted");
        }
    }

    #[test]
    fn wrong_key_fails() {
        let token =
            ProbeTokenKey::random().mint(&test_session_id(), ProbeRole::Receiver, far_future());
        assert!(ProbeTokenKey::random().verify(&token).is_none());
    }

    #[test]
    fn expired_token_fails() {
        let key = ProbeTokenKey::random();
        let past = SystemTime::now() - Duration::from_secs(1);
        let token = key.mint(&test_session_id(), ProbeRole::Receiver, past);
        assert!(key.verify(&token).is_none());
    }

    #[test]
    fn truncated_and_oversized_fail() {
        let key = ProbeTokenKey::random();
        let token = key.mint(&test_session_id(), ProbeRole::Receiver, far_future());
        assert!(key.verify(&token[..PROBE_TOKEN_LEN - 1]).is_none());
        assert!(key.verify(&[]).is_none());
        let mut long = token.to_vec();
        long.push(0);
        assert!(key.verify(&long).is_none());
    }

    #[test]
    fn invalid_role_byte_fails() {
        // Mint a valid token, then force an unknown role byte and re-tag
        // it with the same key — role validation itself must reject it.
        let key = ProbeTokenKey::random();
        let mut token = key.mint(&test_session_id(), ProbeRole::Receiver, far_future());
        token[16] = 0x03;
        let tag = blake3::keyed_hash(&key.key, &token[..PAYLOAD_LEN]);
        token[PAYLOAD_LEN..].copy_from_slice(tag.as_bytes());
        assert!(key.verify(&token).is_none());
    }
}
