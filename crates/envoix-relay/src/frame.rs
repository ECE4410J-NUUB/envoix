//! Data-plane datagram framing.
//!
//! Wire format: `magic || token || payload`. The relay parses an incoming
//! datagram into (token, payload), validates the token elsewhere, and
//! forwards the bare payload. The token flows only peer->relay; the relay
//! never echoes it.
//!
//! Magic first byte `0x3F` keeps the top two bits `00` so a relay datagram
//! is distinguishable from a QUIC packet on a shared socket; last byte
//! `0x59` distinguishes it from the probe magic (`...58`) if the two ever
//! co-locate.

use crate::token::RELAY_TOKEN_LEN;

pub const RELAY_MAGIC: [u8; 4] = [0x3f, 0x45, 0x56, 0x59];

/// magic || token. The client prepends this to every QUIC datagram on a
/// relayed path; the client must shrink its QUIC max-datagram by this many
/// bytes to stay under the path MTU.
pub const RELAY_HEADER_LEN: usize = 4 + RELAY_TOKEN_LEN; // 61

/// A parsed data-plane datagram: the token to validate and the opaque
/// payload to forward.
pub struct RelayDatagram<'a> {
    pub token: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> RelayDatagram<'a> {
    /// Parse `magic || token || payload`. Returns `None` if the buffer is too
    /// short or the magic is wrong - caller drops silently.
    pub fn parse(buf: &'a [u8]) -> Option<RelayDatagram<'a>> {
        if buf.len() <= RELAY_HEADER_LEN || buf[..4] != RELAY_MAGIC {
            return None;
        }
        Some(RelayDatagram {
            token: &buf[4..RELAY_HEADER_LEN],
            payload: &buf[RELAY_HEADER_LEN..],
        })
    }
}

/// Build a data-plane datagram. Used by the client and by tests; the relay
/// itself only parses (and forwards bare payload).
pub fn encode(token: &[u8; RELAY_TOKEN_LEN], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
    buf.extend_from_slice(&RELAY_MAGIC);
    buf.extend_from_slice(token);
    buf.extend_from_slice(payload);
    buf
}

/// Reachability-probe magic. Same prefix as [`RELAY_MAGIC`], last byte `0x58`
/// (vs `0x59`) so a probe is unmistakable from a real data-plane datagram on
/// the same socket. A relay that receives `magic || nonce` echoes the exact
/// bytes back to the sender, letting an external prober (the rendezvous)
/// confirm the relay's UDP port is reachable. It carries no token: it proves
/// only that a packet reached the port, nothing about any session.
pub const RELAY_PROBE_MAGIC: [u8; 4] = [0x3f, 0x45, 0x56, 0x58];

/// Probe nonce length. The prober picks a fresh random nonce per probe so a
/// stray or replayed echo cannot be mistaken for the current one.
pub const RELAY_PROBE_NONCE_LEN: usize = 16;

/// Probe datagram length: `magic(4) || nonce(16)`. Any other length is not a
/// probe.
pub const RELAY_PROBE_LEN: usize = 4 + RELAY_PROBE_NONCE_LEN;

/// If `buf` is a probe datagram, return its nonce; otherwise `None`.
pub fn parse_probe(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() == RELAY_PROBE_LEN && buf[..4] == RELAY_PROBE_MAGIC {
        Some(&buf[4..])
    } else {
        None
    }
}

/// Build a probe datagram: `magic || nonce`.
pub fn encode_probe(nonce: &[u8; RELAY_PROBE_NONCE_LEN]) -> [u8; RELAY_PROBE_LEN] {
    let mut buf = [0u8; RELAY_PROBE_LEN];
    buf[..4].copy_from_slice(&RELAY_PROBE_MAGIC);
    buf[4..].copy_from_slice(nonce);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_len_is_61() {
        assert_eq!(RELAY_HEADER_LEN, 61);
    }

    #[test]
    fn magic_first_byte_cannot_alias_quic() {
        // RFC 9000: every QUIC packet sets one of the top two bits.
        assert_eq!(RELAY_MAGIC[0] & 0xc0, 0);
    }

    #[test]
    fn magic_distinct_from_probe() {
        // Probe magic is 3f 45 56 58; relay is 3f 45 56 59.
        assert_eq!(RELAY_MAGIC, [0x3f, 0x45, 0x56, 0x59]);
        assert_eq!(RELAY_PROBE_MAGIC, [0x3f, 0x45, 0x56, 0x58]);
        assert_ne!(RELAY_MAGIC, RELAY_PROBE_MAGIC);
    }

    #[test]
    fn probe_round_trip() {
        let nonce = [0xa7u8; RELAY_PROBE_NONCE_LEN];
        let buf = encode_probe(&nonce);
        assert_eq!(buf.len(), RELAY_PROBE_LEN);
        assert_eq!(parse_probe(&buf), Some(&nonce[..]));
    }

    #[test]
    fn probe_rejects_wrong_magic_and_length() {
        let nonce = [0x01u8; RELAY_PROBE_NONCE_LEN];
        let mut buf = encode_probe(&nonce);
        // Wrong length (a real relay datagram, or truncated) is not a probe.
        assert!(parse_probe(&buf[..RELAY_PROBE_LEN - 1]).is_none());
        assert!(parse_probe(&[]).is_none());
        // The relay magic, even at probe length, is not a probe.
        buf[3] = 0x59;
        assert!(parse_probe(&buf).is_none());
    }

    #[test]
    fn round_trip() {
        let token = [0xcd; RELAY_TOKEN_LEN];
        let payload = b"opaque quic datagram bytes";
        let buf = encode(&token, payload);
        assert_eq!(buf.len(), RELAY_HEADER_LEN + payload.len());

        let parsed = RelayDatagram::parse(&buf).expect("valid");
        assert_eq!(parsed.token, &token[..]);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn rejects_short_and_bad_magic() {
        let token = [0xcd; RELAY_TOKEN_LEN];
        let buf = encode(&token, b"x");

        // Exactly header length (empty payload) is rejected - a real
        // datagram always carries payload.
        assert!(RelayDatagram::parse(&buf[..RELAY_HEADER_LEN]).is_none());
        assert!(RelayDatagram::parse(&buf[..10]).is_none());
        assert!(RelayDatagram::parse(&[]).is_none());

        let mut bad = buf.clone();
        bad[0] ^= 0xff;
        assert!(RelayDatagram::parse(&bad).is_none());
    }
}
