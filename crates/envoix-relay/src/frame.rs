//! Data-plane datagram framing.
//!
//! Wire format per `docs/relay-design.md` §3.2: `magic || token || payload`.
//! The relay parses an incoming datagram into (token, payload), validates
//! the token elsewhere, and forwards the bare payload (§3.3). The token
//! flows only peer->relay; the relay never echoes it.
//!
//! Magic first byte `0x3F` keeps the top two bits `00` so a relay datagram
//! is distinguishable from a QUIC packet on a shared socket (RFC 8489 §5
//! lesson, same as the probe magic); last byte `0x59` distinguishes it
//! from the probe magic (`...58`) if the two ever co-locate.

use crate::token::RELAY_TOKEN_LEN;

pub const RELAY_MAGIC: [u8; 4] = [0x3f, 0x45, 0x56, 0x59];

/// magic || token. The client prepends this to every QUIC datagram on a
/// relayed path; the client must shrink its QUIC max-datagram by this many
/// bytes to stay under the path MTU (design §6).
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
