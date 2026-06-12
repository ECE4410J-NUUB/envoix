//! Probe frame encode/decode for reflexive UDP discovery.
//!
//! Wire format per `docs/reflexive-discovery-design.md` §3.2–3.3. The
//! choices encode lessons from RFC 8489 (see design §2.2):
//!
//! - Magic first byte `0x3F` keeps the top two bits `00`, so probe
//!   frames are distinguishable from QUIC packets (which always set one
//!   of the top two bits) on the client's shared socket.
//! - The reply's address is XOR-obfuscated so NAT ALGs that rewrite raw
//!   public-IP bytes in payloads cannot mangle it.
//! - The client-chosen `txid` is echoed so off-path attackers cannot
//!   forge replies, and retransmits can be correlated.
//!
//! Decode functions return `Option`: a malformed datagram is silently
//! dropped (design §4.1), never answered.

use std::net::{IpAddr, SocketAddr};

use crate::probe_token::PROBE_TOKEN_LEN;

pub const PROBE_MAGIC: [u8; 4] = [0x3f, 0x45, 0x56, 0x58];
pub const PROBE_VERSION: u8 = 0x01;
pub const PROBE_TXID_LEN: usize = 8;

const HEADER_LEN: usize = 4 + 1 + PROBE_TXID_LEN; // magic ‖ version ‖ txid
/// Requests are exactly this long: header ‖ token. At 70 bytes the
/// request always exceeds the largest reply (32 bytes) — amplification
/// safety needs no padding rule.
pub const PROBE_REQUEST_LEN: usize = HEADER_LEN + PROBE_TOKEN_LEN; // 70

const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;
const REPLY_LEN_V4: usize = HEADER_LEN + 1 + 2 + 4; // 20
const REPLY_LEN_V6: usize = HEADER_LEN + 1 + 2 + 16; // 32

// Amplification safety (design §3.3): the largest reply must stay
// strictly smaller than the request. Checked at compile time — changing
// either layout in a way that breaks the invariant will not build.
const _: () = assert!(REPLY_LEN_V6 < PROBE_REQUEST_LEN);

pub struct ProbeRequest {
    pub txid: [u8; PROBE_TXID_LEN],
    pub token: [u8; PROBE_TOKEN_LEN],
}

impl ProbeRequest {
    pub fn encode(&self) -> [u8; PROBE_REQUEST_LEN] {
        let mut buf = [0u8; PROBE_REQUEST_LEN];
        write_header(&mut buf, &self.txid);
        buf[HEADER_LEN..].copy_from_slice(&self.token);
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != PROBE_REQUEST_LEN || !header_ok(buf) {
            return None;
        }
        let mut txid = [0u8; PROBE_TXID_LEN];
        txid.copy_from_slice(&buf[5..HEADER_LEN]);
        let mut token = [0u8; PROBE_TOKEN_LEN];
        token.copy_from_slice(&buf[HEADER_LEN..]);
        Some(Self { txid, token })
    }
}

pub struct ProbeReply {
    pub txid: [u8; PROBE_TXID_LEN],
    pub observed: SocketAddr,
}

impl ProbeReply {
    pub fn encode(&self) -> Vec<u8> {
        let keystream = keystream(&self.txid);
        let xport = (self.observed.port() ^ magic_port_mask()).to_be_bytes();

        let mut buf = Vec::with_capacity(REPLY_LEN_V6);
        buf.extend_from_slice(&PROBE_MAGIC);
        buf.push(PROBE_VERSION);
        buf.extend_from_slice(&self.txid);
        match self.observed.ip() {
            IpAddr::V4(ip) => {
                buf.push(FAMILY_V4);
                buf.extend_from_slice(&xport);
                buf.extend(ip.octets().iter().zip(&keystream).map(|(a, k)| a ^ k));
            }
            IpAddr::V6(ip) => {
                buf.push(FAMILY_V6);
                buf.extend_from_slice(&xport);
                buf.extend(ip.octets().iter().zip(&keystream).map(|(a, k)| a ^ k));
            }
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < REPLY_LEN_V4 || !header_ok(buf) {
            return None;
        }
        let mut txid = [0u8; PROBE_TXID_LEN];
        txid.copy_from_slice(&buf[5..HEADER_LEN]);
        let keystream = keystream(&txid);

        let family = buf[HEADER_LEN];
        let port =
            u16::from_be_bytes([buf[HEADER_LEN + 1], buf[HEADER_LEN + 2]]) ^ magic_port_mask();
        let addr_bytes = &buf[HEADER_LEN + 3..];

        let ip: IpAddr = match (family, buf.len(), addr_bytes.len()) {
            (FAMILY_V4, REPLY_LEN_V4, 4) => {
                let mut a = [0u8; 4];
                for (i, b) in addr_bytes.iter().enumerate() {
                    a[i] = b ^ keystream[i];
                }
                IpAddr::from(a)
            }
            (FAMILY_V6, REPLY_LEN_V6, 16) => {
                let mut a = [0u8; 16];
                for (i, b) in addr_bytes.iter().enumerate() {
                    a[i] = b ^ keystream[i];
                }
                IpAddr::from(a)
            }
            _ => return None,
        };
        Some(Self {
            txid,
            observed: SocketAddr::new(ip, port),
        })
    }
}

fn write_header(buf: &mut [u8], txid: &[u8; PROBE_TXID_LEN]) {
    buf[..4].copy_from_slice(&PROBE_MAGIC);
    buf[4] = PROBE_VERSION;
    buf[5..HEADER_LEN].copy_from_slice(txid);
}

fn header_ok(buf: &[u8]) -> bool {
    buf[..4] == PROBE_MAGIC && buf[4] == PROBE_VERSION
}

/// XOR keystream for the reply address: magic ‖ txid ‖ magic (16 bytes,
/// covers IPv6). Spelled out in design §3.3 so both ends agree.
fn keystream(txid: &[u8; PROBE_TXID_LEN]) -> [u8; 16] {
    let mut ks = [0u8; 16];
    ks[..4].copy_from_slice(&PROBE_MAGIC);
    ks[4..12].copy_from_slice(txid);
    ks[12..].copy_from_slice(&PROBE_MAGIC);
    ks
}

fn magic_port_mask() -> u16 {
    u16::from_be_bytes([PROBE_MAGIC[0], PROBE_MAGIC[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn request() -> ProbeRequest {
        ProbeRequest {
            txid: TXID,
            token: [0xab; PROBE_TOKEN_LEN],
        }
    }

    #[test]
    fn magic_first_byte_cannot_collide_with_quic() {
        // RFC 9000: every QUIC packet sets one of the top two bits of its
        // first byte. Our magic must keep both clear (RFC 8489 §5 lesson).
        assert_eq!(PROBE_MAGIC[0] & 0xc0, 0);
    }

    #[test]
    fn request_round_trip() {
        let buf = request().encode();
        assert_eq!(buf.len(), 70);
        let back = ProbeRequest::decode(&buf).expect("valid");
        assert_eq!(back.txid, TXID);
        assert_eq!(back.token, [0xab; PROBE_TOKEN_LEN]);
    }

    #[test]
    fn request_rejects_wrong_length_magic_version() {
        let buf = request().encode();
        assert!(ProbeRequest::decode(&buf[..69]).is_none());
        let mut long = buf.to_vec();
        long.push(0);
        assert!(ProbeRequest::decode(&long).is_none());

        let mut bad_magic = buf;
        bad_magic[0] ^= 0xff;
        assert!(ProbeRequest::decode(&bad_magic).is_none());

        let mut bad_version = buf;
        bad_version[4] = 0x02;
        assert!(ProbeRequest::decode(&bad_version).is_none());
    }

    #[test]
    fn reply_round_trip_v4() {
        let reply = ProbeReply {
            txid: TXID,
            observed: "203.0.113.7:54321".parse().unwrap(),
        };
        let buf = reply.encode();
        assert_eq!(buf.len(), 20);
        let back = ProbeReply::decode(&buf).expect("valid");
        assert_eq!(back.txid, TXID);
        assert_eq!(back.observed, reply.observed);
    }

    #[test]
    fn reply_round_trip_v6() {
        let reply = ProbeReply {
            txid: TXID,
            observed: "[2001:db8::1]:9000".parse().unwrap(),
        };
        let buf = reply.encode();
        assert_eq!(buf.len(), 32);
        let back = ProbeReply::decode(&buf).expect("valid");
        assert_eq!(back.observed, reply.observed);
    }

    #[test]
    fn reply_address_is_not_raw_in_packet() {
        // The ALG-mangling defence (RFC 8489 §14.2 lesson): the observed
        // address bytes must never appear verbatim in the datagram.
        let reply = ProbeReply {
            txid: TXID,
            observed: "203.0.113.7:54321".parse().unwrap(),
        };
        let buf = reply.encode();
        let raw_addr = [203u8, 0, 113, 7];
        assert!(
            !buf.windows(4).any(|w| w == raw_addr),
            "raw address bytes leaked into reply"
        );
        let raw_port = 54321u16.to_be_bytes();
        assert_ne!(&buf[14..16], &raw_port, "raw port leaked into reply");
    }

    #[test]
    fn reply_xor_vectors_fixed() {
        // Hand-checkable vector: keystream = magic ‖ txid ‖ magic.
        let ks = keystream(&TXID);
        assert_eq!(&ks[..4], &PROBE_MAGIC);
        assert_eq!(&ks[4..12], &TXID);
        assert_eq!(&ks[12..], &PROBE_MAGIC);

        let reply = ProbeReply {
            txid: TXID,
            observed: "10.0.0.1:80".parse().unwrap(),
        };
        let buf = reply.encode();
        // port 80 ^ 0x3f45
        assert_eq!(&buf[14..16], &(80u16 ^ 0x3f45).to_be_bytes());
        // addr[0] = 10 ^ keystream[0] = 10 ^ 0x3f
        assert_eq!(buf[16], 10 ^ 0x3f);
    }

    #[test]
    fn reply_rejects_family_length_mismatch() {
        let reply = ProbeReply {
            txid: TXID,
            observed: "203.0.113.7:54321".parse().unwrap(),
        };
        let mut buf = reply.encode();
        buf[HEADER_LEN] = FAMILY_V6; // claims v6 but has v4 length
        assert!(ProbeReply::decode(&buf).is_none());

        let unknown_family = {
            let mut b = reply.encode();
            b[HEADER_LEN] = 0x03;
            b
        };
        assert!(ProbeReply::decode(&unknown_family).is_none());
    }
}
