//! QR-based pairing invite payload — serialization, encoding, and validation.
//!
//! Invite strings have the form `envoix:<base64url>` where the base64url payload
//! is a JSON-encoded [`QrInvitePayload`].  The `envoix:` prefix makes the string
//! recognisable and leaves room for future format versions.

use std::net::SocketAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use qrcode::QrCode;
use qrcode::types::Color;
use serde::{Deserialize, Serialize};

use envoix_types::PROTOCOL_VERSION;

/// Prefix prepended to every encoded invite string.
pub const INVITE_PREFIX: &str = "envoix:";

/// Current payload schema version.  Increment when the schema changes in a
/// backward-incompatible way.
pub const PAYLOAD_VERSION: u32 = 1;

/// Minimum shared-token length required by the SPAKE2 auth layer.
const MIN_TOKEN_LEN: usize = 12;

/// Versioned invite payload carried inside a QR code or pasted as plain text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QrInvitePayload {
    /// Payload schema version — must equal [`PAYLOAD_VERSION`].
    pub version: u32,
    /// Wire protocol version the receiver is running.
    pub protocol_version: u32,
    /// SPAKE2 shared token (≥12 ASCII bytes).
    pub token: String,
    /// Network candidates the sender should try, e.g. `["192.168.1.5:54321"]`.
    pub candidates: Vec<String>,
    /// Expiry as a Unix timestamp in seconds.  Senders reject payloads where
    /// `expires_at ≤ now`.
    pub expires_at: u64,
    /// Reserved feature flags — set to 0 for this version.
    pub flags: u32,
}

/// Errors returned by QR payload operations.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum QrError {
    #[error("unsupported payload schema version {found} (expected {expected})")]
    VersionMismatch { found: u32, expected: u32 },

    #[error("unsupported protocol version {found} (expected {expected})")]
    ProtocolVersionMismatch { found: u32, expected: u32 },

    #[error("invite has expired")]
    Expired,

    #[error("invite contains no network candidates")]
    NoCandidates,

    #[error("token is too short or not ASCII (minimum {MIN_TOKEN_LEN} ASCII bytes)")]
    WeakToken,

    #[error("malformed candidate address: {0}")]
    MalformedAddress(String),

    #[error("decode error: {0}")]
    DecodeError(String),

    #[error("entropy source unavailable: {0}")]
    Entropy(String),

    #[error("unsupported feature flags 0x{0:08x}; sender and receiver versions may be incompatible")]
    UnsupportedFlags(u32),
}

impl QrInvitePayload {
    /// Encodes the payload into an invite string: `envoix:<base64url>`.
    ///
    /// Serialization is infallible for this struct (only primitives, `String`,
    /// and `Vec<String>`), so this does not return a `Result`.
    pub fn encode(&self) -> String {
        let json =
            serde_json::to_string(self).expect("QrInvitePayload always serializes to JSON");
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("{INVITE_PREFIX}{b64}")
    }

    /// Decodes an invite string produced by [`encode`](Self::encode).
    ///
    /// Returns [`QrError::DecodeError`] for any parse failure.  Call
    /// [`validate`](Self::validate) separately to check semantic constraints.
    pub fn decode(s: &str) -> Result<Self, QrError> {
        let b64 = s
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| QrError::DecodeError(format!("missing '{INVITE_PREFIX}' prefix")))?;

        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| QrError::DecodeError(format!("base64 decode failed: {e}")))?;

        serde_json::from_slice(&bytes)
            .map_err(|e| QrError::DecodeError(format!("JSON parse failed: {e}")))
    }

    /// Validates semantic constraints on the payload.
    ///
    /// `now` is the current Unix timestamp in seconds.  Pass
    /// `std::time::SystemTime::now()` converted to seconds, or a fixed value
    /// in tests.
    pub fn validate(&self, now: u64) -> Result<(), QrError> {
        if self.version != PAYLOAD_VERSION {
            return Err(QrError::VersionMismatch {
                found: self.version,
                expected: PAYLOAD_VERSION,
            });
        }

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(QrError::ProtocolVersionMismatch {
                found: self.protocol_version,
                expected: PROTOCOL_VERSION,
            });
        }

        if self.expires_at <= now {
            return Err(QrError::Expired);
        }

        if self.candidates.is_empty() {
            return Err(QrError::NoCandidates);
        }

        if !self.token.is_ascii() || self.token.len() < MIN_TOKEN_LEN {
            return Err(QrError::WeakToken);
        }

        for candidate in &self.candidates {
            candidate.parse::<SocketAddr>().map_err(|_| {
                QrError::MalformedAddress(candidate.clone())
            })?;
        }

        if self.flags != 0 {
            return Err(QrError::UnsupportedFlags(self.flags));
        }

        Ok(())
    }

    /// Returns the first candidate parsed as a [`SocketAddr`].
    ///
    /// Assumes the payload has already been validated; returns
    /// [`QrError::NoCandidates`] if the list is empty.
    pub fn first_candidate(&self) -> Result<SocketAddr, QrError> {
        let s = self.candidates.first().ok_or(QrError::NoCandidates)?;
        s.parse::<SocketAddr>()
            .map_err(|_| QrError::MalformedAddress(s.clone()))
    }

    /// Constructs a new payload with the current protocol version and schema
    /// version pre-filled.
    pub fn new(token: String, candidates: Vec<String>, expires_at: u64) -> Self {
        Self {
            version: PAYLOAD_VERSION,
            protocol_version: PROTOCOL_VERSION,
            token,
            candidates,
            expires_at,
            flags: 0,
        }
    }
}

/// Generates a random pairing token as an 18-character lowercase hex string.
///
/// 9 random bytes → 18 hex chars, which satisfies the ≥12 ASCII-byte
/// requirement of the SPAKE2 auth layer.  Returns [`QrError::Entropy`]
/// only if the OS entropy source is unavailable.
pub fn generate_token() -> Result<String, QrError> {
    let mut bytes = [0u8; 9];
    getrandom::fill(&mut bytes).map_err(|e| QrError::Entropy(e.to_string()))?;

    let mut token = String::with_capacity(18);
    for b in bytes {
        use std::fmt::Write as _;
        write!(token, "{b:02x}").expect("writing to String is infallible");
    }
    Ok(token)
}

/// Renders `data` as a QR code and returns a UTF-8 string suitable for
/// printing directly to a terminal.
///
/// Each pair of QR rows is collapsed into one line of text using Unicode
/// half-block characters (`▀` `▄` `█` ` `), so the output is roughly square
/// in a fixed-width font.  A four-module quiet zone is added on every side
/// per the QR Code specification, which requires this minimum for reliable
/// finder-pattern detection.
///
/// Returns `None` if `data` is too long to encode at any QR error-correction
/// level.
pub fn render_terminal_qr(data: &str) -> Option<String> {
    const QUIET: usize = 4;

    let code = QrCode::new(data.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.into_colors();
    let padded = width + QUIET * 2;

    // Dark module lookup that treats the quiet zone as light.
    let is_dark = |row: usize, col: usize| -> bool {
        if row < QUIET || col < QUIET || row >= width + QUIET || col >= width + QUIET {
            return false;
        }
        colors[(row - QUIET) * width + (col - QUIET)] == Color::Dark
    };

    // Render two QR rows per output line using half-block characters.
    let mut output = String::new();
    for row in (0..padded).step_by(2) {
        for col in 0..padded {
            let top = is_dark(row, col);
            let bot = row + 1 < padded && is_dark(row + 1, col);
            output.push(match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push('\n');
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "abcdefghijkl"; // exactly 12 ASCII bytes

    fn valid_payload(now: u64) -> QrInvitePayload {
        QrInvitePayload::new(TOKEN.into(), vec!["127.0.0.1:9000".into()], now + 300)
    }

    // --- encode / decode ---

    #[test]
    fn round_trip_encode_decode() {
        let payload = valid_payload(0);
        let encoded = payload.encode();
        let decoded = QrInvitePayload::decode(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        let err = QrInvitePayload::decode("badstring").unwrap_err();
        assert!(matches!(err, QrError::DecodeError(_)));
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let err = QrInvitePayload::decode("envoix:!!!").unwrap_err();
        assert!(matches!(err, QrError::DecodeError(_)));
    }

    #[test]
    fn decode_rejects_invalid_json() {
        let b64 = URL_SAFE_NO_PAD.encode(b"not json");
        let err = QrInvitePayload::decode(&format!("envoix:{b64}")).unwrap_err();
        assert!(matches!(err, QrError::DecodeError(_)));
    }

    // Invite strings copied from a terminal or QR scanner often carry a
    // trailing newline or leading space.
    #[test]
    fn decode_tolerates_surrounding_whitespace() {
        let invite = format!("  {}\n", valid_payload(0).encode());
        QrInvitePayload::decode(&invite).unwrap();
    }

    // --- validate ---

    #[test]
    fn valid_payload_passes_validation() {
        let now = 1_000_000_u64;
        valid_payload(now).validate(now).unwrap();
    }

    // expires_at == now satisfies the `<=` condition and must be rejected.
    #[test]
    fn expired_payload_is_rejected() {
        let payload = valid_payload(0); // expires_at = 300
        let err = payload.validate(300).unwrap_err(); // now == expires_at → expired
        assert_eq!(err, QrError::Expired);
    }

    // expires_at == now + 1 is the tightest value that must pass.
    #[test]
    fn payload_expiring_in_one_second_passes() {
        let now = 1_000_000_u64;
        let mut payload = valid_payload(0);
        payload.expires_at = now + 1;
        payload.validate(now).unwrap();
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut payload = valid_payload(0);
        payload.version = 99;
        let err = payload.validate(0).unwrap_err();
        assert!(matches!(err, QrError::VersionMismatch { found: 99, .. }));
    }

    #[test]
    fn protocol_version_mismatch_is_rejected() {
        let mut payload = valid_payload(0);
        payload.protocol_version = 999;
        let err = payload.validate(0).unwrap_err();
        assert!(matches!(
            err,
            QrError::ProtocolVersionMismatch { found: 999, .. }
        ));
    }

    #[test]
    fn nonzero_flags_are_rejected() {
        let mut payload = valid_payload(0);
        payload.flags = 1;
        let err = payload.validate(0).unwrap_err();
        assert!(matches!(err, QrError::UnsupportedFlags(1)));
    }

    #[test]
    fn no_candidates_is_rejected() {
        let mut payload = valid_payload(0);
        payload.candidates.clear();
        let err = payload.validate(0).unwrap_err();
        assert_eq!(err, QrError::NoCandidates);
    }

    // Token exactly one byte short of the minimum must be rejected.
    #[test]
    fn token_one_byte_short_of_minimum_is_rejected() {
        let mut payload = valid_payload(0);
        payload.token = "a".repeat(MIN_TOKEN_LEN - 1);
        assert_eq!(payload.validate(0).unwrap_err(), QrError::WeakToken);
    }

    #[test]
    fn non_ascii_token_is_rejected() {
        let mut payload = valid_payload(0);
        payload.token = "abcdefghijklé".into(); // non-ASCII suffix, still ≥12 bytes
        assert_eq!(payload.validate(0).unwrap_err(), QrError::WeakToken);
    }

    #[test]
    fn malformed_candidate_is_rejected() {
        let mut payload = valid_payload(0);
        payload.candidates = vec!["not-an-address".into()];
        let err = payload.validate(0).unwrap_err();
        assert!(matches!(err, QrError::MalformedAddress(_)));
    }

    #[test]
    fn ipv6_candidate_is_accepted() {
        let mut payload = valid_payload(0);
        payload.candidates = vec!["[::1]:9000".into()];
        payload.validate(0).unwrap();
    }

    // --- first_candidate ---

    // With multiple candidates the first one must be returned, not the last.
    #[test]
    fn first_candidate_with_multiple_returns_first() {
        let mut payload = valid_payload(0);
        payload.candidates = vec!["1.2.3.4:1000".into(), "5.6.7.8:2000".into()];
        let addr = payload.first_candidate().unwrap();
        assert_eq!(addr, "1.2.3.4:1000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn first_candidate_on_empty_list_returns_error() {
        let mut payload = valid_payload(0);
        payload.candidates.clear();
        assert_eq!(payload.first_candidate().unwrap_err(), QrError::NoCandidates);
    }

    // --- generate_token ---

    // Verify all structural requirements in a single test: length, charset,
    // and SPAKE2 minimum — these are the same property viewed from three angles.
    #[test]
    fn generated_token_is_valid_hex_and_meets_spake2_minimum() {
        let token = generate_token().unwrap();
        assert_eq!(token.len(), 18);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(token.len() >= MIN_TOKEN_LEN);
    }

    #[test]
    fn generated_token_passes_payload_validation() {
        let token = generate_token().unwrap();
        let payload = QrInvitePayload::new(token, vec!["127.0.0.1:9000".into()], 999);
        payload.validate(0).unwrap();
    }

    // --- render_terminal_qr ---

    #[test]
    fn render_output_contains_only_block_chars_and_newlines() {
        let qr = render_terminal_qr("test").unwrap();
        for ch in qr.chars() {
            assert!(
                matches!(ch, '█' | '▀' | '▄' | ' ' | '\n'),
                "unexpected character: {ch:?}"
            );
        }
    }

    // All lines must be the same width so the QR matrix is square.
    #[test]
    fn render_all_lines_have_equal_width() {
        let qr = render_terminal_qr("envoix test payload").unwrap();
        let lines: Vec<&str> = qr.trim_end_matches('\n').split('\n').collect();
        let widths: Vec<usize> = lines.iter().map(|l| l.chars().count()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "lines have different widths: {widths:?}"
        );
    }

    // A real invite string must encode without hitting the QR data limit.
    #[test]
    fn render_invite_string_produces_scannable_qr() {
        let payload = valid_payload(0);
        let invite = payload.encode();
        assert!(render_terminal_qr(&invite).is_some());
    }
}
