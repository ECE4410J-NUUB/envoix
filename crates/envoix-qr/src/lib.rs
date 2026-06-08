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
    #[error("unsupported payload version {found} (expected {expected})")]
    VersionMismatch { found: u32, expected: u32 },

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
}

impl QrInvitePayload {
    /// Encodes the payload into an invite string: `envoix:<base64url>`.
    pub fn encode(&self) -> Result<String, QrError> {
        let json = serde_json::to_string(self)
            .map_err(|e| QrError::DecodeError(format!("serialization failed: {e}")))?;
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
        Ok(format!("{INVITE_PREFIX}{b64}"))
    }

    /// Decodes an invite string produced by [`encode`](Self::encode).
    ///
    /// Returns [`QrError::DecodeError`] for any parse failure.  Call
    /// [`validate`](Self::validate) separately to check semantic constraints.
    pub fn decode(s: &str) -> Result<Self, QrError> {
        let b64 = s
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
/// requirement of the SPAKE2 auth layer.  Returns [`QrError::DecodeError`]
/// only if the OS entropy source is unavailable.
pub fn generate_token() -> Result<String, QrError> {
    let mut bytes = [0u8; 9];
    getrandom::fill(&mut bytes)
        .map_err(|e| QrError::DecodeError(format!("entropy source unavailable: {e}")))?;

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
/// in a fixed-width font.  A two-module quiet zone is added on every side so
/// that scanners can locate the finder patterns reliably.
///
/// Returns an empty string if `data` is too long to encode at any QR error-
/// correction level.
pub fn render_terminal_qr(data: &str) -> String {
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    // Collect the raw module grid (true = dark).
    let width = code.width();
    let modules: Vec<bool> = code
        .into_colors()
        .iter()
        .map(|c| *c == Color::Dark)
        .collect();

    // Add a 2-module quiet zone on every side.
    const QUIET: usize = 2;
    let padded_width = width + QUIET * 2;
    let padded_height = width + QUIET * 2; // QR codes are always square

    // Build the padded grid (false = light/white).
    let mut grid = vec![false; padded_width * padded_height];
    for row in 0..width {
        for col in 0..width {
            grid[(row + QUIET) * padded_width + (col + QUIET)] = modules[row * width + col];
        }
    }

    // Render two rows per output line using half-block Unicode characters.
    let mut output = String::new();
    let mut row = 0;
    while row < padded_height {
        let top_row = row;
        let bot_row = row + 1;

        for col in 0..padded_width {
            let top = grid[top_row * padded_width + col];
            let bot = if bot_row < padded_height {
                grid[bot_row * padded_width + col]
            } else {
                false
            };

            // Dark modules are "filled"; light modules are "empty".
            let ch = match (top, bot) {
                (true,  true)  => '█',
                (true,  false) => '▀',
                (false, true)  => '▄',
                (false, false) => ' ',
            };
            output.push(ch);
        }
        output.push('\n');
        row += 2;
    }

    output
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
        let encoded = payload.encode().unwrap();
        let decoded = QrInvitePayload::decode(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn encoded_string_has_invite_prefix() {
        let encoded = valid_payload(0).encode().unwrap();
        assert!(encoded.starts_with(INVITE_PREFIX));
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

    // --- validate ---

    #[test]
    fn valid_payload_passes_validation() {
        let now = 1_000_000_u64;
        valid_payload(now).validate(now).unwrap();
    }

    #[test]
    fn expired_payload_is_rejected() {
        let payload = valid_payload(0); // expires_at = 300
        let err = payload.validate(300).unwrap_err(); // now == expires_at → expired
        assert_eq!(err, QrError::Expired);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut payload = valid_payload(0);
        payload.version = 99;
        let err = payload.validate(0).unwrap_err();
        assert!(matches!(err, QrError::VersionMismatch { found: 99, .. }));
    }

    #[test]
    fn no_candidates_is_rejected() {
        let mut payload = valid_payload(0);
        payload.candidates.clear();
        let err = payload.validate(0).unwrap_err();
        assert_eq!(err, QrError::NoCandidates);
    }

    #[test]
    fn short_token_is_rejected() {
        let mut payload = valid_payload(0);
        payload.token = "short".into();
        let err = payload.validate(0).unwrap_err();
        assert_eq!(err, QrError::WeakToken);
    }

    #[test]
    fn non_ascii_token_is_rejected() {
        let mut payload = valid_payload(0);
        payload.token = "abcdefghijklé".into(); // non-ASCII
        let err = payload.validate(0).unwrap_err();
        assert_eq!(err, QrError::WeakToken);
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

    #[test]
    fn first_candidate_returns_parsed_addr() {
        let payload = valid_payload(0);
        let addr = payload.first_candidate().unwrap();
        assert_eq!(addr, "127.0.0.1:9000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn first_candidate_on_empty_list_returns_error() {
        let mut payload = valid_payload(0);
        payload.candidates.clear();
        assert_eq!(payload.first_candidate().unwrap_err(), QrError::NoCandidates);
    }

    // --- generate_token ---

    #[test]
    fn token_is_18_chars() {
        let token = generate_token().unwrap();
        assert_eq!(token.len(), 18);
    }

    #[test]
    fn token_is_ascii_hex() {
        let token = generate_token().unwrap();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn token_satisfies_auth_minimum_length() {
        let token = generate_token().unwrap();
        assert!(token.is_ascii());
        assert!(token.len() >= MIN_TOKEN_LEN);
    }

    #[test]
    fn two_tokens_are_different() {
        // Probability of collision is 1/2^72 — effectively impossible.
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_token_passes_payload_validation() {
        let token = generate_token().unwrap();
        let payload = QrInvitePayload::new(token, vec!["127.0.0.1:9000".into()], 999);
        payload.validate(0).unwrap();
    }

    // --- render_terminal_qr ---

    #[test]
    fn render_produces_non_empty_output_for_short_data() {
        let qr = render_terminal_qr("hello");
        assert!(!qr.is_empty());
    }

    #[test]
    fn render_output_contains_only_block_chars_and_newlines() {
        let qr = render_terminal_qr("test");
        for ch in qr.chars() {
            assert!(
                matches!(ch, '█' | '▀' | '▄' | ' ' | '\n'),
                "unexpected character: {ch:?}"
            );
        }
    }

    #[test]
    fn render_all_lines_have_equal_width() {
        let qr = render_terminal_qr("envoix test payload");
        let lines: Vec<&str> = qr.trim_end_matches('\n').split('\n').collect();
        let widths: Vec<usize> = lines.iter().map(|l| l.chars().count()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "lines have different widths: {widths:?}"
        );
    }

    #[test]
    fn render_invite_string_produces_scannable_qr() {
        let payload = valid_payload(0);
        let invite = payload.encode().unwrap();
        let qr = render_terminal_qr(&invite);
        assert!(!qr.is_empty());
    }
}
