//! Pairing and peer-authentication configuration.

use envoix_error::CoreError;
use envoix_protocol::{AuthFrame, Frame, Spake2Confirm, Spake2Message, Spake2Start};
use envoix_transport::FrameConnection;
use envoix_types::{PROTOCOL_VERSION, PeerRole};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub use envoix_types::MIN_SHARED_TOKEN_LEN;

/// Domain label used for SPAKE2 transcript and QUIC exporter binding.
pub const SPAKE2_DOMAIN: &[u8] = b"envoix-auth-spake2-v1";

/// User-facing warning for the current SPAKE2 backend.
pub const SPAKE2_EXPERIMENTAL_WARNING: &str = "warning: SPAKE2 shared-token pairing is experimental; the Rust SPAKE2 dependency is not independently audited";

const NONCE_LEN: usize = 32;
const SENDER_IDENTITY: &[u8] = b"envoix sender";
const RECEIVER_IDENTITY: &[u8] = b"envoix receiver";
const EXPORTER_CONTEXT: &[u8] = b"pairing";
const SENDER_CONFIRM_LABEL: &[u8] = b"sender-confirm";
const RECEIVER_CONFIRM_LABEL: &[u8] = b"receiver-confirm";

type HmacSha256 = Hmac<Sha256>;

/// Error type returned by pairing authentication.
pub type AuthError = CoreError;

/// Pairing method selected for a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingConfig {
    /// Experimental SPAKE2 pairing using a shared ASCII token.
    Spake2SharedToken {
        /// Shared token known to both peers.
        token: String,
    },
}

impl PairingConfig {
    /// Creates a validated experimental SPAKE2 shared-token config.
    pub fn spake2_shared_token(token: impl Into<String>) -> Result<Self, AuthError> {
        let config = Self::Spake2SharedToken {
            token: token.into(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates pairing config invariants that are independent of transport.
    pub fn validate(&self) -> Result<(), AuthError> {
        match self {
            Self::Spake2SharedToken { token } => validate_shared_token(token),
        }
    }
}

/// Authenticates the sender side before any transfer frames are sent.
pub async fn authenticate_sender(
    connection: &mut dyn FrameConnection,
    config: &PairingConfig,
) -> Result<(), AuthError> {
    config.validate()?;
    let token = shared_token(config);
    let exporter = connection.export_keying_material(SPAKE2_DOMAIN, EXPORTER_CONTEXT)?;
    let sender_nonce = random_nonce()?;
    let (state, sender_message) = Spake2::<Ed25519Group>::start_a(
        &Password::new(token.as_bytes()),
        &Identity::new(SENDER_IDENTITY),
        &Identity::new(RECEIVER_IDENTITY),
    );

    connection
        .send_frame(Frame::Auth(AuthFrame::Spake2Start(Spake2Start {
            protocol_version: PROTOCOL_VERSION,
            role: PeerRole::Sender,
            nonce: sender_nonce.to_vec(),
            message: sender_message.clone(),
        })))
        .await?;

    let response = expect_spake2_message(connection.recv_frame().await?)?;
    validate_nonce(&response.nonce)?;
    let shared_key = finish_spake2(state, &response.message)?;
    let transcript = ConfirmationTranscript {
        sender_nonce: &sender_nonce,
        receiver_nonce: &response.nonce,
        sender_message: &sender_message,
        receiver_message: &response.message,
        exporter: &exporter,
    };
    let sender_proof = confirmation_proof(&shared_key, &transcript, SENDER_CONFIRM_LABEL);

    connection
        .send_frame(Frame::Auth(AuthFrame::Spake2Confirm(Spake2Confirm {
            proof: sender_proof,
        })))
        .await?;

    let receiver_confirm = expect_spake2_confirm(connection.recv_frame().await?)?;
    verify_confirmation(
        &shared_key,
        &transcript,
        RECEIVER_CONFIRM_LABEL,
        &receiver_confirm.proof,
    )
}

/// Authenticates the receiver side before any transfer frames are accepted.
pub async fn authenticate_receiver(
    connection: &mut dyn FrameConnection,
    config: &PairingConfig,
) -> Result<(), AuthError> {
    config.validate()?;
    let token = shared_token(config);
    let exporter = connection.export_keying_material(SPAKE2_DOMAIN, EXPORTER_CONTEXT)?;
    let start = expect_spake2_start(connection.recv_frame().await?)?;
    validate_start(&start)?;

    let receiver_nonce = random_nonce()?;
    let (state, receiver_message) = Spake2::<Ed25519Group>::start_b(
        &Password::new(token.as_bytes()),
        &Identity::new(SENDER_IDENTITY),
        &Identity::new(RECEIVER_IDENTITY),
    );

    connection
        .send_frame(Frame::Auth(AuthFrame::Spake2Message(Spake2Message {
            nonce: receiver_nonce.to_vec(),
            message: receiver_message.clone(),
        })))
        .await?;

    let shared_key = finish_spake2(state, &start.message)?;
    let transcript = ConfirmationTranscript {
        sender_nonce: &start.nonce,
        receiver_nonce: &receiver_nonce,
        sender_message: &start.message,
        receiver_message: &receiver_message,
        exporter: &exporter,
    };

    let sender_confirm = expect_spake2_confirm(connection.recv_frame().await?)?;
    verify_confirmation(
        &shared_key,
        &transcript,
        SENDER_CONFIRM_LABEL,
        &sender_confirm.proof,
    )?;

    let receiver_proof = confirmation_proof(&shared_key, &transcript, RECEIVER_CONFIRM_LABEL);
    connection
        .send_frame(Frame::Auth(AuthFrame::Spake2Confirm(Spake2Confirm {
            proof: receiver_proof,
        })))
        .await?;

    Ok(())
}

fn shared_token(config: &PairingConfig) -> &str {
    match config {
        PairingConfig::Spake2SharedToken { token } => token,
    }
}

fn validate_shared_token(token: &str) -> Result<(), AuthError> {
    if !token.is_ascii() {
        return Err(CoreError::InvalidInput(
            "SPAKE2 shared token must be ASCII".into(),
        ));
    }
    if token.len() < MIN_SHARED_TOKEN_LEN {
        return Err(CoreError::InvalidInput(format!(
            "SPAKE2 shared token must be at least {MIN_SHARED_TOKEN_LEN} ASCII bytes"
        )));
    }
    Ok(())
}

fn random_nonce() -> Result<[u8; NONCE_LEN], AuthError> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| CoreError::Crypto(error.to_string()))?;
    Ok(nonce)
}

fn finish_spake2(state: Spake2<Ed25519Group>, peer_message: &[u8]) -> Result<Vec<u8>, AuthError> {
    state
        .finish(peer_message)
        .map_err(|error| CoreError::Crypto(format!("SPAKE2 failed: {error:?}")))
}

fn expect_spake2_start(frame: Frame) -> Result<Spake2Start, AuthError> {
    match frame {
        Frame::Auth(AuthFrame::Spake2Start(start)) => Ok(start),
        frame => Err(CoreError::Protocol(format!(
            "expected SPAKE2 start, got {frame:?}"
        ))),
    }
}

fn expect_spake2_message(frame: Frame) -> Result<Spake2Message, AuthError> {
    match frame {
        Frame::Auth(AuthFrame::Spake2Message(message)) => Ok(message),
        frame => Err(CoreError::Protocol(format!(
            "expected SPAKE2 message, got {frame:?}"
        ))),
    }
}

fn expect_spake2_confirm(frame: Frame) -> Result<Spake2Confirm, AuthError> {
    match frame {
        Frame::Auth(AuthFrame::Spake2Confirm(confirm)) => Ok(confirm),
        frame => Err(CoreError::Protocol(format!(
            "expected SPAKE2 confirmation, got {frame:?}"
        ))),
    }
}

fn validate_start(start: &Spake2Start) -> Result<(), AuthError> {
    if start.protocol_version != PROTOCOL_VERSION {
        return Err(CoreError::Protocol(format!(
            "unsupported auth protocol version {}",
            start.protocol_version
        )));
    }
    if start.role != PeerRole::Sender {
        return Err(CoreError::Protocol(format!(
            "expected sender SPAKE2 role, got {:?}",
            start.role
        )));
    }
    validate_nonce(&start.nonce)
}

fn validate_nonce(nonce: &[u8]) -> Result<(), AuthError> {
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::Protocol(format!(
            "SPAKE2 nonce must be {NONCE_LEN} bytes"
        )));
    }
    Ok(())
}

struct ConfirmationTranscript<'a> {
    sender_nonce: &'a [u8],
    receiver_nonce: &'a [u8],
    sender_message: &'a [u8],
    receiver_message: &'a [u8],
    exporter: &'a [u8],
}

fn confirmation_proof(
    shared_key: &[u8],
    transcript: &ConfirmationTranscript<'_>,
    proof_label: &[u8],
) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(shared_key).expect("HMAC-SHA256 accepts keys of any length");
    update_confirmation_mac(&mut mac, transcript, proof_label);
    mac.finalize().into_bytes().to_vec()
}

fn verify_confirmation(
    shared_key: &[u8],
    transcript: &ConfirmationTranscript<'_>,
    proof_label: &[u8],
    received_proof: &[u8],
) -> Result<(), AuthError> {
    let expected = confirmation_proof(shared_key, transcript, proof_label);
    if expected != received_proof {
        return Err(CoreError::Crypto(
            "SPAKE2 confirmation proof mismatch".into(),
        ));
    }
    Ok(())
}

fn update_confirmation_mac(
    mac: &mut HmacSha256,
    transcript: &ConfirmationTranscript<'_>,
    proof_label: &[u8],
) {
    update_len_prefixed(mac, SPAKE2_DOMAIN);
    mac.update(&PROTOCOL_VERSION.to_be_bytes());
    update_len_prefixed(mac, SENDER_IDENTITY);
    update_len_prefixed(mac, RECEIVER_IDENTITY);
    update_len_prefixed(mac, transcript.sender_nonce);
    update_len_prefixed(mac, transcript.receiver_nonce);
    update_len_prefixed(mac, transcript.sender_message);
    update_len_prefixed(mac, transcript.receiver_message);
    update_len_prefixed(mac, transcript.exporter);
    update_len_prefixed(mac, proof_label);
}

fn update_len_prefixed(mac: &mut HmacSha256, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use envoix_protocol::{Frame, Ready};
    use envoix_transport::TransportError;
    use tokio::sync::mpsc;

    const TOKEN: &str = "abcdefghijkl";

    #[test]
    fn accepts_ascii_token_at_minimum_length() {
        let config = PairingConfig::spake2_shared_token(TOKEN).unwrap();

        assert_eq!(
            config,
            PairingConfig::Spake2SharedToken {
                token: TOKEN.into()
            }
        );
    }

    #[test]
    fn rejects_short_token() {
        let error = PairingConfig::spake2_shared_token("short").unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    #[test]
    fn rejects_non_ascii_token() {
        let error = PairingConfig::spake2_shared_token("abcdefghijklé").unwrap_err();

        assert!(matches!(error, CoreError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn matching_tokens_complete_auth() {
        let (mut sender, mut receiver) = memory_connection_pair([7_u8; 32], [7_u8; 32]);
        let sender_config = PairingConfig::spake2_shared_token(TOKEN).unwrap();
        let receiver_config = PairingConfig::spake2_shared_token(TOKEN).unwrap();

        let receiver_task =
            tokio::spawn(
                async move { authenticate_receiver(&mut receiver, &receiver_config).await },
            );

        authenticate_sender(&mut sender, &sender_config)
            .await
            .unwrap();
        receiver_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mismatched_tokens_fail_confirmation() {
        let (mut sender, mut receiver) = memory_connection_pair([7_u8; 32], [7_u8; 32]);
        let sender_config = PairingConfig::spake2_shared_token(TOKEN).unwrap();
        let receiver_config = PairingConfig::spake2_shared_token("mnopqrstuvwx").unwrap();

        let receiver_task =
            tokio::spawn(
                async move { authenticate_receiver(&mut receiver, &receiver_config).await },
            );

        let sender_result = authenticate_sender(&mut sender, &sender_config).await;
        let receiver_result = receiver_task.await.unwrap();

        assert!(sender_result.is_err() || receiver_result.is_err());
    }

    #[tokio::test]
    async fn different_channel_bindings_fail_confirmation() {
        let (mut sender, mut receiver) = memory_connection_pair([1_u8; 32], [2_u8; 32]);
        let sender_config = PairingConfig::spake2_shared_token(TOKEN).unwrap();
        let receiver_config = PairingConfig::spake2_shared_token(TOKEN).unwrap();

        let receiver_task =
            tokio::spawn(
                async move { authenticate_receiver(&mut receiver, &receiver_config).await },
            );

        let sender_result = authenticate_sender(&mut sender, &sender_config).await;
        let receiver_result = receiver_task.await.unwrap();

        assert!(sender_result.is_err() || receiver_result.is_err());
    }

    #[test]
    fn confirmation_proofs_are_role_separated() {
        let transcript = ConfirmationTranscript {
            sender_nonce: &[1_u8; NONCE_LEN],
            receiver_nonce: &[2_u8; NONCE_LEN],
            sender_message: b"sender message",
            receiver_message: b"receiver message",
            exporter: &[3_u8; 32],
        };
        let key = b"shared key";

        let sender_proof = confirmation_proof(key, &transcript, SENDER_CONFIRM_LABEL);
        let receiver_proof = confirmation_proof(key, &transcript, RECEIVER_CONFIRM_LABEL);

        assert_ne!(sender_proof, receiver_proof);
    }

    struct MemoryFrameConnection {
        tx: mpsc::Sender<Frame>,
        rx: mpsc::Receiver<Frame>,
        exporter: [u8; 32],
    }

    fn memory_connection_pair(
        sender_exporter: [u8; 32],
        receiver_exporter: [u8; 32],
    ) -> (MemoryFrameConnection, MemoryFrameConnection) {
        let (sender_tx, receiver_rx) = mpsc::channel(16);
        let (receiver_tx, sender_rx) = mpsc::channel(16);

        (
            MemoryFrameConnection {
                tx: sender_tx,
                rx: sender_rx,
                exporter: sender_exporter,
            },
            MemoryFrameConnection {
                tx: receiver_tx,
                rx: receiver_rx,
                exporter: receiver_exporter,
            },
        )
    }

    #[async_trait]
    impl FrameConnection for MemoryFrameConnection {
        async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
            self.tx
                .send(frame)
                .await
                .map_err(|error| CoreError::Transport(error.to_string()))
        }

        async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| CoreError::Transport("memory connection closed".into()))
        }

        fn export_keying_material(
            &self,
            _label: &[u8],
            _context: &[u8],
        ) -> Result<[u8; 32], TransportError> {
            Ok(self.exporter)
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn default_channel_binding_failure_rejects_auth() {
        struct NoBindingConnection;

        #[async_trait]
        impl FrameConnection for NoBindingConnection {
            async fn send_frame(&mut self, _frame: Frame) -> Result<(), TransportError> {
                Ok(())
            }

            async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
                Ok(Frame::Ready(Ready))
            }

            async fn close(&mut self) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let mut connection = NoBindingConnection;
        let config = PairingConfig::spake2_shared_token(TOKEN).unwrap();
        let error = authenticate_sender(&mut connection, &config)
            .await
            .unwrap_err();

        assert!(matches!(error, CoreError::Transport(_)));
    }
}
