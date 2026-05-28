//! QUIC transport implementation.
//!
//! This crate intentionally uses generated self-signed certificates and an
//! insecure no-auth client verifier. The p2p auth relies on the pairing.  

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use envoix_error::CoreError;
use envoix_protocol::{Frame, read_frame, write_frame};
use envoix_transport::{
    ConnectionCandidate, FrameConnection, TransportDialer, TransportError, TransportListener,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const STREAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default)]
/// QUIC dialer that opens one bidirectional stream per transfer.
pub struct QuicDialer;

#[async_trait]
impl TransportDialer for QuicDialer {
    async fn dial(
        &self,
        candidate: ConnectionCandidate,
    ) -> Result<Box<dyn FrameConnection>, TransportError> {
        let ConnectionCandidate::Quic { addr } = candidate;

        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint =
            Endpoint::client(bind_addr).map_err(|error| CoreError::Transport(error.to_string()))?;
        endpoint.set_default_client_config(insecure_no_auth_client_config()?);

        let connection = endpoint
            .connect(addr, "localhost")
            .map_err(|error| CoreError::Transport(error.to_string()))?
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;

        Ok(Box::new(QuicFrameConnection {
            _endpoint: endpoint,
            connection,
            send,
            recv,
        }))
    }
}

#[derive(Debug)]
/// QUIC listener that accepts one bidirectional stream per connection.
pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    /// Binds a QUIC endpoint to `addr` using the insecure no-auth skeleton config.
    pub fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let endpoint = Endpoint::server(insecure_no_auth_server_config()?, addr)
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        Ok(Self { endpoint })
    }

    /// Returns the operating system assigned local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|error| CoreError::Transport(error.to_string()))
    }
}

#[async_trait]
impl TransportListener for QuicListener {
    async fn accept(&self) -> Result<Box<dyn FrameConnection>, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| CoreError::Transport("QUIC listener closed".into()))?;
        let connection = incoming
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;

        Ok(Box::new(QuicFrameConnection {
            _endpoint: self.endpoint.clone(),
            connection,
            send,
            recv,
        }))
    }
}

#[derive(Debug)]
struct QuicFrameConnection {
    _endpoint: Endpoint,
    connection: quinn::Connection,
    send: SendStream,
    recv: RecvStream,
}

#[async_trait]
impl FrameConnection for QuicFrameConnection {
    async fn send_frame(&mut self, frame: Frame) -> Result<(), TransportError> {
        write_frame(&mut self.send, &frame).await
    }

    async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
        read_frame(&mut self.recv).await
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], TransportError> {
        let mut output = [0_u8; 32];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|error| CoreError::Transport(format!("{error:?}")))?;
        Ok(output)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        let _ = tokio::time::timeout(STREAM_DRAIN_TIMEOUT, self.send.stopped()).await;
        Ok(())
    }
}

fn insecure_no_auth_server_config() -> Result<quinn::ServerConfig, TransportError> {
    install_rustls_crypto_provider();
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    let cert = CertificateDer::from(certified_key.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified_key.key_pair.serialize_der(),
    ));
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|error| CoreError::Transport(error.to_string()))?;
    let quic_crypto = QuicServerConfig::try_from(server_crypto)
        .map_err(|error| CoreError::Transport(error.to_string()))?;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport_config(shared_transport_config());
    Ok(config)
}

fn insecure_no_auth_client_config() -> Result<quinn::ClientConfig, TransportError> {
    install_rustls_crypto_provider();
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureNoAuthServerVerifier))
        .with_no_client_auth();
    let quic_crypto = QuicClientConfig::try_from(client_crypto)
        .map_err(|error| CoreError::Transport(error.to_string()))?;

    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(shared_transport_config());
    Ok(config)
}

fn shared_transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .max_idle_timeout(Some(MAX_IDLE_TIMEOUT.try_into().unwrap()))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    Arc::new(config)
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
struct InsecureNoAuthServerVerifier;

impl ServerCertVerifier for InsecureNoAuthServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoix_protocol::{Frame, Ready};

    #[tokio::test]
    async fn quic_transport_exchanges_frames_over_ipv4() {
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        let receiver = tokio::spawn(async move {
            let mut connection = listener.accept().await.unwrap();
            assert_eq!(connection.recv_frame().await.unwrap(), Frame::Ready(Ready));
            connection.send_frame(Frame::Ready(Ready)).await.unwrap();
            let _ = done_rx.await;
        });

        let dialer = QuicDialer;
        let mut connection = dialer
            .dial(ConnectionCandidate::Quic { addr })
            .await
            .unwrap();

        connection.send_frame(Frame::Ready(Ready)).await.unwrap();
        assert_eq!(connection.recv_frame().await.unwrap(), Frame::Ready(Ready));
        let _ = done_tx.send(());

        receiver.await.unwrap();
    }
}
