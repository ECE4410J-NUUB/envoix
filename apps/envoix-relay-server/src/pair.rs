//! `pair`: hand this relay's master key + data-port range to a client via a
//! SPAKE2 handshake (envoix-relay-pair) over a short-lived TCP listener.
//!
//! The relay prints a word-code + QR (the SPAKE2 password + where to connect);
//! the client connects, runs SPAKE2, and receives the sealed credentials. The
//! code is low-entropy by design, so the window is attempt-capped and expiring.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use envoix_qr::{RelayInvitePayload, generate_wordcode, render_terminal_qr};
use envoix_relay_pair::{
    Confirm, MAX_FRAME_BODY, PakeStart, RelayProvision, frame, relay_respond, seal_provision,
    unframe,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::Config;

/// Options for the `pair` subcommand.
pub struct PairArgs {
    pub config: PathBuf,
    pub pairing_port: u16,
    pub public_ip: Option<IpAddr>,
    pub words: usize,
    pub expires_secs: u64,
    pub max_attempts: u32,
}

/// Run a pairing session: discover the endpoint, show the code/QR, then accept
/// pairing attempts until one succeeds or the window closes.
pub async fn run(args: PairArgs) -> Result<(), String> {
    let cfg = Config::load(&args.config).map_err(|e| format!("config: {e}"))?;
    let key_hex = resolve_key_hex(&cfg)?;
    let ports = data_range(&cfg)?;

    // Public IP: placeholder reflexive discovery via a public IP-echo service.
    // TODO: optionally swap for the rdz /relay-probe (also confirms the port is
    // reachable). A public echo is enough for just the IP.
    let public_ip = match args.public_ip {
        Some(ip) => ip,
        None => discover_public_ip().map_err(|e| format!("public-ip discovery: {e}"))?,
    };
    let endpoint = SocketAddr::new(public_ip, args.pairing_port).to_string();

    let code = generate_wordcode(args.words).map_err(|e| format!("word-code: {e}"))?;
    let expires_at = now_unix() + args.expires_secs;
    let invite = RelayInvitePayload::new(code.clone(), endpoint.clone(), ports, expires_at);

    print_invite(&invite, &code, &endpoint, args.expires_secs);

    let provision = RelayProvision { key: key_hex, ports };
    let listener = TcpListener::bind(("0.0.0.0", args.pairing_port))
        .await
        .map_err(|e| format!("cannot listen on :{}: {e}", args.pairing_port))?;

    accept_loop(&listener, &code, &provision, args.expires_secs, args.max_attempts).await
}

/// Accept pairing attempts until one succeeds, the attempt cap is hit, or the
/// window expires.
async fn accept_loop(
    listener: &TcpListener,
    code: &str,
    provision: &RelayProvision,
    expires_secs: u64,
    max_attempts: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(expires_secs);
    let mut attempts = 0u32;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err("pairing window expired before a client paired".into());
        };
        let accepted = tokio::time::timeout(remaining, listener.accept()).await;
        let (mut stream, peer) = match accepted {
            Err(_) => return Err("pairing window expired before a client paired".into()),
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "accept failed; continuing");
                continue;
            }
        };
        match relay_pair_session(&mut stream, code, provision).await {
            Ok(()) => {
                println!("\npaired with {peer} - relay credentials delivered.");
                return Ok(());
            }
            Err(e) => {
                attempts += 1;
                tracing::warn!(%peer, error = %e, attempt = attempts, "pairing attempt failed");
                println!("attempt from {peer} failed ({attempts}/{max_attempts})");
                if attempts >= max_attempts {
                    return Err(format!("gave up after {max_attempts} failed attempts"));
                }
            }
        }
    }
}

/// Drive the relay side of one pairing handshake over `stream`.
async fn relay_pair_session<S>(
    stream: &mut S,
    password: &str,
    provision: &RelayProvision,
) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let start: PakeStart = read_msg(stream).await?;
    let (relay, response) = relay_respond(password, &start).map_err(io::Error::other)?;
    write_msg(stream, &frame(&response).map_err(io::Error::other)?).await?;

    let client_confirm: Confirm = read_msg(stream).await?;
    let (paired, relay_confirm) = relay.verify(&client_confirm).map_err(io::Error::other)?;
    write_msg(stream, &frame(&relay_confirm).map_err(io::Error::other)?).await?;

    let sealed = seal_provision(paired.key(), provision).map_err(io::Error::other)?;
    write_frame(stream, &sealed).await
}

// --- framing helpers (u32 big-endian length + body) ---

/// Read one length-prefixed body.
async fn read_body<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BODY {
        return Err(io::Error::other("frame body too large"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Read and deserialize one framed message.
async fn read_msg<S, T>(stream: &mut S) -> io::Result<T>
where
    S: AsyncReadExt + Unpin,
    T: serde::de::DeserializeOwned,
{
    let body = read_body(stream).await?;
    unframe(&body).map_err(io::Error::other)
}

/// Write already-framed bytes (e.g. from `frame`).
async fn write_msg<S: AsyncWriteExt + Unpin>(stream: &mut S, framed: &[u8]) -> io::Result<()> {
    stream.write_all(framed).await?;
    stream.flush().await
}

/// Write a length-prefixed raw body (the sealed bundle is not JSON).
async fn write_frame<S: AsyncWriteExt + Unpin>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

// --- helpers ---

/// The relay's 64-hex master key, from ENVOIX_RELAY_KEY or the key file
/// (generated on first use).
fn resolve_key_hex(cfg: &Config) -> Result<String, String> {
    if let Ok(hex) = std::env::var("ENVOIX_RELAY_KEY") {
        let hex = hex.trim().to_string();
        return validate_key_hex(hex);
    }
    crate::keyfile::load_or_generate(&cfg.key_file).map_err(|e| format!("relay key: {e}"))?;
    let hex = std::fs::read_to_string(&cfg.key_file)
        .map_err(|e| format!("{}: {e}", cfg.key_file.display()))?
        .trim()
        .to_string();
    validate_key_hex(hex)
}

fn validate_key_hex(hex: String) -> Result<String, String> {
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err("relay key is not 64 hex characters".into())
    }
}

/// `[first, last]` data-port range, or `None` for a single port.
fn data_range(cfg: &Config) -> Result<Option<[u16; 2]>, String> {
    let ports = cfg.listen_ports(cfg.listen.port())?;
    Ok((ports.len() > 1).then(|| [ports[0], ports[ports.len() - 1]]))
}

/// Placeholder reflexive discovery: ask a public IP-echo service for our
/// public IPv4. The relay can't see its own public IP behind NAT.
fn discover_public_ip() -> io::Result<IpAddr> {
    let out = Command::new("curl")
        .args(["-4", "-sS", "--max-time", "8", "https://api.ipify.org"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip-echo failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let body = String::from_utf8_lossy(&out.stdout);
    body.trim()
        .parse::<IpAddr>()
        .map_err(|_| io::Error::other(format!("unexpected ip-echo reply: {:?}", body.trim())))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn print_invite(invite: &RelayInvitePayload, code: &str, endpoint: &str, expires_secs: u64) {
    if let Some(qr) = render_terminal_qr(&invite.encode()) {
        println!("{qr}");
    }
    println!("Pair this relay with a client:");
    println!("  code:     {code}");
    println!("  endpoint: {endpoint}");
    println!("  expires:  in {expires_secs}s");
    println!("Scan the QR or enter the code on the client. Waiting for a client...");
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoix_relay_pair::{client_start, open_provision};

    /// Client side of the handshake, mirroring `relay_pair_session`, used only
    /// to drive the round-trip test (the real client lives elsewhere).
    async fn client_pair_session<S>(stream: &mut S, password: &str) -> io::Result<RelayProvision>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (client, start) = client_start(password).map_err(io::Error::other)?;
        write_msg(stream, &frame(&start).map_err(io::Error::other)?).await?;

        let response = read_msg(stream).await?;
        let (confirming, client_confirm) = client.finish(&response).map_err(io::Error::other)?;
        write_msg(stream, &frame(&client_confirm).map_err(io::Error::other)?).await?;

        let relay_confirm: Confirm = read_msg(stream).await?;
        let paired = confirming.verify(&relay_confirm).map_err(io::Error::other)?;

        let sealed = read_body(stream).await?;
        open_provision(paired.key(), &sealed).map_err(io::Error::other)
    }

    #[tokio::test]
    async fn pairing_round_trip_over_a_pipe() {
        let (mut relay_side, mut client_side) = tokio::io::duplex(8192);
        let provision = RelayProvision { key: "ab".repeat(32), ports: Some([9100, 9105]) };

        let relay = {
            let provision = provision.clone();
            tokio::spawn(async move {
                relay_pair_session(&mut relay_side, "42-galaxy-pencil", &provision).await
            })
        };
        let got = client_pair_session(&mut client_side, "42-galaxy-pencil")
            .await
            .expect("client pairs");
        relay.await.unwrap().expect("relay pairs");
        assert_eq!(got, provision);
    }

    #[tokio::test]
    async fn wrong_code_fails_both_sides() {
        let (mut relay_side, mut client_side) = tokio::io::duplex(8192);
        let provision = RelayProvision { key: "cd".repeat(32), ports: None };
        let relay = tokio::spawn(async move {
            relay_pair_session(&mut relay_side, "11-correct-code", &provision).await
        });
        // Client uses the wrong code -> confirmation must fail, no bundle.
        let result = client_pair_session(&mut client_side, "99-wrong-code-x").await;
        assert!(result.is_err());
        assert!(relay.await.unwrap().is_err());
    }

    /// End-to-end: a paired client uses the delivered master key to mint its
    /// own relay tokens (custom relay -> the client is the issuer), then two
    /// peers register and transfer a multi-datagram "file" through a real
    /// relay bound with the same key. Proves the pairing actually authorizes
    /// relay use.
    #[tokio::test]
    async fn paired_client_registers_and_transfers_a_file() {
        use std::sync::Arc;
        use std::time::{Duration, SystemTime};

        use envoix_relay::{RelayConfig, RelayRole, RelaySessionId, RelayTokenKey, encode};
        use tokio::net::UdpSocket;

        use crate::server::RelayServer;

        // The custom relay's master key. In production it lives in the relay's
        // key file; `pair` reads it and seals it to the client over SPAKE2.
        let master = [0x5au8; 32];
        let master_hex: String = master.iter().map(|b| format!("{b:02x}")).collect();

        // 1) Pair: deliver {key, ports} to a mock client over an in-memory pipe.
        let provision = RelayProvision { key: master_hex, ports: Some([9100, 9105]) };
        let code = "31-relay-pair";
        let (mut relay_side, mut client_side) = tokio::io::duplex(8192);
        let relay_pair = {
            let provision = provision.clone();
            tokio::spawn(async move {
                relay_pair_session(&mut relay_side, code, &provision).await
            })
        };
        let paired = client_pair_session(&mut client_side, code).await.expect("client pairs");
        relay_pair.await.unwrap().expect("relay pairs");
        assert_eq!(paired, provision);

        // 2) Mint: the client turns the delivered key into its own tokens.
        let client_key = RelayTokenKey::from_hex(&paired.key).expect("paired key is valid hex");
        let session = RelaySessionId::from_bytes([0xa5; 16]);
        let expires = SystemTime::now() + Duration::from_secs(300);
        let sender_token = client_key.mint(&session, RelayRole::Sender, expires);
        let receiver_token = client_key.mint(&session, RelayRole::Receiver, expires);

        // 3) Run a real relay bound with the SAME master key.
        let usage_path = std::env::temp_dir()
            .join(format!("envoix-pair-int-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&usage_path);
        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            &[0],
            RelayTokenKey::from_bytes(master),
            RelayConfig::default(),
            u64::MAX,
            usage_path.clone(),
        )
        .await
        .expect("bind relay");
        let server = Arc::new(server);
        let relay_addr = server.local_addrs()[0];
        {
            let run = server.clone();
            tokio::spawn(async move { run.run().await });
        }

        // 4) Register + file transfer: sender registers, receiver streams the
        //    "file" chunk by chunk; the relay cross-forwards each bare payload.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&encode(&sender_token, b"hello"), relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let file: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 512]).collect();
        let mut received = Vec::new();
        let mut buf = [0u8; 2048];
        for chunk in &file {
            receiver.send_to(&encode(&receiver_token, chunk), relay_addr).await.unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(1), sender.recv_from(&mut buf))
                .await
                .expect("forward timed out")
                .expect("recv");
            received.push(buf[..n].to_vec());
        }
        assert_eq!(received, file, "relay forwarded the file intact");

        let _ = std::fs::remove_file(&usage_path);
    }
}
