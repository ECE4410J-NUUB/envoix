use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use envoix_client::{
    ClientConfig, ConnectionPolicy, EnvoixClient, EventSink, NoopClientEventSink, PairingConfig,
    ReceiveFileRequest, SPAKE2_EXPERIMENTAL_WARNING, SendFileRequest, SendRequest,
    TransferDirection, TransferEvent,
};
use envoix_qr::{QrInvitePayload, generate_token, render_terminal_qr};

const IPV4_RECEIVE_ADDR: &str = "0.0.0.0:0";
const IPV6_RECEIVE_ADDR: &str = "[::]:0";
const PROGRESS_RENDER_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Parser)]
#[command(
    name = "envoix",
    version,
    about = "Secure file transfer CLI",
    after_help = "Manual flow:
    envoix receive --output ./received --token <token>
    envoix send --peer <receiver-ip>:<port> --token <token> <file>

QR flow (no manual token or address needed):
    envoix receive --auto --output ./received
    envoix send --invite <invite-string> <file>
"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send one file to a receiver address printed by `envoix receive`.
    Send {
        /// Receiver address (manual mode). Cannot be combined with --invite.
        #[arg(long, conflicts_with = "invite")]
        peer: Option<SocketAddr>,
        /// Use automatic discovery (placeholder). Cannot be combined with --invite.
        #[arg(long, conflicts_with = "invite")]
        auto: bool,
        /// Shared ASCII pairing token (≥12 bytes). Required unless --invite is set.
        #[arg(long, required_unless_present = "invite", conflicts_with = "invite")]
        token: Option<String>,
        /// Invite string printed by `envoix receive --auto`; sets peer and token automatically.
        #[arg(long, conflicts_with_all = ["peer", "auto", "token"])]
        invite: Option<String>,
        /// File to send.
        file: PathBuf,
    },
    /// Receive one file into an output directory.
    Receive {
        /// Directory where the received file and resume state are stored.
        #[arg(long)]
        output: PathBuf,
        /// Generate a random token and print a QR invite; cannot be combined with --token.
        #[arg(long)]
        auto: bool,
        /// Shared ASCII pairing token (≥12 bytes). Required unless --auto is set.
        #[arg(long)]
        token: Option<String>,
        /// Address family to bind for receiving.
        #[arg(long, value_enum, default_value_t = IpVersion::Ipv4)]
        ip_version: IpVersion,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum IpVersion {
    Ipv4,
    Ipv6,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), envoix_client::PublicError> {
    match cli.command {
        Command::Send {
            peer,
            auto,
            token,
            invite,
            file,
        } => {
            let summary = if let Some(invite_str) = invite {
                let payload =
                    envoix_qr::QrInvitePayload::decode(&invite_str).map_err(|e| {
                        envoix_client::PublicError::InvalidInput(format!("invalid invite: {e}"))
                    })?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                payload.validate(now).map_err(|e| {
                    envoix_client::PublicError::InvalidInput(format!("invalid invite: {e}"))
                })?;
                let peer_addr = payload.first_candidate().map_err(|e| {
                    envoix_client::PublicError::InvalidInput(format!("invalid invite: {e}"))
                })?;
                let expires_in = payload.expires_at.saturating_sub(now);
                eprintln!(
                    "connecting to {peer_addr} (invite expires in {})",
                    format_duration(Duration::from_secs(expires_in))
                );
                client_for_token(payload.token)?
                    .send_file(
                        SendFileRequest {
                            peer_addr,
                            file_path: file,
                        },
                        Box::new(ConsoleEventSink::new()),
                    )
                    .await?
            } else if auto {
                if peer.is_some() {
                    return Err(envoix_client::PublicError::InvalidInput(
                        "use either --auto or --peer, not both".into(),
                    ));
                }
                let token = token.expect("clap ensures --token is present with --auto");
                client_for_token(token)?
                    .send(
                        SendRequest {
                            file_path: file,
                            connection_policy: ConnectionPolicy::Auto,
                        },
                        Box::new(NoopClientEventSink),
                    )
                    .await?
            } else {
                let peer = peer.ok_or_else(|| {
                    envoix_client::PublicError::InvalidInput(
                        "send requires --peer unless --auto or --invite is set".into(),
                    )
                })?;
                let token = token.expect("clap ensures --token is present without --invite");
                client_for_token(token)?
                    .send_file(
                        SendFileRequest {
                            peer_addr: peer,
                            file_path: file,
                        },
                        Box::new(ConsoleEventSink::new()),
                    )
                    .await?
            };
            eprintln!(
                "sent {} bytes from {}",
                summary.bytes_transferred, summary.file_name
            );
        }
        Command::Receive {
            output,
            auto,
            token,
            ip_version,
        } => {
            let summary = if auto {
                if token.is_some() {
                    return Err(envoix_client::PublicError::InvalidInput(
                        "use either --auto or --token, not both".into(),
                    ));
                }
                let generated = generate_token().map_err(|e| {
                    envoix_client::PublicError::InvalidInput(format!(
                        "failed to generate token: {e}"
                    ))
                })?;
                let client = client_for_token(generated.clone())?;
                let expires_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 300;
                client
                    .receive_file_with_bound_addr(
                        ReceiveFileRequest {
                            listen_addr: receive_addr_for(ip_version),
                            output_dir: output,
                        },
                        Box::new(ConsoleEventSink::new()),
                        |bound_addr| {
                            let candidates = build_candidates(bound_addr, ip_version);
                            let payload =
                                QrInvitePayload::new(generated, candidates, expires_at);
                            match payload.encode() {
                                Ok(invite) => {
                                    let qr = render_terminal_qr(&invite);
                                    eprint!("{qr}");
                                    eprintln!("invite: {invite}");
                                    eprintln!("waiting for sender...");
                                }
                                Err(e) => eprintln!("warning: could not encode invite: {e}"),
                            }
                        },
                    )
                    .await?
            } else {
                let token = token.ok_or_else(|| {
                    envoix_client::PublicError::InvalidInput(
                        "receive requires --token unless --auto is set".into(),
                    )
                })?;
                client_for_token(token)?
                    .receive_file_with_bound_addr(
                        ReceiveFileRequest {
                            listen_addr: receive_addr_for(ip_version),
                            output_dir: output,
                        },
                        Box::new(ConsoleEventSink::new()),
                        |addr| eprintln!("listening on {addr}"),
                    )
                    .await?
            };
            eprintln!(
                "received {} bytes into {}",
                summary.bytes_transferred, summary.file_name
            );
        }
    }

    Ok(())
}

fn receive_addr_for(ip_version: IpVersion) -> SocketAddr {
    let addr = match ip_version {
        IpVersion::Ipv4 => IPV4_RECEIVE_ADDR,
        IpVersion::Ipv6 => IPV6_RECEIVE_ADDR,
    };
    addr.parse().expect("default receive address is valid")
}

/// Builds the candidate list for a QR invite from the listener's bound address.
///
/// Uses a UDP socket trick to find the machine's outbound LAN IP, then pairs
/// it with the bound port.  Falls back to the bound address itself if detection
/// fails (e.g. offline machine or unusual network config).
fn build_candidates(bound_addr: SocketAddr, ip_version: IpVersion) -> Vec<String> {
    let port = bound_addr.port();
    let ip = detect_local_ip(ip_version).unwrap_or(bound_addr.ip());
    vec![SocketAddr::new(ip, port).to_string()]
}

/// Probes the OS routing table to find the preferred outbound LAN IP without
/// sending any packets (connect on UDP never transmits data).
fn detect_local_ip(ip_version: IpVersion) -> Option<IpAddr> {
    match ip_version {
        IpVersion::Ipv4 => {
            let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
            socket.connect("8.8.8.8:80").ok()?;
            Some(socket.local_addr().ok()?.ip())
        }
        IpVersion::Ipv6 => {
            let socket = UdpSocket::bind("[::]:0").ok()?;
            socket.connect("[2001:4860:4860::8888]:80").ok()?;
            Some(socket.local_addr().ok()?.ip())
        }
    }
}

fn client_for_token(token: String) -> Result<EnvoixClient, envoix_client::PublicError> {
    eprintln!("{SPAKE2_EXPERIMENTAL_WARNING}");
    Ok(EnvoixClient::new(ClientConfig::new(
        PairingConfig::spake2_shared_token(token)?,
    )))
}

#[derive(Debug, Default)]
struct ConsoleEventSink {
    progress: Mutex<Option<ProgressState>>,
}

impl ConsoleEventSink {
    fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
struct ProgressState {
    file_name: String,
    direction: TransferDirection,
    total_bytes: u64,
    started_at: Instant,
    last_rendered_at: Instant,
}

impl EventSink for ConsoleEventSink {
    fn on_event(&self, event: TransferEvent) {
        match event {
            TransferEvent::Started {
                direction,
                file_name,
                total_bytes,
                ..
            } => {
                let state = ProgressState {
                    file_name,
                    direction,
                    total_bytes,
                    started_at: Instant::now(),
                    last_rendered_at: Instant::now(),
                };
                render_progress_line(&state, 0, false);
                *self.progress.lock().unwrap() = Some(state);
            }
            TransferEvent::Progress {
                bytes_transferred, ..
            } => {
                if let Some(state) = self.progress.lock().unwrap().as_mut()
                    && state.last_rendered_at.elapsed() >= PROGRESS_RENDER_INTERVAL
                {
                    render_progress_line(state, bytes_transferred, false);
                    state.last_rendered_at = Instant::now();
                }
            }
            TransferEvent::Completed {
                bytes_transferred, ..
            } => {
                let state = self.progress.lock().unwrap().take();
                if let Some(state) = state {
                    render_progress_line(&state, bytes_transferred, true);
                } else {
                    eprintln!("completed {bytes_transferred} bytes");
                }
            }
        }
    }
}

fn render_progress_line(state: &ProgressState, bytes_transferred: u64, done: bool) {
    let percent = bytes_transferred
        .saturating_mul(100)
        .checked_div(state.total_bytes)
        .unwrap_or(100);
    let elapsed = state.started_at.elapsed();
    let bytes_per_second = if elapsed.is_zero() {
        0.0
    } else {
        bytes_transferred as f64 / elapsed.as_secs_f64()
    };
    let eta = eta(bytes_transferred, state.total_bytes, bytes_per_second);
    let verb = match state.direction {
        TransferDirection::Send => "send",
        TransferDirection::Receive => "recv",
    };
    let line = format!(
        "{:<24} {:>4}% {:>9}/{:<9} {:>10}/s {:>5}",
        format!("{verb} {}", display_file_name(&state.file_name)),
        percent.min(100),
        format_bytes(bytes_transferred),
        format_bytes(state.total_bytes),
        format_bytes(bytes_per_second as u64),
        eta,
    );

    let mut stderr = io::stderr().lock();
    if done {
        let _ = writeln!(stderr, "\r{line:<80}");
    } else {
        let _ = write!(stderr, "\r{line:<80}");
        let _ = stderr.flush();
    }
}

fn display_file_name(file_name: &str) -> String {
    const MAX_LEN: usize = 19;

    if file_name.chars().count() <= MAX_LEN {
        return file_name.to_owned();
    }

    let suffix: String = file_name
        .chars()
        .rev()
        .take(MAX_LEN - 1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("~{suffix}")
}

fn eta(bytes_transferred: u64, total_bytes: u64, bytes_per_second: f64) -> String {
    if bytes_transferred >= total_bytes {
        return "00:00".into();
    }
    if bytes_transferred == 0 || bytes_per_second <= 0.0 {
        return "--:--".into();
    }

    let remaining = total_bytes - bytes_transferred;
    format_duration(Duration::from_secs_f64(remaining as f64 / bytes_per_second))
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    format!("{minutes:02}:{seconds:02}")
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut value = bytes as f64;
    let mut unit = UNITS[0];
    for next_unit in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next_unit;
    }

    if unit == "B" {
        format!("{bytes}B")
    } else if value < 10.0 {
        format!("{value:.1}{unit}")
    } else {
        format!("{value:.0}{unit}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_send_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            "[::1]:9000",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer,
                auto,
                ref token,
                invite: None,
                ref file,
            } if peer == Some("[::1]:9000".parse().unwrap())
                && !auto
                && token.as_deref() == Some("abcdefghijkl")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_send_auto_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--auto",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer: None,
                auto: true,
                ref token,
                invite: None,
                ref file,
            } if token.as_deref() == Some("abcdefghijkl")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_receive_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "receive",
            "--output",
            "received",
            "--token",
            "abcdefghijkl",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                output,
                auto,
                token: Some(ref token),
                ip_version
            } if output == std::path::Path::new("received")
                && !auto
                && token == "abcdefghijkl"
                && ip_version == IpVersion::Ipv4
        ));
    }

    #[test]
    fn parses_receive_auto_command() {
        let cli = Cli::try_parse_from(["envoix", "receive", "--auto", "--output", "received"])
            .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                output,
                auto: true,
                token: None,
                ..
            } if output == std::path::Path::new("received")
        ));
    }

    #[test]
    fn parses_receive_with_explicit_token() {
        let cli = Cli::try_parse_from([
            "envoix",
            "receive",
            "--output",
            "received",
            "--token",
            "abcdefghijkl",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                auto: false,
                token: Some(ref t),
                ..
            } if t == "abcdefghijkl"
        ));
    }

    #[test]
    fn parses_receive_ipv6() {
        let cli = Cli::try_parse_from([
            "envoix",
            "receive",
            "--output",
            "received",
            "--token",
            "abcdefghijkl",
            "--ip-version",
            "ipv6",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                ip_version: IpVersion::Ipv6,
                ..
            }
        ));
    }

    #[test]
    fn parses_send_invite_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--invite",
            "envoix:dGVzdA",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer: None,
                auto: false,
                token: None,
                ref invite,
                ref file,
            } if invite.as_deref() == Some("envoix:dGVzdA")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn rejects_missing_token() {
        let error = Cli::try_parse_from(["envoix", "send", "--peer", "[::1]:9000", "hello.txt"])
            .unwrap_err();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
