use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use envoix_client::{
    ClientConfig, ClientEvent, ConnectionPolicy, EnvoixClient, EventSink, IdentityConfig,
    PairingConfig, PeerDescriptor, ReceiveFileRequest, ReceiveRequest, SPAKE2_EXPERIMENTAL_WARNING,
    SendFileRequest, SendRequest, TransferDirection, TransferEvent,
};
use envoix_qr::{QrInvitePayload, generate_token, render_terminal_qr};

const IPV4_RECEIVE_ADDR: &str = "0.0.0.0:0";
const IPV6_RECEIVE_ADDR: &str = "[::]:0";
const PROGRESS_RENDER_INTERVAL: Duration = Duration::from_millis(250);
/// Lifetime of a generated QR invite before it is considered expired.
const INVITE_TTL_SECS: u64 = 300;

#[derive(Debug, Parser)]
#[command(
    name = "envoix",
    version,
    about = "Secure file transfer CLI",
    after_help = "Manual flow:
    envoix receive --output ./received --token <token>
    envoix send --peer <endpoint-id>@<receiver-ip>:<port> --token <token> <file>

QR flow (no manual token or address needed):
    envoix receive --enable-mdns --output ./received
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
        /// Receiver peer descriptor (manual mode). Cannot be combined with --invite.
        #[arg(long, conflicts_with = "invite")]
        peer: Option<PeerDescriptor>,
        /// Explicit TOML config file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Use iroh mDNS discovery when available. Cannot be combined with --invite.
        #[arg(long, conflicts_with = "invite")]
        enable_mdns: bool,
        /// Persistent iroh identity file. Created if missing.
        #[arg(long, conflicts_with = "ephemeral_identity")]
        identity: Option<PathBuf>,
        /// Use a fresh iroh identity for this run.
        #[arg(long)]
        ephemeral_identity: bool,
        /// Start a new transfer and ignore compatible receiver-side resume state.
        #[arg(long = "fresh", action = ArgAction::SetFalse, default_value_t = true)]
        resume: bool,
        /// Shared ASCII pairing token (>=12 bytes). Required unless --invite is set.
        #[arg(long, required_unless_present = "invite", conflicts_with = "invite")]
        token: Option<String>,
        /// Invite string printed by `envoix receive --enable-mdns`; sets peer and token automatically.
        #[arg(long, conflicts_with_all = ["peer", "enable_mdns", "token"])]
        invite: Option<String>,
        /// File to send.
        file: PathBuf,
    },
    /// Receive one file into an output directory.
    Receive {
        /// Directory where the received file and resume state are stored.
        #[arg(long)]
        output: PathBuf,
        /// Explicit TOML config file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Enable iroh mDNS/address discovery. When used without
        /// --token, generates a random token and prints a QR invite.
        #[arg(long, visible_alias = "auto")]
        enable_mdns: bool,
        /// Persistent iroh identity file. Created if missing.
        #[arg(long, conflicts_with = "ephemeral_identity")]
        identity: Option<PathBuf>,
        /// Use a fresh iroh identity for this run.
        #[arg(long)]
        ephemeral_identity: bool,
        /// Shared ASCII pairing token (>=12 bytes). Required unless --enable-mdns is set.
        #[arg(long, required_unless_present = "enable_mdns")]
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
    init_tracing();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Initialize the tracing subscriber.  Honors `RUST_LOG`, defaulting to
/// `warn` for the workspace and `error` for everything else so that library
/// warnings (e.g. resume-state corruption notices) reach the terminal
/// without flooding it.  Output goes to stderr to keep stdout clean for
/// future machine-consumable formats.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("envoix=warn,warn"));
    fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .init();
}

async fn run(cli: Cli) -> Result<(), envoix_client::PublicError> {
    match cli.command {
        Command::Send {
            peer,
            config,
            enable_mdns,
            identity,
            ephemeral_identity: _,
            resume,
            token,
            invite,
            file,
        } => {
            let summary = if let Some(invite_str) = invite {
                let resolved = resolve_invite(&invite_str)?;
                eprintln!(
                    "connecting to {} (invite expires in {})",
                    resolved.peer,
                    format_duration(Duration::from_secs(resolved.expires_in))
                );
                client_for_token(resolved.token, config.as_deref(), identity_config(identity))?
                    .send_file(
                        SendFileRequest {
                            peer: resolved.peer,
                            file_path: file,
                            resume,
                        },
                        Box::new(ConsoleEventSink::new()),
                    )
                    .await?
            } else if enable_mdns {
                if peer.is_some() {
                    return Err(envoix_client::PublicError::InvalidInput(
                        "use either --enable-mdns or --peer, not both".into(),
                    ));
                }
                let token = token.expect("clap ensures --token is present with --enable-mdns");
                client_for_token(token, config.as_deref(), identity_config(identity))?
                    .send(
                        SendRequest {
                            file_path: file,
                            connection_policy: ConnectionPolicy::EnableMdns,
                            resume,
                        },
                        Box::new(ConsoleClientEventSink),
                        Box::new(ConsoleEventSink::new()),
                    )
                    .await?
            } else {
                let peer = peer.ok_or_else(|| {
                    envoix_client::PublicError::InvalidInput(
                        "send requires --peer unless --enable-mdns or --invite is set".into(),
                    )
                })?;
                let token = token.expect("clap ensures --token is present without --invite");
                client_for_token(token, config.as_deref(), identity_config(identity))?
                    .send_file(
                        SendFileRequest {
                            peer,
                            file_path: file,
                            resume,
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
            config,
            enable_mdns,
            identity,
            ephemeral_identity: _,
            token,
            ip_version,
        } => {
            let listen_addr = receive_addr_for(ip_version);
            let identity = identity_config(identity);
            let summary = if enable_mdns {
                match token {
                    Some(t) => {
                        let token_for_print = t.clone();
                        let client = client_for_token(t, config.as_deref(), identity)?;
                        eprintln!("waiting for sender...");
                        client
                            .receive(
                                ReceiveRequest {
                                    output_dir: output,
                                    connection_policy: ConnectionPolicy::EnableMdns,
                                    listen_addr,
                                },
                                Box::new(ConsoleClientEventSink),
                                Box::new(ConsoleEventSink::new()),
                                move |peer| {
                                    eprintln!("peer: {peer}");
                                    eprintln!("token: {token_for_print}");
                                },
                            )
                            .await?
                    }
                    None => {
                        // Auto-generate token and print QR invite for the sender.
                        let generated = generate_token().map_err(|e| {
                            envoix_client::PublicError::InvalidInput(format!(
                                "failed to generate token: {e}"
                            ))
                        })?;
                        let token_for_qr = generated.clone();
                        let client = client_for_token(generated, config.as_deref(), identity)?;
                        eprintln!("waiting for sender...");
                        client
                            .receive(
                                ReceiveRequest {
                                    output_dir: output,
                                    connection_policy: ConnectionPolicy::EnableMdns,
                                    listen_addr,
                                },
                                Box::new(ConsoleClientEventSink),
                                Box::new(ConsoleEventSink::new()),
                                move |peer| {
                                    let payload = QrInvitePayload::new(
                                        token_for_qr,
                                        peer.clone(),
                                        unix_now() + INVITE_TTL_SECS,
                                    );
                                    let invite = payload.encode();
                                    eprintln!("peer: {peer}");
                                    eprintln!("\ninvite: {invite}");
                                    if let Some(qr) = render_terminal_qr(&invite) {
                                        eprintln!("{qr}");
                                    }
                                },
                            )
                            .await?
                    }
                }
            } else {
                let token = token.expect("clap requires --token unless --enable-mdns is set");
                let token_for_print = token.clone();
                client_for_token(token, config.as_deref(), identity)?
                    .receive_file_with_bound_peer(
                        ReceiveFileRequest {
                            listen_addr: receive_addr_for(ip_version),
                            output_dir: output,
                        },
                        Box::new(ConsoleEventSink::new()),
                        move |peer| {
                            eprintln!("peer: {peer}");
                            eprintln!("token: {token_for_print}");
                        },
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

/// Resolved fields extracted from a validated QR invite.
struct ResolvedInvite {
    peer: PeerDescriptor,
    token: String,
    expires_in: u64,
}

/// Decodes and validates an invite string, returning the fields the sender needs.
///
/// Validation (including expiry and version checks) runs before any connection
/// is attempted, so a stale or incompatible invite fails fast.
fn resolve_invite(invite: &str) -> Result<ResolvedInvite, envoix_client::PublicError> {
    let to_err = |e| envoix_client::PublicError::InvalidInput(format!("invalid invite: {e}"));

    let payload = QrInvitePayload::decode(invite).map_err(to_err)?;
    let now = unix_now();
    payload.validate(now).map_err(to_err)?;
    let peer = payload.peer_descriptor().map_err(to_err)?;

    Ok(ResolvedInvite {
        peer,
        token: payload.token,
        expires_in: payload.expires_at.saturating_sub(now),
    })
}

/// Current Unix time in whole seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn client_for_token(
    token: String,
    config_path: Option<&std::path::Path>,
    identity: IdentityConfig,
) -> Result<EnvoixClient, envoix_client::PublicError> {
    eprintln!("{SPAKE2_EXPERIMENTAL_WARNING}");
    let pairing = PairingConfig::spake2_shared_token(token)?;
    let mut config = ClientConfig::from_runtime_sources(pairing, config_path)?;
    config.identity = identity;
    Ok(EnvoixClient::new(config))
}

fn identity_config(path: Option<PathBuf>) -> IdentityConfig {
    path.map(IdentityConfig::Persistent)
        .unwrap_or(IdentityConfig::Ephemeral)
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
            TransferEvent::HashStarted {
                direction,
                file_name,
                bytes_to_hash,
                ..
            } => {
                render_hash_line(direction, &file_name, bytes_to_hash, false);
            }
            TransferEvent::HashCompleted {
                direction,
                file_name,
                bytes_hashed,
                ..
            } => {
                render_hash_line(direction, &file_name, bytes_hashed, true);
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
            TransferEvent::Failed { direction, reason } => {
                let state = self.progress.lock().unwrap().take();
                if let Some(state) = state {
                    render_transfer_failure_line(&state, &reason);
                } else {
                    render_attempt_failure_line(direction, &reason);
                }
            }
        }
    }
}

/// A [`ClientEventSink`] that logs client lifecycle events to stderr.
#[derive(Clone, Copy, Debug)]
struct ConsoleClientEventSink;

impl envoix_client::ClientEventSink for ConsoleClientEventSink {
    fn on_event(&self, event: ClientEvent) {
        match event {
            ClientEvent::NetworkDetectionStarted => {
                eprintln!("detecting network environment...");
            }
            ClientEvent::EndpointStarted { direction } => {
                let dir = match direction {
                    TransferDirection::Send => "send",
                    TransferDirection::Receive => "receive",
                };
                eprintln!("starting {dir} endpoint...");
            }
            ClientEvent::DirectAddressAvailable { peer } => {
                eprintln!("  direct address: {peer}");
            }
            ClientEvent::DialStarted { peer } => {
                eprintln!("dialing {peer}...");
            }
            ClientEvent::Authenticated { direction } => {
                let dir = match direction {
                    TransferDirection::Send => "send",
                    TransferDirection::Receive => "receive",
                };
                eprintln!("authenticated {dir} peer");
            }
            ClientEvent::ConnectionFailed { reason } => {
                eprintln!("  connection failed: {reason}");
            }
            ClientEvent::TooManyAuthFailures => {
                eprintln!(
                    "  failed pairing attempts exceeded threshold: another peer may be using the wrong token or interfering"
                );
            }
        }
    }
}

fn render_hash_line(direction: TransferDirection, file_name: &str, bytes_hashed: u64, done: bool) {
    let verb = match direction {
        TransferDirection::Send => "send",
        TransferDirection::Receive => "recv",
    };
    let status = if done { "verified" } else { "verifying" };
    let line = format!(
        "{:<24} {:>9} {}",
        format!("{verb} {}", display_file_name(file_name)),
        format_bytes(bytes_hashed),
        status,
    );

    let mut stderr = io::stderr().lock();
    if done {
        let _ = writeln!(stderr, "\r{line:<80}");
    } else {
        let _ = write!(stderr, "\r{line:<80}");
        let _ = stderr.flush();
    }
}

fn render_transfer_failure_line(state: &ProgressState, reason: &str) {
    let verb = match state.direction {
        TransferDirection::Send => "send",
        TransferDirection::Receive => "recv",
    };
    let line = format!(
        "{:<24} failed: {}",
        format!("{verb} {}", display_file_name(&state.file_name)),
        reason
    );
    eprintln!("\r{line:<80}");
}

fn render_attempt_failure_line(direction: TransferDirection, reason: &str) {
    let verb = match direction {
        TransferDirection::Send => "send",
        TransferDirection::Receive => "recv",
    };
    eprintln!("{verb} attempt failed: {reason}");
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

    const PEER: &str = "peer@[::1]:9000";

    #[test]
    fn parses_send_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            PEER,
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer,
                config: None,
                enable_mdns,
                resume,
                ref token,
                invite: None,
                ref file,
                ..
            } if peer == Some(PEER.parse().unwrap())
                && !enable_mdns
                && resume
                && token.as_deref() == Some("abcdefghijkl")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_send_enable_mdns_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--enable-mdns",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer: None,
                config: None,
                enable_mdns: true,
                resume: true,
                ref token,
                invite: None,
                ref file,
                ..
            } if token.as_deref() == Some("abcdefghijkl")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_send_fresh_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            PEER,
            "--fresh",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(cli.command, Command::Send { resume: false, .. }));
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
                config: None,
                enable_mdns,
                token: Some(ref token),
                ip_version,
                ..
            } if output == std::path::Path::new("received")
                && !enable_mdns
                && token == "abcdefghijkl"
                && ip_version == IpVersion::Ipv4
        ));
    }

    #[test]
    fn parses_receive_enable_mdns_command() {
        let cli =
            Cli::try_parse_from(["envoix", "receive", "--enable-mdns", "--output", "received"])
                .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                output,
                enable_mdns: true,
                token: None,
                ..
            } if output == std::path::Path::new("received")
        ));
    }

    #[test]
    fn parses_receive_auto_alias() {
        let cli =
            Cli::try_parse_from(["envoix", "receive", "--auto", "--output", "received"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                enable_mdns: true,
                ..
            }
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
                enable_mdns: false,
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
        let cli = Cli::try_parse_from(["envoix", "send", "--invite", "envoix:dGVzdA", "hello.txt"])
            .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                peer: None,
                config: None,
                enable_mdns: false,
                resume: true,
                token: None,
                ref invite,
                ref file,
                ..
            } if invite.as_deref() == Some("envoix:dGVzdA")
                && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_explicit_config_path() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            PEER,
            "--config",
            "envoix.toml",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Send {
                config,
                ..
            } if config == Some(std::path::PathBuf::from("envoix.toml"))
        ));
    }

    #[test]
    fn rejects_missing_token() {
        let error =
            Cli::try_parse_from(["envoix", "send", "--peer", PEER, "hello.txt"]).unwrap_err();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn receive_enable_mdns_with_token_is_valid() {
        assert!(
            Cli::try_parse_from([
                "envoix",
                "receive",
                "--enable-mdns",
                "--output",
                "recv",
                "--token",
                "abcdefghijkl",
            ])
            .is_ok()
        );
    }

    #[test]
    fn receive_enable_mdns_without_token_is_valid() {
        assert!(
            Cli::try_parse_from(["envoix", "receive", "--enable-mdns", "--output", "recv",])
                .is_ok()
        );
    }

    #[test]
    fn rejects_send_invite_with_peer() {
        assert!(
            Cli::try_parse_from([
                "envoix",
                "send",
                "--invite",
                "envoix:dGVzdA",
                "--peer",
                PEER,
                "f.txt",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_send_invite_with_token() {
        assert!(
            Cli::try_parse_from([
                "envoix",
                "send",
                "--invite",
                "envoix:dGVzdA",
                "--token",
                "abcdefghijkl",
                "f.txt",
            ])
            .is_err()
        );
    }
}
