use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use envoix_client::{
    ClientConfig, ConnectionPolicy, EnvoixClient, EventSink, NoopClientEventSink, PairingConfig,
    ReceiveFileRequest, ReceiveRequest, SPAKE2_EXPERIMENTAL_WARNING, SendFileRequest, SendRequest,
    TransferDirection, TransferEvent,
};

const IPV4_RECEIVE_ADDR: &str = "0.0.0.0:0";
const IPV6_RECEIVE_ADDR: &str = "[::]:0";
const PROGRESS_RENDER_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Parser)]
#[command(
    name = "envoix",
    version,
    about = "Secure file transfer CLI",
    after_help = "Typical flow:
1. Run `envoix receive --output ./received --token <token> --ip-version ipv4`.
2. Copy the printed port and run `envoix send --peer <receiver-ip>:<port> --token <token> <file>`.

Future automatic flow:
    envoix receive --auto --output ./received --token <token>
    envoix send --auto --token <token> <file>
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
        /// Receiver address, using the port printed by `envoix receive`.
        #[arg(long)]
        peer: Option<SocketAddr>,
        /// Explicit TOML config file path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Use automatic discovery, pairing, and connection setup.
        #[arg(long)]
        auto: bool,
        /// Resume from compatible receiver-side state.
        #[arg(long)]
        resume: bool,
        /// Shared ASCII pairing token, at least 12 bytes.
        #[arg(long)]
        token: String,
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
        /// Use automatic discovery, pairing, and connection setup.
        #[arg(long)]
        auto: bool,
        /// Shared ASCII pairing token, at least 12 bytes.
        #[arg(long)]
        token: String,
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
            config,
            auto,
            resume,
            token,
            file,
        } => {
            let client = client_for_token(token, config.as_deref())?;
            let summary = if auto {
                if peer.is_some() {
                    return Err(envoix_client::PublicError::InvalidInput(
                        "use either --auto or --peer, not both".into(),
                    ));
                }
                client
                    .send(
                        SendRequest {
                            file_path: file,
                            connection_policy: ConnectionPolicy::Auto,
                            resume,
                        },
                        Box::new(NoopClientEventSink),
                    )
                    .await?
            } else {
                let peer = peer.ok_or_else(|| {
                    envoix_client::PublicError::InvalidInput(
                        "send requires --peer unless --auto is set".into(),
                    )
                })?;
                client
                    .send_file(
                        SendFileRequest {
                            peer_addr: peer,
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
            auto,
            token,
            ip_version,
        } => {
            let client = client_for_token(token, config.as_deref())?;
            let summary = if auto {
                client
                    .receive(
                        ReceiveRequest {
                            output_dir: output,
                            connection_policy: ConnectionPolicy::Auto,
                        },
                        Box::new(NoopClientEventSink),
                    )
                    .await?
            } else {
                client
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

fn client_for_token(
    token: String,
    config_path: Option<&std::path::Path>,
) -> Result<EnvoixClient, envoix_client::PublicError> {
    eprintln!("{SPAKE2_EXPERIMENTAL_WARNING}");
    let pairing = PairingConfig::spake2_shared_token(token)?;
    Ok(EnvoixClient::new(ClientConfig::from_runtime_sources(
        pairing,
        config_path,
    )?))
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
                config: None,
                auto,
                resume,
                token,
                file
            } if peer == Some("[::1]:9000".parse().unwrap())
                && !auto
                && !resume
                && token == "abcdefghijkl"
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
                config: None,
                auto: true,
                resume: false,
                token,
                file
            } if token == "abcdefghijkl" && file == std::path::Path::new("hello.txt")
        ));
    }

    #[test]
    fn parses_send_resume_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            "[::1]:9000",
            "--resume",
            "--token",
            "abcdefghijkl",
            "hello.txt",
        ])
        .unwrap();

        assert!(matches!(cli.command, Command::Send { resume: true, .. }));
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
                auto,
                token,
                ip_version
            } if output == std::path::Path::new("received")
                && !auto
                && token == "abcdefghijkl"
                && ip_version == IpVersion::Ipv4
        ));
    }

    #[test]
    fn parses_receive_auto_command() {
        let cli = Cli::try_parse_from([
            "envoix",
            "receive",
            "--auto",
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
                auto: true,
                token,
                ..
            } if output == std::path::Path::new("received") && token == "abcdefghijkl"
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
    fn parses_explicit_config_path() {
        let cli = Cli::try_parse_from([
            "envoix",
            "send",
            "--peer",
            "[::1]:9000",
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
        let error = Cli::try_parse_from(["envoix", "send", "--peer", "[::1]:9000", "hello.txt"])
            .unwrap_err();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
