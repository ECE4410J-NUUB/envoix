use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use envoix_client::{
    ClientConfig, EnvoixClient, EventSink, PairingConfig, ReceiveFileRequest,
    SPAKE2_EXPERIMENTAL_WARNING, SendFileRequest, TransferDirection, TransferEvent,
};

const IPV4_RECEIVE_ADDR: &str = "0.0.0.0:0";
const IPV6_RECEIVE_ADDR: &str = "[::]:0";

#[derive(Debug, Parser)]
#[command(
    name = "envoix",
    version,
    about = "Secure file transfer CLI",
    after_help = "Typical flow:\n  1. Run `envoix receive --output ./received --token <token> --ip-version ipv4`.\n  2. Copy the printed port and run `envoix send --peer <receiver-ip>:<port> --token <token> <file>`."
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
        peer: SocketAddr,
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
        Command::Send { peer, token, file } => {
            let client = client_for_token(token)?;
            let summary = client
                .send_file(
                    SendFileRequest {
                        peer_addr: peer,
                        file_path: file,
                    },
                    Box::new(ConsoleEventSink),
                )
                .await?;
            eprintln!(
                "sent {} bytes from {}",
                summary.bytes_transferred, summary.file_name
            );
        }
        Command::Receive {
            output,
            token,
            ip_version,
        } => {
            let client = client_for_token(token)?;
            let summary = client
                .receive_file_with_bound_addr(
                    ReceiveFileRequest {
                        listen_addr: receive_addr_for(ip_version),
                        output_dir: output,
                    },
                    Box::new(ConsoleEventSink),
                    |addr| eprintln!("listening on {addr}"),
                )
                .await?;
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

fn client_for_token(token: String) -> Result<EnvoixClient, envoix_client::PublicError> {
    eprintln!("{SPAKE2_EXPERIMENTAL_WARNING}");
    Ok(EnvoixClient::new(ClientConfig::new(
        PairingConfig::spake2_shared_token(token)?,
    )))
}

#[derive(Clone, Copy, Debug)]
struct ConsoleEventSink;

impl EventSink for ConsoleEventSink {
    fn on_event(&self, event: TransferEvent) {
        match event {
            TransferEvent::Started {
                direction,
                file_name,
                total_bytes,
                ..
            } => {
                let verb = match direction {
                    TransferDirection::Send => "sending",
                    TransferDirection::Receive => "receiving",
                };
                eprintln!("{verb} {file_name} ({total_bytes} bytes)");
            }
            TransferEvent::Progress {
                bytes_transferred,
                total_bytes,
                ..
            } => {
                eprintln!("progress {bytes_transferred}/{total_bytes} bytes");
            }
            TransferEvent::Completed {
                bytes_transferred, ..
            } => {
                eprintln!("completed {bytes_transferred} bytes");
            }
        }
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
                token,
                file
            } if peer == "[::1]:9000".parse().unwrap()
                && token == "abcdefghijkl"
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
                token,
                ip_version
            } if output == std::path::Path::new("received")
                && token == "abcdefghijkl"
                && ip_version == IpVersion::Ipv4
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
    fn rejects_missing_token() {
        let error = Cli::try_parse_from(["envoix", "send", "--peer", "[::1]:9000", "hello.txt"])
            .unwrap_err();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
