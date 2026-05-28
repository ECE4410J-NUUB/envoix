use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use envoix_client::{
    ClientConfig, EnvoixClient, EventSink, PairingConfig, ReceiveFileRequest,
    SPAKE2_EXPERIMENTAL_WARNING, SendFileRequest, TransferDirection, TransferEvent,
};

#[derive(Debug, Parser)]
#[command(name = "envoix", version, about = "Secure file transfer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Send {
        #[arg(long)]
        peer: SocketAddr,
        #[arg(long)]
        token: String,
        file: PathBuf,
    },
    Receive {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        token: String,
    },
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
            listen,
            output,
            token,
        } => {
            let client = client_for_token(token)?;
            let summary = client
                .receive_file(
                    ReceiveFileRequest {
                        listen_addr: listen,
                        output_dir: output,
                    },
                    Box::new(ConsoleEventSink),
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
            "--listen",
            "[::1]:9000",
            "--output",
            "received",
            "--token",
            "abcdefghijkl",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::Receive {
                listen,
                output,
                token
            } if listen == "[::1]:9000".parse().unwrap()
                && output == std::path::Path::new("received")
                && token == "abcdefghijkl"
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
