use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use envoix_qr::QrInvitePayload;

const TOKEN: &str = "abcdefghijkl";
const WRONG_TOKEN: &str = "mnopqrstuvwx";

#[test]
fn cli_transfers_file_over_default_quic_loopback() {
    run_cli_loopback();
}

#[test]
fn cli_wrong_token_does_not_finalize_or_create_sidecar() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("secret.txt");
    fs::write(&source_path, b"must not be received").unwrap();
    let mut receiver = spawn_receiver(&output_dir, TOKEN);
    let listen_addr = loopback_addr_for(receiver.bound_addr);

    let send_output = run_send_with_retries(listen_addr, &source_path, WRONG_TOKEN);
    assert!(
        !send_output.status.success(),
        "send unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&send_output.stdout),
        String::from_utf8_lossy(&send_output.stderr)
    );

    let receiver_status = wait_for_child(&mut receiver.child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = receiver.child.kill();
            panic!("receiver did not exit after failed auth");
        })
        .unwrap();
    assert!(
        !receiver_status.success(),
        "receiver unexpectedly succeeded\nstderr:\n{}",
        read_stderr(receiver.child)
    );

    assert!(!output_dir.join("secret.txt").exists());
    assert_no_sidecars(&output_dir);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn qr_invite_loopback() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("qr_test.txt");
    let source_text = b"hello via QR invite";
    fs::write(&source_path, source_text).unwrap();

    let mut receiver = spawn_receiver_auto(&output_dir);

    let send_output = run_send_with_invite(&receiver.invite_str, &source_path);

    if !send_output.status.success() {
        let _ = receiver.child.kill();
        panic!(
            "send --invite failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&send_output.stdout),
            String::from_utf8_lossy(&send_output.stderr)
        );
    }

    let receiver_status = wait_for_child(&mut receiver.child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = receiver.child.kill();
            panic!("receiver did not exit after QR invite transfer");
        })
        .unwrap();

    if !receiver_status.success() {
        panic!("receiver failed\nstderr:\n{}", read_stderr(receiver.child));
    }

    assert_eq!(
        fs::read(output_dir.join("qr_test.txt")).unwrap(),
        source_text
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn send_with_expired_invite_fails() {
    let expired = QrInvitePayload::new(
        "abcdefghijkl".into(),
        vec!["127.0.0.1:9000".into()],
        0, // expires_at = 0 → always in the past
    )
    .encode()
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .args(["send", "--invite", &expired, "ignored.txt"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "expected non-zero exit for expired invite");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "expected 'expired' in stderr, got: {stderr}"
    );
}

#[test]
fn send_with_version_mismatched_invite_fails() {
    let mut payload = QrInvitePayload::new(
        "abcdefghijkl".into(),
        vec!["127.0.0.1:9000".into()],
        u64::MAX,
    );
    payload.version = 99;
    let invite = payload.encode().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .args(["send", "--invite", &invite, "ignored.txt"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "expected non-zero exit for version-mismatched invite"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("version"),
        "expected 'version' in stderr, got: {stderr}"
    );
}

fn run_cli_loopback() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("hello.txt");
    let source_text = b"hello from the cli";
    fs::write(&source_path, source_text).unwrap();

    let mut receiver = spawn_receiver(&output_dir, TOKEN);
    let listen_addr = loopback_addr_for(receiver.bound_addr);

    let send_output = run_send_with_retries(listen_addr, &source_path, TOKEN);

    if !send_output.status.success() {
        let _ = receiver.child.kill();
        panic!(
            "send failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&send_output.stdout),
            String::from_utf8_lossy(&send_output.stderr)
        );
    }

    let receiver_status = wait_for_child(&mut receiver.child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = receiver.child.kill();
            panic!("receiver did not exit after one transfer");
        })
        .unwrap();

    if !receiver_status.success() {
        panic!("receiver failed\nstderr:\n{}", read_stderr(receiver.child));
    }

    assert_eq!(fs::read(output_dir.join("hello.txt")).unwrap(), source_text);

    fs::remove_dir_all(root).unwrap();
}

struct SpawnedReceiver {
    child: Child,
    bound_addr: SocketAddr,
}

fn spawn_receiver(output_dir: &Path, token: &str) -> SpawnedReceiver {
    let mut receiver_command = Command::new(env!("CARGO_BIN_EXE_envoix"));
    receiver_command
        .arg("receive")
        .arg("--output")
        .arg(output_dir)
        .arg("--token")
        .arg(token);
    let mut child = receiver_command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let bound_addr = read_bound_addr(&mut child);
    SpawnedReceiver { child, bound_addr }
}

struct SpawnedAutoReceiver {
    child: Child,
    invite_str: String,
}

fn spawn_receiver_auto(output_dir: &Path) -> SpawnedAutoReceiver {
    let mut child = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .args(["receive", "--auto", "--output"])
        .arg(output_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let invite_str = read_invite_str(&mut child);
    SpawnedAutoReceiver { child, invite_str }
}

/// Reads stderr line by line until it finds the `invite: envoix:...` line.
fn read_invite_str(child: &mut Child) -> String {
    let stderr = child.stderr.as_mut().unwrap();
    let mut line = String::new();
    let mut byte = [0_u8; 1];

    loop {
        stderr.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            if let Some(invite) = line.strip_prefix("invite: ") {
                return invite.trim().to_string();
            }
            line.clear();
        } else {
            line.push(byte[0] as char);
        }
    }
}

fn run_send_with_invite(invite: &str, source_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envoix"))
        .arg("send")
        .arg("--invite")
        .arg(invite)
        .arg(source_path)
        .output()
        .unwrap()
}

fn run_send_with_retries(listen_addr: SocketAddr, source_path: &Path, token: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        let output = run_send_once(listen_addr, source_path, token);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() || !stderr.contains("Connection refused") {
            return output;
        }
        if Instant::now() >= deadline {
            return output;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_send_once(listen_addr: SocketAddr, source_path: &Path, token: &str) -> Output {
    let mut send_command = Command::new(env!("CARGO_BIN_EXE_envoix"));
    send_command
        .arg("send")
        .arg("--peer")
        .arg(listen_addr.to_string())
        .arg("--token")
        .arg(token);
    send_command.arg(source_path).output().unwrap()
}

fn loopback_addr_for(bound_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound_addr.port())
}

fn read_bound_addr(child: &mut Child) -> SocketAddr {
    let stderr = child.stderr.as_mut().unwrap();
    let mut line = String::new();
    let mut byte = [0_u8; 1];

    loop {
        stderr.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            if let Some(addr) = line.strip_prefix("listening on ") {
                return addr.trim().parse().unwrap();
            }
            line.clear();
        } else {
            line.push(byte[0] as char);
        }
    }
}

fn wait_for_child(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::io::Result<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(Ok(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        }
    }
}

fn read_stderr(mut child: Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return String::new();
    };

    let mut output = String::new();
    stderr.read_to_string(&mut output).unwrap();
    output
}

fn assert_no_sidecars(output_dir: &Path) {
    if !output_dir.exists() {
        return;
    }

    let sidecars: Vec<_> = fs::read_dir(output_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json") || name.ends_with(".part"))
        })
        .collect();

    assert!(sidecars.is_empty(), "unexpected sidecars: {sidecars:?}");
}

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("envoix-cli-test-{}-{nanos}", std::process::id()))
}
