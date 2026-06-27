use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use envoix_protocol::PeerDescriptor;
use envoix_qr::QrInvitePayload;

const TOKEN: &str = "abcdefghijkl";
const WRONG_TOKEN: &str = "mnopqrstuvwx";
const MDNS_TOKEN: &str = "abcdefghijkl-mdns";

fn test_peer_descriptor() -> PeerDescriptor {
    PeerDescriptor::new(
        "peer",
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)],
    )
    .unwrap()
}

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
    let peer = loopback_peer_for(&receiver.peer);

    let send_output = run_send_with_retries(&peer, &source_path, WRONG_TOKEN);
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

    let invite = loopback_invite(&receiver.invite_str);
    let send_output = retry_send(|| run_send_with_invite(&invite, &source_path));

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
}

#[test]
fn qr_receiver_keeps_waiting_after_wrong_token() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("retry_after_wrong_token.txt");
    let source_text = b"hello after wrong QR token";
    fs::write(&source_path, source_text).unwrap();

    let mut receiver = spawn_receiver_auto(&output_dir);
    let wrong_invite = loopback_invite_with_token(&receiver.invite_str, WRONG_TOKEN);

    let wrong_output = run_send_with_invite(&wrong_invite, &source_path);
    assert!(
        !wrong_output.status.success(),
        "wrong-token invite unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&wrong_output.stdout),
        String::from_utf8_lossy(&wrong_output.stderr)
    );
    assert!(
        wait_for_child(&mut receiver.child, Duration::from_millis(250)).is_none(),
        "receiver exited after failed QR authentication"
    );

    let invite = loopback_invite(&receiver.invite_str);
    let send_output = retry_send(|| run_send_with_invite(&invite, &source_path));

    if !send_output.status.success() {
        let _ = receiver.child.kill();
        panic!(
            "send --invite failed after wrong-token attempt\nstdout:\n{}\nstderr:\n{}",
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
        panic!("receiver failed after retry");
    }

    assert_eq!(
        fs::read(output_dir.join("retry_after_wrong_token.txt")).unwrap(),
        source_text
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_enable_mdns_flow() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("mdns.txt");
    let source_text = b"hello via iroh mdns";
    fs::write(&source_path, source_text).unwrap();

    let mut receiver = spawn_receiver_enable_mdns(&output_dir, MDNS_TOKEN);
    let send_output = run_send_enable_mdns(&source_path, MDNS_TOKEN);

    if !send_output.status.success() {
        let _ = receiver.child.kill();
        panic!(
            "send --enable-mdns failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&send_output.stdout),
            String::from_utf8_lossy(&send_output.stderr)
        );
    }

    let receiver_status = wait_for_child(&mut receiver.child, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = receiver.child.kill();
            panic!("receiver did not exit after mDNS transfer");
        })
        .unwrap();

    if !receiver_status.success() {
        panic!("receiver failed\nstderr:\n{}", read_stderr(receiver.child));
    }

    assert_eq!(fs::read(output_dir.join("mdns.txt")).unwrap(), source_text);
}

// The next two tests pass a nonexistent file ("ignored.txt") on purpose: invite
// validation must reject the invite before the sender ever opens the file or
// dials the peer, so a missing file never matters.

#[test]
fn send_with_expired_invite_fails() {
    let expired = QrInvitePayload::new(
        "abcdefghijkl".into(),
        test_peer_descriptor(),
        0, // expires_at = 0 → always in the past
    )
    .encode();

    let output = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .args(["send", "--invite", &expired, "ignored.txt"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "expected non-zero exit for expired invite"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "expected 'expired' in stderr, got: {stderr}"
    );
}

#[test]
fn send_with_version_mismatched_invite_fails() {
    let mut payload = QrInvitePayload::new("abcdefghijkl".into(), test_peer_descriptor(), u64::MAX);
    payload.version = 99;
    let invite = payload.encode();

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
    let peer = loopback_peer_for(&receiver.peer);

    let send_output = run_send_with_retries(&peer, &source_path, TOKEN);

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
}

struct SpawnedReceiver {
    child: Child,
    peer: PeerDescriptor,
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
    let peer = read_bound_peer(&mut child);
    SpawnedReceiver { child, peer }
}

struct SpawnedAutoReceiver {
    child: Child,
    invite_str: String,
    /// Drains receiver stderr after the invite line so the pipe buffer never
    /// fills up and blocks the child process.
    _stderr_drain: thread::JoinHandle<()>,
}

fn spawn_receiver_auto(output_dir: &Path) -> SpawnedAutoReceiver {
    let mut child = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .args(["receive", "--enable-mdns", "--output"])
        .arg(output_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Take ownership of stderr so we can hand the handle to the drain thread
    // after extracting the invite.  Once taken, child.stderr is None, which
    // is fine: read_stderr() on failure will just return an empty string.
    let stderr = child.stderr.take().unwrap();
    let (invite_str, drain) = extract_invite_and_drain(stderr);
    SpawnedAutoReceiver {
        child,
        invite_str,
        _stderr_drain: drain,
    }
}

fn spawn_receiver_enable_mdns(output_dir: &Path, token: &str) -> SpawnedReceiver {
    let mut receiver_command = Command::new(env!("CARGO_BIN_EXE_envoix"));
    receiver_command
        .arg("receive")
        .arg("--enable-mdns")
        .arg("--output")
        .arg(output_dir)
        .arg("--token")
        .arg(token);
    let mut child = receiver_command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let peer = read_bound_peer(&mut child);
    SpawnedReceiver { child, peer }
}

/// Scans `stderr` line by line for the `invite: envoix:...` line, then
/// spawns a thread that drains any remaining output so the pipe buffer cannot
/// fill and deadlock the child.
fn extract_invite_and_drain(stderr: ChildStderr) -> (String, thread::JoinHandle<()>) {
    let mut reader = BufReader::new(stderr);
    let invite = loop {
        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .expect("reading receiver stderr");
        if bytes_read == 0 {
            panic!("receiver exited before printing invite");
        }
        if let Some(s) = line.trim_end_matches(['\n', '\r']).strip_prefix("invite: ") {
            break s.trim().to_string();
        }
    };
    let drain = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while reader.read(&mut buf).unwrap_or(0) > 0 {}
    });
    (invite, drain)
}

fn run_send_with_invite(invite: &str, source_path: &Path) -> Output {
    run_with_timeout(
        Command::new(env!("CARGO_BIN_EXE_envoix"))
            .arg("send")
            .arg("--invite")
            .arg(invite)
            .arg(source_path),
        Duration::from_secs(10),
    )
}

fn run_send_enable_mdns(source_path: &Path, token: &str) -> Output {
    run_with_timeout(
        Command::new(env!("CARGO_BIN_EXE_envoix"))
            .arg("send")
            .arg("--enable-mdns")
            .arg("--token")
            .arg(token)
            .arg(source_path),
        Duration::from_secs(15),
    )
}

fn run_send_with_retries(peer: &PeerDescriptor, source_path: &Path, token: &str) -> Output {
    retry_send(|| run_send_once(peer, source_path, token))
}

/// Runs a send closure, retrying while the receiver's QUIC listener is still
/// coming up.  Both the manual `--peer` and the QR `--invite` flows print the
/// receiver address from the same point, so both can race the listener and
/// need this guard against transient "Connection refused".
fn retry_send(mut send: impl FnMut() -> Output) -> Output {
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        let output = send();
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

fn run_send_once(peer: &PeerDescriptor, source_path: &Path, token: &str) -> Output {
    let mut send_command = Command::new(env!("CARGO_BIN_EXE_envoix"));
    send_command
        .arg("send")
        .arg("--peer")
        .arg(peer.to_string())
        .arg("--token")
        .arg(token);
    send_command.arg(source_path).output().unwrap()
}

fn loopback_invite(invite: &str) -> String {
    loopback_invite_with(invite, |payload| payload.token.clone())
}

fn loopback_invite_with_token(invite: &str, token: &str) -> String {
    loopback_invite_with(invite, |_| token.to_string())
}

fn loopback_invite_with(invite: &str, token: impl FnOnce(&QrInvitePayload) -> String) -> String {
    let mut payload = QrInvitePayload::decode(invite).unwrap();
    let port = payload.peer.direct_addrs[0].port();
    payload.token = token(&payload);
    payload.peer.direct_addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)];
    payload.encode()
}

fn run_with_timeout(command: &mut Command, timeout: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait().unwrap() {
            Some(_) => return child.wait_with_output().unwrap(),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            None => {
                let _ = child.kill();
                let mut output = child.wait_with_output().unwrap();
                output
                    .stderr
                    .extend_from_slice(b"\nsend command timed out in test\n");
                return output;
            }
        }
    }
}

fn loopback_peer_for(peer: &PeerDescriptor) -> PeerDescriptor {
    let port = peer.direct_addrs[0].port();
    PeerDescriptor::new(
        peer.endpoint_id.clone(),
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
    )
    .unwrap()
}

fn read_bound_peer(child: &mut Child) -> PeerDescriptor {
    let stderr = child.stderr.as_mut().unwrap();
    let mut line = String::new();
    let mut byte = [0_u8; 1];

    loop {
        stderr.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            if let Some(peer) = line.strip_prefix("peer: ") {
                return peer.trim().parse().unwrap();
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

struct TestDir(tempfile::TempDir);

impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

fn unique_test_dir() -> TestDir {
    TestDir(
        tempfile::Builder::new()
            .prefix("envoix-cli-test-")
            .tempdir()
            .unwrap(),
    )
}
