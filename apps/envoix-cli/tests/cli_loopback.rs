use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn cli_transfers_file_over_ipv6_loopback() {
    let root = unique_test_dir();
    let source_dir = root.join("source");
    let output_dir = root.join("received");
    fs::create_dir_all(&source_dir).unwrap();

    let source_path = source_dir.join("hello.txt");
    let source_text = b"hello from the cli";
    fs::write(&source_path, source_text).unwrap();

    let listen_addr = free_ipv6_loopback_addr();
    let mut receiver = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .arg("receive")
        .arg("--listen")
        .arg(listen_addr.to_string())
        .arg("--output")
        .arg(&output_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // TODO: should use other approaches other than fixed time sleep.
    // but this is not easy to solve.
    thread::sleep(Duration::from_millis(200));

    let send_output = Command::new(env!("CARGO_BIN_EXE_envoix"))
        .arg("send")
        .arg("--peer")
        .arg(listen_addr.to_string())
        .arg(&source_path)
        .output()
        .unwrap();

    if !send_output.status.success() {
        let _ = receiver.kill();
        panic!(
            "send failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&send_output.stdout),
            String::from_utf8_lossy(&send_output.stderr)
        );
    }

    let receiver_status = wait_for_child(&mut receiver, Duration::from_secs(5))
        .unwrap_or_else(|| {
            let _ = receiver.kill();
            panic!("receiver did not exit after one transfer");
        })
        .unwrap();

    if !receiver_status.success() {
        panic!("receiver failed\nstderr:\n{}", read_stderr(receiver));
    }

    assert_eq!(fs::read(output_dir.join("hello.txt")).unwrap(), source_text);

    fs::remove_dir_all(root).unwrap();
}

fn free_ipv6_loopback_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    listener.local_addr().unwrap()
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

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("envoix-cli-test-{}-{nanos}", std::process::id()))
}
