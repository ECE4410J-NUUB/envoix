//! Preflight diagnostics: check the local environment and tell the operator
//! what is wrong and how to fix it. Local checks only; external reachability
//! needs the rendezvous-assisted probe (separate work).

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use crate::config::Config;

enum Status {
    Pass,
    Warn,
    Fail,
}

struct Check {
    status: Status,
    name: &'static str,
    detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self { status: Status::Pass, name, detail: detail.into() }
    }
    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self { status: Status::Warn, name, detail: detail.into() }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self { status: Status::Fail, name, detail: detail.into() }
    }
}

/// Run all checks against the effective config and exit non-zero on any FAIL.
pub fn run(config_path: &Path) {
    let cfg = Config::load(config_path).unwrap_or_else(|e| {
        eprintln!("error: config: {e}");
        std::process::exit(1);
    });

    let mut checks = vec![
        check_bind(cfg.listen),
        check_firewall(cfg.listen.port()),
        check_clock(),
        check_key_perms(&cfg.key_file),
        check_state_dir(&cfg.usage_file),
    ];
    // External reachability: only when a rendezvous URL is configured (this
    // is the one check that makes a network call).
    if let Some(c) = check_reachability(&cfg) {
        checks.push(c);
    }

    let mut failed = false;
    for c in &checks {
        let tag = match c.status {
            Status::Pass => "[ OK ]",
            Status::Warn => "[WARN]",
            Status::Fail => {
                failed = true;
                "[FAIL]"
            }
        };
        println!("{tag} {}: {}", c.name, c.detail);
    }
    if failed {
        std::process::exit(1);
    }
}

fn check_bind(listen: SocketAddr) -> Check {
    match std::net::UdpSocket::bind(listen) {
        Ok(_) => Check::pass("bind", format!("can bind {listen}")),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            Check::warn("bind", format!("{listen} in use (relay already running?)"))
        }
        Err(e) => Check::fail("bind", format!("cannot bind {listen}: {e}")),
    }
}

fn check_firewall(port: u16) -> Check {
    if let Some(out) = run_cmd("ufw", &["status"]) {
        let lower = out.to_lowercase();
        if lower.contains("you need to be root") || lower.contains("permission denied") {
            return Check::warn("firewall (ufw)", "re-run with sudo to verify the rule");
        }
        if lower.contains("status: inactive") {
            return Check::pass("firewall (ufw)", "inactive, not blocking");
        }
        if ufw_port_allowed(&out, port) {
            return Check::pass("firewall (ufw)", format!("{port}/udp allowed"));
        }
        return Check::warn(
            "firewall (ufw)",
            format!("no rule for {port}/udp; run: sudo ufw allow {port}/udp"),
        );
    }
    if let Some(state) = run_cmd("firewall-cmd", &["--state"])
        && state.to_lowercase().contains("running")
    {
        let ports = run_cmd("firewall-cmd", &["--list-ports"]).unwrap_or_default();
        if firewalld_port_open(&ports, port) {
            return Check::pass("firewall (firewalld)", format!("{port}/udp open"));
        }
        return Check::warn(
            "firewall (firewalld)",
            format!(
                "{port}/udp not open; run: sudo firewall-cmd --add-port={port}/udp \
                 --permanent && sudo firewall-cmd --reload"
            ),
        );
    }
    if run_cmd("nft", &["--version"]).is_some() || run_cmd("iptables", &["--version"]).is_some() {
        return Check::warn(
            "firewall",
            format!("nftables/iptables present; cannot auto-verify - ensure UDP {port} is open"),
        );
    }
    Check::pass(
        "firewall",
        format!("no host firewall detected; if unreachable, check your provider's security group for UDP {port}"),
    )
}

fn check_clock() -> Check {
    match run_cmd("timedatectl", &["status"]) {
        Some(out) if clock_synchronized(&out) => Check::pass("clock", "NTP-synchronized"),
        Some(_) => Check::warn(
            "clock",
            "system clock not NTP-synchronized; token expiry needs an accurate clock",
        ),
        None => Check::warn(
            "clock",
            "cannot check time sync (timedatectl absent); ensure the clock is accurate",
        ),
    }
}

fn check_key_perms(path: &Path) -> Check {
    if !path.exists() {
        return Check::pass(
            "key file",
            format!("{} absent (generated on first run)", path.display()),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(m) => {
                let mode = m.permissions().mode() & 0o777;
                if mode & 0o077 == 0 {
                    Check::pass("key file", format!("{} ({mode:o})", path.display()))
                } else {
                    Check::warn(
                        "key file",
                        format!(
                            "{} is {mode:o}, should be 600: chmod 600 {}",
                            path.display(),
                            path.display()
                        ),
                    )
                }
            }
            Err(e) => Check::warn("key file", format!("{}: {e}", path.display())),
        }
    }
    #[cfg(not(unix))]
    {
        Check::pass("key file", "present")
    }
}

fn check_state_dir(usage_file: &Path) -> Check {
    let dir = usage_file.parent().unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        return Check::warn(
            "state dir",
            format!("{} does not exist (created on first run if permitted)", dir.display()),
        );
    }
    let probe = dir.join(".envoix-relay-write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Check::pass("state dir", format!("{} writable", dir.display()))
        }
        Err(e) => Check::fail("state dir", format!("{} not writable: {e}", dir.display())),
    }
}

/// External reachability via the rendezvous prober. `None` when no rendezvous
/// URL is configured, so the check (and its network call) is skipped.
///
/// `test` is often run before the relay is started, so if the port is free we
/// briefly answer the probe ourselves - the round-trip still proves the port
/// is reachable from the internet. If the relay is already running, it echoes
/// the probe instead. Unreachable is a WARN, not a FAIL: the firewall or
/// port-forward may legitimately not be open yet at preflight time.
fn check_reachability(cfg: &Config) -> Option<Check> {
    let url = cfg.rendezvous_url.as_deref()?;
    let port = cfg.listen.port();
    let echo = spawn_echo_responder(cfg.listen);
    let result = rendezvous_probe(url, port);
    if let Some(h) = echo {
        let _ = h.join();
    }
    Some(match result {
        Ok(true) => Check::pass(
            "reachability",
            format!("rendezvous reached udp/{port} from the internet"),
        ),
        Ok(false) => Check::warn(
            "reachability",
            format!(
                "rendezvous could NOT reach udp/{port}; check NAT/port-forward \
                 and the provider's security group"
            ),
        ),
        Err(e) => Check::warn("reachability", format!("probe could not run: {e}")),
    })
}

/// Bind the relay port and echo one probe datagram. `None` if the port is in
/// use (the running relay answers) or cannot be bound.
fn spawn_echo_responder(listen: SocketAddr) -> Option<std::thread::JoinHandle<()>> {
    let sock = std::net::UdpSocket::bind(listen).ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok()?;
    Some(std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if envoix_relay::parse_probe(&buf[..n]).is_some() => {
                    let _ = sock.send_to(&buf[..n], from);
                    return;
                }
                Ok(_) => continue, // stray packet; keep waiting for a probe
                Err(_) => return,  // read timeout / error
            }
        }
    }))
}

/// Ask the rendezvous to probe this relay's `port` on our own public IP, and
/// return whether the echo came back. Uses the system `curl` (the rendezvous
/// is HTTPS via Cloudflare) - consistent with the other checks shelling out
/// to system tools, and keeps the static binary free of a TLS stack.
fn rendezvous_probe(base_url: &str, port: u16) -> Result<bool, String> {
    let url = format!("{}/api/v1/relay-probe", base_url.trim_end_matches('/'));
    let body = format!("{{\"port\":{port}}}");
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "8",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ])
        .output()
        .map_err(|e| format!("curl not available: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl failed: {}", err.trim()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("bad probe response: {e}"))?;
    v.get("reachable")
        .and_then(|r| r.as_bool())
        .ok_or_else(|| "malformed probe response".to_string())
}

/// Run a command, returning combined stdout+stderr, or `None` if the binary
/// is absent or could not be spawned.
fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

fn ufw_port_allowed(status: &str, port: u16) -> bool {
    let needle = format!("{port}/udp");
    status
        .lines()
        .any(|l| l.contains(&needle) && l.to_uppercase().contains("ALLOW"))
}

/// True if `port/udp` is covered by a firewalld `--list-ports` token, which is
/// either a single port (`9104/udp`) or an inclusive range (`9100-9105/udp`).
fn firewalld_port_open(ports: &str, port: u16) -> bool {
    ports.split_whitespace().any(|t| {
        let Some((spec, "udp")) = t.split_once('/') else { return false };
        match spec.split_once('-') {
            Some((lo, hi)) => matches!(
                (lo.parse::<u16>(), hi.parse::<u16>()),
                (Ok(lo), Ok(hi)) if lo <= port && port <= hi
            ),
            None => spec.parse::<u16>() == Ok(port),
        }
    })
}

fn clock_synchronized(timedatectl: &str) -> bool {
    timedatectl.lines().any(|l| {
        let l = l.to_lowercase();
        l.contains("system clock synchronized") && l.contains("yes")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufw_rule_detected() {
        let out = "Status: active\n\nTo Action From\n-- ------ ----\n9104/udp ALLOW Anywhere";
        assert!(ufw_port_allowed(out, 9104));
        assert!(!ufw_port_allowed(out, 9105));
    }

    #[test]
    fn ufw_deny_is_not_allowed() {
        let out = "9104/udp DENY Anywhere";
        assert!(!ufw_port_allowed(out, 9104));
    }

    #[test]
    fn firewalld_ports_parsed() {
        assert!(firewalld_port_open("9104/udp 443/tcp", 9104));
        assert!(!firewalld_port_open("9104/tcp", 9104));
        assert!(!firewalld_port_open("", 9104));
    }

    #[test]
    fn firewalld_ranges_parsed() {
        assert!(firewalld_port_open("9100-9105/udp", 9104));
        assert!(firewalld_port_open("8443/tcp 9100-9105/udp", 9100));
        assert!(firewalld_port_open("9100-9105/udp", 9105));
        assert!(!firewalld_port_open("9100-9105/udp", 9106));
        assert!(!firewalld_port_open("9100-9105/tcp", 9104));
        assert!(!firewalld_port_open("9100-/udp", 9104));
    }

    #[test]
    fn clock_sync_parsed() {
        assert!(clock_synchronized("System clock synchronized: yes\nNTP service: active"));
        assert!(!clock_synchronized("System clock synchronized: no"));
    }
}
