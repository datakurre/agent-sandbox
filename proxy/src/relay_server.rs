#[path = "relay_protocol.rs"]
mod relay_protocol;

use relay_protocol::{read_frame, write_frame, CommandType, Frame, RelayHeader};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;

fn domain_match(domain: &str, pattern: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix('*') {
        if suffix.starts_with('.') {
            domain == &pattern[2..] || domain.ends_with(suffix)
        } else {
            domain.ends_with(suffix)
        }
    } else {
        domain == pattern
    }
}

fn log_relay(cmd: &str, dest: Option<&str>, allowed: bool, reason: &str) {
    let line = match dest {
        Some(d) => format!(
            "{{\"cmd\":\"{}\",\"dest\":\"{}\",\"allowed\":{},\"reason\":\"{}\"}}\n",
            cmd, d, allowed, reason
        ),
        None => format!(
            "{{\"cmd\":\"{}\",\"allowed\":{},\"reason\":\"{}\"}}\n",
            cmd, allowed, reason
        ),
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/sidecar_shared/relay.jsonl")
    {
        let _ = file.write_all(line.as_bytes());
    }
}

fn extract_ssh_destination(args: &[String]) -> Option<String> {
    // Options whose next argument is a value (not a host).
    // Complete list from ssh(1) man page.
    const TAKES_ARG: &[&str] = &[
        "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
        "-p", "-Q", "-R", "-S", "-W", "-w",
    ];

    let mut skip_next = false;
    let mut saw_separator = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if saw_separator || !arg.starts_with('-') {
            // First non-option after flags is the destination.
            let dest = match arg.split_once('@') {
                Some((_, host)) => host,
                None => arg.as_str(),
            };
            return Some(dest.to_string());
        }
        if arg == "--" {
            saw_separator = true;
            continue;
        }
        // Pure flag with no argument (e.g., -4, -6, -v, -N, etc.)
        if arg.len() == 2 && !TAKES_ARG.contains(&arg.as_str()) {
            continue;
        }
        // Exact match for a flag that takes a separate argument
        if TAKES_ARG.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        // Combined form: -p2222 → first two chars are the option, rest is value.
        // Safely skip these as they consume the value inline.
        let prefix = &arg[..2];
        if TAKES_ARG.contains(&prefix) {
            continue;
        }
        // Bundled single-char flags without argument: -vvv, -46, etc.
        // Only valid if every character is a known no-arg flag.
        let no_arg_chars = "1246AaCfGgKkMNnqsTtVvXxYy";
        if arg[1..].chars().all(|c| no_arg_chars.contains(c)) {
            continue;
        }
        // Unrecognized option — fail closed rather than guess.
        return None;
    }
    None
}

fn validate_gpg_args(args: &[String]) -> bool {
    let mut has_signing_intent = false;
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.starts_with("--homedir")
            || lower.contains("export")
            || lower.contains("decrypt")
            || lower == "-d"
        {
            return false;
        }

        if lower == "--sign"
            || lower == "--detach-sign"
            || lower == "--clearsign"
            || lower == "--verify"
            || lower == "--clear-sign"
        {
            has_signing_intent = true;
        } else if lower.starts_with('-') && !lower.starts_with("--") {
            if lower.contains('s') || lower.contains('b') || lower.contains('v') {
                has_signing_intent = true;
            }
        }
    }
    has_signing_intent
}

/// The two authorization axes the relay enforces, read from the same policy
/// file: `ssh_hosts` gates which destinations `git push`/`pull` may reach,
/// while `gpg_enabled` gates GPG signing on its own -- host-agnostic, since
/// gpg has no destination of its own.
struct SigningPolicy {
    ssh_hosts: Vec<String>,
    gpg_enabled: bool,
}

fn load_signing_policy(policy_path: &str) -> SigningPolicy {
    let mut ssh_hosts = Vec::new();
    let mut gpg_enabled = false;
    if let Ok(file) = File::open(policy_path) {
        for line in BufReader::new(file).lines().flatten() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                match key {
                    "allow_signing" => {
                        if let Some(val) = parts.next() {
                            ssh_hosts.push(val.to_string());
                        }
                    }
                    "signing_enabled" => {
                        gpg_enabled = parts.next() == Some("true");
                    }
                    _ => {}
                }
            }
        }
    }
    SigningPolicy {
        ssh_hosts,
        gpg_enabled,
    }
}

fn handle_client(mut stream: TcpStream, policy_path: &str) {
    let req = match RelayHeader::read_from(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("relay-server: failed to read request header: {}", e);
            return;
        }
    };

    let signing_policy = load_signing_policy(policy_path);

    let (bin, is_ssh) = match req.cmd {
        CommandType::Gpg => {
            let allowed = signing_policy.gpg_enabled;
            let safe_args = validate_gpg_args(&req.args);

            log_relay(
                "gpg",
                None,
                allowed && safe_args,
                if !allowed {
                    "gpg signing not enabled"
                } else if !safe_args {
                    "disallowed gpg arguments"
                } else {
                    ""
                },
            );
            if !allowed || !safe_args {
                let msg = if !allowed {
                    b"agent-sandbox: gpg denied: signing not enabled -- relaunch with --gpg\n".as_slice()
                } else {
                    b"agent-sandbox: gpg denied: disallowed or dangerous arguments detected\n"
                        .as_slice()
                };
                let _ = write_frame(&mut stream, &Frame::Stderr(msg.to_vec()));
                let _ = write_frame(&mut stream, &Frame::Exit(255));
                return;
            }
            // Resolved through PATH: the image is a Nix closure, where the
            // only thing under /usr/bin is `env`.
            ("gpg", false)
        }
        CommandType::Ssh => {
            let host = extract_ssh_destination(&req.args);

            // Check for dangerous SSH arguments
            for arg in &req.args {
                let lower = arg.to_ascii_lowercase();
                if lower.contains("proxycommand")
                    || lower.contains("proxyusefdpass")
                    || lower.contains("localcommand")
                    || lower.contains("permitlocalcommand")
                {
                    eprintln!("relay-server: ssh command contains dangerous options");
                    let _ = write_frame(
                        &mut stream,
                        &Frame::Stderr(
                            b"agent-sandbox: ssh denied: dangerous options detected\n".to_vec(),
                        ),
                    );
                    let _ = write_frame(&mut stream, &Frame::Exit(255));
                    return;
                }
            }
            match host {
                Some(dest) => {
                    let mut allowed = false;
                    for rule in &signing_policy.ssh_hosts {
                        if domain_match(&dest, rule) {
                            allowed = true;
                            break;
                        }
                    }

                    log_relay(
                        "ssh",
                        Some(&dest),
                        allowed,
                        if allowed {
                            ""
                        } else {
                            "denied by allow_signing policy"
                        },
                    );

                    if !allowed {
                        eprintln!(
                            "relay-server: ssh to {} denied by allow_signing policy",
                            dest
                        );
                        let _ = write_frame(
                            &mut stream,
                            &Frame::Stderr(
                                format!(
                                    "agent-sandbox: ssh to {} denied by allow_signing policy\n",
                                    dest
                                )
                                .into_bytes(),
                            ),
                        );
                        let _ = write_frame(&mut stream, &Frame::Exit(255));
                        return;
                    }
                }
                None => {
                    log_relay("ssh", None, false, "could not determine destination");
                    let _ = write_frame(
                        &mut stream,
                        &Frame::Stderr(
                            b"agent-sandbox: ssh denied: could not determine destination host\n"
                                .to_vec(),
                        ),
                    );
                    let _ = write_frame(&mut stream, &Frame::Exit(255));
                    return;
                }
            }
            ("ssh", true)
        }
    };

    let mut cmd = Command::new(bin);
    cmd.args(&req.args);

    // Only pass through a strict whitelist of safe environment variables from the sandbox
    for (k, v) in req.envs {
        let k_str = k.as_str();
        if k_str == "LANG" || k_str.starts_with("LC_") || k_str == "TZ" || k_str == "TERM" {
            cmd.env(k, v);
        }
    }

    if is_ssh {
        cmd.env("SSH_AUTH_SOCK", "/run/host-ssh-agent");
    } else {
        // gpg uses the host agent mounted at /run/host-gpg-agent by the sidecar
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = write_frame(
                &mut stream,
                &Frame::Stderr(
                    format!("relay-server: failed to spawn {}: {}\n", bin, e).into_bytes(),
                ),
            );
            let _ = write_frame(&mut stream, &Frame::Exit(255));
            return;
        }
    };

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    let mut stream_read = stream.try_clone().unwrap();
    let mut stream_write_stdout = stream.try_clone().unwrap();
    let mut stream_write_stderr = stream.try_clone().unwrap();
    let mut stream_write_exit = stream;

    // Thread to read client frames (Stdin) and write to child stdin
    let t_stdin = thread::spawn(move || {
        loop {
            match read_frame(&mut stream_read) {
                Ok(Frame::Stdin(data)) => {
                    if data.is_empty() {
                        // EOF
                        break;
                    }
                    if child_stdin.write_all(&data).is_err() || child_stdin.flush().is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    // Ignore other frames from client
                }
                Err(_) => {
                    break;
                }
            }
        }
        // child_stdin is dropped here, closing it
    });

    let t_stdout = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_frame(&mut stream_write_stdout, &Frame::Stdout(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let t_stderr = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_frame(&mut stream_write_stderr, &Frame::Stderr(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let status = child.wait().unwrap();
    let _ = t_stdin.join();
    let _ = t_stdout.join();
    let _ = t_stderr.join();

    let code = status.code().unwrap_or(255);
    let _ = write_frame(&mut stream_write_exit, &Frame::Exit(code));
}

fn main() {
    let mut args = env::args().skip(1);
    let mut listen_addr = "0.0.0.0:8889".to_string();
    let mut policy_path = "/sidecar_policy/policy".to_string();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                if let Some(val) = args.next() {
                    listen_addr = val;
                }
            }
            "--policy" => {
                if let Some(val) = args.next() {
                    policy_path = val;
                }
            }
            _ => {}
        }
    }

    let listener = TcpListener::bind(&listen_addr).unwrap_or_else(|e| {
        eprintln!("relay-server: failed to bind {}: {}", listen_addr, e);
        std::process::exit(1);
    });

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let pp = policy_path.clone();
                thread::spawn(move || {
                    handle_client(s, &pp);
                });
            }
            Err(e) => {
                eprintln!("relay-server: accept failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_host() {
        let args = vec!["github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn user_at_host() {
        let args = vec!["git@github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn option_with_separate_value() {
        let args = vec!["-p".into(), "2222".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn combined_option_value() {
        let args = vec!["-p2222".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn combined_option_o() {
        let args = vec!["-oStrictHostKeyChecking=no".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn double_dash_separator() {
        let args = vec!["--".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn bundled_flags() {
        let args = vec!["-vvv".into(), "github.com".into()];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn no_args_returns_none() {
        let args: Vec<String> = vec![];
        assert_eq!(extract_ssh_destination(&args), None);
    }

    #[test]
    fn only_flags_returns_none() {
        let args = vec!["-v".into(), "-N".into()];
        assert_eq!(extract_ssh_destination(&args), None);
    }

    #[test]
    fn real_git_ssh_invocation() {
        // git push typically does: ssh [-p port] [user@]host git-upload-pack 'repo'
        let args = vec![
            "-o".into(),
            "SendEnv=GIT_PROTOCOL".into(),
            "git@github.com".into(),
            "git-upload-pack".into(),
            "user/repo.git".into(),
        ];
        assert_eq!(extract_ssh_destination(&args), Some("github.com".into()));
    }

    #[test]
    fn domain_match_exact() {
        assert!(domain_match("github.com", "github.com"));
        assert!(!domain_match("github.com", "gitlab.com"));
    }

    #[test]
    fn domain_match_wildcard() {
        assert!(domain_match("api.github.com", "*.github.com"));
        assert!(domain_match("github.com", "*.github.com"));
        assert!(!domain_match("github.org", "*.github.com"));
    }

    #[test]
    fn signing_policy_decouples_gpg_from_ssh_hosts() {
        // --gpg alone must enable gpg with no ssh destination named at all --
        // that is the whole point of the split.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy");
        std::fs::write(&path, "signing_enabled true\n").unwrap();

        let policy = load_signing_policy(path.to_str().unwrap());
        assert!(policy.gpg_enabled);
        assert!(policy.ssh_hosts.is_empty());
    }

    #[test]
    fn signing_policy_reads_ssh_hosts_independently_of_gpg() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy");
        std::fs::write(&path, "allow_signing github.com\n").unwrap();

        let policy = load_signing_policy(path.to_str().unwrap());
        assert!(!policy.gpg_enabled);
        assert_eq!(policy.ssh_hosts, vec!["github.com".to_string()]);
    }
}
