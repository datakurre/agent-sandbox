#![forbid(unsafe_code)]

use agent_sandbox_cli::host_bridge;
use agent_sandbox_proxy::known_hosts::FORGE_KNOWN_HOSTS;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Where the launcher mounts the `--host-loopback-port` socket directory.
const HOST_PORT_DIR: &str = "/run/agent-sandbox-host";

/// Set on the copy of this binary the entrypoint spawns to serve the host
/// loopback bridge, so it runs that instead of the entrypoint proper.
const BRIDGE_ROLE_ENV: &str = "AGENT_SANDBOX_HOST_BRIDGE_PORTS";

fn main() -> Result<()> {
    if let Ok(ports) = env::var(BRIDGE_ROLE_ENV) {
        run_host_bridge(&ports);
    }

    // 1. nix-store load db
    let skip_nix_init = env::var("AGENT_SANDBOX_SKIP_NIX_INIT").unwrap_or_else(|_| "0".to_string());
    // `--nix` now exposes the host store only as an HTTP substituter. It does
    // not replace this image's store or registration database, so the image's
    // registration must still be loaded on the first start.
    if skip_nix_init != "1" {
        let db_path = Path::new("/nix/var/nix/db/db.sqlite");
        let reg_path = Path::new("/nix/registration");
        if !db_path.exists() && reg_path.exists() {
            let file = fs::File::open(reg_path).context("Failed to open /nix/registration")?;
            let status = Command::new("nix-store")
                .arg("--load-db")
                .stdin(Stdio::from(file))
                .status();
            match status {
                Ok(status) if status.success() => {}
                Ok(status) => eprintln!(
                    "Warning: nix-store --load-db exited unsuccessfully: {}",
                    status
                ),
                Err(e) => eprintln!("Warning: failed to run nix-store --load-db: {}", e),
            }
        }
    }

    // NIX_CONFIG is inherited by every Nix command in this process tree and is
    // also recorded for `ctl attach` below. The host cache is intentionally an
    // HTTP binary cache, not a mounted local store or forwarded daemon socket.
    // It is applied only once the bridge carrying it is live (step 8).
    let mut pending_nix_config = None;
    if let (Ok(port), Ok(pubkey)) = (
        env::var("AGENT_SANDBOX_NIX_SERVE_PORT"),
        env::var("AGENT_SANDBOX_NIX_SERVE_PUBKEY"),
    ) {
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .context("invalid AGENT_SANDBOX_NIX_SERVE_PORT")?;
        let nix_config = nix_config_with_host_cache(
            &env::var("NIX_CONFIG").unwrap_or_default(),
            port,
            &pubkey,
        )?;
        pending_nix_config = Some((port, nix_config));
    }

    let home = env::var("HOME").context("HOME not set")?;
    let home_path = PathBuf::from(&home);

    // 2. GPG setup
    if env::var("AGENT_SANDBOX_GPG_AGENT").unwrap_or_default() == "1"
        && Path::new("/run/host-gpg-agent").exists()
    {
        let gnupg_dir = home_path.join(".gnupg");
        fs::create_dir_all(&gnupg_dir)?;
        let mut perms = fs::metadata(&gnupg_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&gnupg_dir, perms)?;

        let s_gpg_agent = gnupg_dir.join("S.gpg-agent");
        let _ = fs::remove_file(&s_gpg_agent);
        let _ = std::os::unix::fs::symlink("/run/host-gpg-agent", &s_gpg_agent);

        if io::stdin().is_terminal() {
            if let Ok(tty) = fs::read_link("/proc/self/fd/0") {
                env::set_var("GPG_TTY", tty);
            }
        }

        let host_gnupg = Path::new("/run/host-gnupg");
        if host_gnupg.is_dir() {
            if let Ok(entries) = fs::read_dir(host_gnupg) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let target = gnupg_dir.join(path.file_name().unwrap());
                        if !target.exists() {
                            let _ = fs::copy(&path, &target);
                        }
                    }
                }
            }
        }

        if env::var("AGENT_SANDBOX_GPG_RECV_KEY").unwrap_or_default() == "1" {
            let output = Command::new("git")
                .args(["config", "--get", "user.signingkey"])
                .output();
            if let Ok(out) = output {
                if out.status.success() {
                    let signing_key = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !signing_key.is_empty() {
                        let _ = Command::new("gpg")
                            .args([
                                "--keyserver",
                                "keyserver.ubuntu.com",
                                "--recv-keys",
                                &signing_key,
                            ])
                            .status();
                    }
                }
            }
        }
    }

    // 3. Known hosts
    // Unconditional: `ssh` can leave a sandbox by two different routes, and
    // the one that used to gate this -- a forwarded agent at /agent.sock --
    // is absent on both of the others.  Under --proxy the socket goes to the
    // sidecar instead, and under --proxy without --ssh the sandbox's own ssh
    // still goes out through the CONNECT proxy configured below.
    //
    // Under --proxy the launcher binds in the keys the operator authorized in
    // trusted.toml, and those are the whole trusted set -- the built-in forge
    // keys are not consulted, because a policy that named a host the operator
    // did not authorize would have been refused before the container started.
    // Without --proxy there is no policy to authorize against and no egress
    // restriction either, so the built-in keys stand in; they are public
    // vendor data, and the already-present check keeps a repeat run a no-op.
    //
    // This is the sandbox's copy.  Under --proxy --ssh the real ssh runs in
    // the sidecar and reads the same file from /sidecar_policy.
    {
        let ssh_dir = home_path.join(".ssh");
        fs::create_dir_all(&ssh_dir)?;
        let mut perms = fs::metadata(&ssh_dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&ssh_dir, perms)?;

        let known_hosts = ssh_dir.join("known_hosts");
        if known_hosts.exists() {
            let meta = fs::metadata(&known_hosts)?;
            if meta.permissions().readonly() {
                let mut p = meta.permissions();
                p.set_mode(0o644);
                if fs::set_permissions(&known_hosts, p).is_err() {
                    let _ = fs::remove_file(&known_hosts);
                }
            }
        }

        let seed = match env::var("AGENT_SANDBOX_KNOWN_HOSTS") {
            Ok(path) if !path.is_empty() => {
                fs::read_to_string(&path).unwrap_or_else(|_| String::new())
            }
            _ => FORGE_KNOWN_HOSTS.to_string(),
        };

        // Line-wise rather than "does it mention github.com": the authorized
        // set is whatever the operator wrote, and may name none of the forges.
        let existing = fs::read_to_string(&known_hosts).unwrap_or_default();
        let missing: Vec<&str> = seed
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| !existing.lines().any(|have| have.trim() == line.trim()))
            .collect();

        if !missing.is_empty() {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts)?;
            for line in missing {
                writeln!(file, "{}", line)?;
            }
        }
    }

    // 4. HTTP_PROXY
    if let Ok(http_proxy) = env::var("HTTP_PROXY") {
        if !http_proxy.is_empty() {
            let ssh_dir = home_path.join(".ssh");
            fs::create_dir_all(&ssh_dir)?;
            let mut perms = fs::metadata(&ssh_dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&ssh_dir, perms)?;

            let ssh_config = ssh_dir.join("config");
            if !ssh_config.exists() && fs::symlink_metadata(&ssh_config).is_err() {
                let (proxy_host, proxy_port) = split_proxy(&http_proxy);

                // ssh takes the first value it sees for a keyword, so the
                // loopback exemption has to precede the catch-all.  Without it
                // a local ssh is sent to the sidecar, which refuses 127.0.0.1.
                let config_content = format!(
                    "Host localhost 127.0.0.1 ::1\n  ProxyCommand none\n\
                     Host *\n  ProxyCommand socat - PROXY:{proxy_host}:%h:%p,proxyport={proxy_port}\n"
                );
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&ssh_config)?;
                file.write_all(config_content.as_bytes())?;

                let mut p = fs::metadata(&ssh_config)?.permissions();
                p.set_mode(0o600);
                fs::set_permissions(&ssh_config, p)?;
            }

            if env::var("NODE_USE_ENV_PROXY").is_err() {
                env::set_var("NODE_USE_ENV_PROXY", "1");
            }
        }
    }

    // 5. CA bundle
    let mut merged_ca_bundle: Option<PathBuf> = None;
    if let Ok(proxy_ca_file) = env::var("AGENT_SANDBOX_PROXY_CA_FILE") {
        if !proxy_ca_file.is_empty() {
            let proxy_ca_path = Path::new(&proxy_ca_file);
            if !proxy_ca_path.exists() {
                eprintln!(
                    "entrypoint: AGENT_SANDBOX_PROXY_CA_FILE is set but not readable: {}",
                    proxy_ca_file
                );
                std::process::exit(1);
            }

            let base_bundle = env::var("NIX_SSL_CERT_FILE")
                .or_else(|_| env::var("SSL_CERT_FILE"))
                .unwrap_or_else(|_| "/etc/ssl/certs/ca-bundle.crt".to_string());
            let base_bundle_path = Path::new(&base_bundle);
            if !base_bundle_path.exists() {
                eprintln!(
                    "entrypoint: base CA bundle is not readable: {}",
                    base_bundle
                );
                std::process::exit(1);
            }

            let merged_bundle = home_path.join(".cache/agent-sandbox-ca-bundle.pem");
            if let Some(parent) = merged_bundle.parent() {
                fs::create_dir_all(parent)?;
            }

            let base_content = fs::read_to_string(base_bundle_path)?;
            let proxy_content = fs::read_to_string(proxy_ca_path)?;

            let mut file = fs::File::create(&merged_bundle)?;
            file.write_all(base_content.as_bytes())?;
            // Without it a bundle that lacks a final newline runs its last END
            // line into the proxy CA's BEGIN, and parsers drop the proxy CA.
            if !base_content.is_empty() && !base_content.ends_with('\n') {
                file.write_all(b"\n")?;
            }
            file.write_all(proxy_content.as_bytes())?;

            let mut p = fs::metadata(&merged_bundle)?.permissions();
            p.set_mode(0o600);
            fs::set_permissions(&merged_bundle, p)?;

            let merged_bundle_str = merged_bundle.to_string_lossy().to_string();
            env::set_var("SSL_CERT_FILE", &merged_bundle_str);
            env::set_var("NIX_SSL_CERT_FILE", &merged_bundle_str);
            env::set_var("GIT_SSL_CAINFO", &merged_bundle_str);
            env::set_var("REQUESTS_CA_BUNDLE", &merged_bundle_str);
            env::set_var("CURL_CA_BUNDLE", &merged_bundle_str);
            env::set_var("NODE_EXTRA_CA_CERTS", &merged_bundle_str);
            merged_ca_bundle = Some(merged_bundle);
        }
    }

    // 5b. Maven
    //
    // Never fatal: a sandbox whose Maven is not proxied is still a sandbox,
    // and every way this can go wrong is reported instead.
    let http_proxy = env::var("HTTP_PROXY").ok().filter(|v| !v.is_empty());
    let (maven_vars, warnings) = setup_maven(
        &home_path,
        http_proxy.as_deref(),
        merged_ca_bundle.as_deref(),
        &|name| env::var(name).unwrap_or_default(),
    );
    for (name, value) in maven_vars {
        env::set_var(name, value);
    }
    for warning in warnings {
        eprintln!("entrypoint: --proxy and Maven: {warning}");
    }

    // 6. Git config
    //
    // Written whole on every start rather than appended to, because ~/.config
    // survives a container restart and a second generation of these sections
    // would stack up.  The image includes this file from /etc/gitconfig too, so
    // it reaches a `git` that was started without the GIT_CONFIG_* environment
    // below -- a `podman exec` shell, or a git spawned by a tool that scrubs its
    // child environment.
    let run_gitconfig = home_path.join(".config/agent-sandbox/gitconfig");
    if let Some(parent) = run_gitconfig.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut gitconfig_file = fs::File::create(&run_gitconfig)?;

    // git's own libcurl honours http_proxy, but only when it is in the
    // environment; recording it as config covers the invocations where it is
    // not, and costs nothing where it is.
    if let Ok(proxy) = env::var("http_proxy") {
        if !proxy.is_empty() {
            writeln!(gitconfig_file, "[http]\n\tproxy = {}", proxy)?;
        }
    }

    if env::var("AGENT_SANDBOX_RELAY_GPG").unwrap_or_default() == "1" {
        writeln!(gitconfig_file, "[gpg]\n\tprogram = relay-gpg")?;
    }

    if env::var("AGENT_SANDBOX_NO_GPG_SIGN").unwrap_or_default() == "1" {
        // Tags as well as commits: the host config that switched signing on
        // usually switches on both, and either one fails the same way without
        // a forwarded agent.
        writeln!(
            gitconfig_file,
            "[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false"
        )?;
    }

    let base_count: usize = env::var("AGENT_SANDBOX_GIT_CONFIG_COUNT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);

    for i in 0..base_count {
        if let Ok(key) = env::var(format!("AGENT_SANDBOX_GIT_CONFIG_KEY_{}", i)) {
            env::set_var(format!("GIT_CONFIG_KEY_{}", i), key);
        }
        if let Ok(val) = env::var(format!("AGENT_SANDBOX_GIT_CONFIG_VALUE_{}", i)) {
            env::set_var(format!("GIT_CONFIG_VALUE_{}", i), val);
        }
    }

    if run_gitconfig.exists() {
        env::set_var("GIT_CONFIG_COUNT", (base_count + 1).to_string());
        env::set_var(format!("GIT_CONFIG_KEY_{}", base_count), "include.path");
        env::set_var(
            format!("GIT_CONFIG_VALUE_{}", base_count),
            run_gitconfig.to_string_lossy().to_string(),
        );
    } else {
        env::set_var("GIT_CONFIG_COUNT", base_count.to_string());
    }

    // 7. SSH relay
    if env::var("AGENT_SANDBOX_RELAY_SSH").unwrap_or_default() == "1" {
        env::set_var("GIT_SSH_COMMAND", "relay-ssh");
        let local_bin = home_path.join(".local/bin");
        fs::create_dir_all(&local_bin)?;

        // Find relay-ssh in PATH or use command -v equivalent
        if let Ok(relay_ssh_path) = which("relay-ssh") {
            let _ = std::os::unix::fs::symlink(&relay_ssh_path, local_bin.join("ssh"));
        }

        let current_path = env::var("PATH").unwrap_or_default();
        env::set_var(
            "PATH",
            format!("{}:{}", local_bin.to_string_lossy(), current_path),
        );
    }

    // 8. Host loopback ports
    // The launcher mounted a directory and dials into it from the host; this
    // side owns the sockets and the TCP listeners clients inside connect to
    // (see host_bridge for why that direction).  127.0.0.1 both because
    // NO_PROXY already exempts it under --proxy and because Chrome's DevTools
    // host check accepts an IP but not an arbitrary name.
    //
    // Spawned, not threaded: this process execs below, which would take any
    // thread of ours with it.  The bridge outlives that as a child of PID 1 and
    // dies with the container.
    let ports = host_bridge_ports(
        &env::var("AGENT_SANDBOX_HOST_PORTS").unwrap_or_default(),
        pending_nix_config
            .as_ref()
            .map(|(port, _)| port.to_string())
            .as_deref(),
    );
    let mut ports_up = HashSet::new();
    if !ports.is_empty() {
        let spawned = env::current_exe().and_then(|exe| {
            Command::new(exe)
                .env(BRIDGE_ROLE_ENV, ports.join(","))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
        });
        match spawned {
            Ok(mut bridge) => {
                if let Some(stdout) = bridge.stdout.take() {
                    ports_up = read_bridge_reports(stdout, Duration::from_secs(3));
                }
            }
            Err(e) => eprintln!(
                "agent-sandbox: could not start the host loopback bridge: {}",
                e
            ),
        }
    }

    // An unreachable substituter is not skipped by Nix: every command retries
    // it for seconds and logs each attempt.  So the host cache goes into
    // NIX_CONFIG only once the launcher has parked a connection on its socket
    // -- and is not waited for at all when the bridge could not serve it.
    if let Some((port, nix_config)) = pending_nix_config {
        let marker = host_bridge::ready_marker(Path::new(HOST_PORT_DIR), port);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while ports_up.contains(&port)
            && !marker.exists()
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
        if ports_up.contains(&port) && marker.exists() {
            env::set_var("NIX_CONFIG", nix_config);
        } else {
            eprintln!(
                "agent-sandbox: --nix: the host cache bridge did not come up; continuing without the host Nix cache."
            );
            env::remove_var("AGENT_SANDBOX_NIX_SERVE_PORT");
        }
    }

    // 9. Ensure skill compatibility symlinks exist inside home directory.
    ensure_skills_symlinks(&home_path);

    // 10. Leave the runtime environment somewhere `ctl attach` can find it.
    //
    // `podman exec` inherits the *container's* environment -- what `podman run`
    // was given -- not the environment this process built on top of it.  So an
    // attached shell had none of what the steps above set: no merged CA bundle,
    // no `GIT_SSH_COMMAND=relay-ssh`, no `GIT_CONFIG_*`.  That is why
    // `git clone git@github.com:...` failed in an attached shell while the same
    // clone worked in the session the launcher started.
    write_attach_env(&home_path);

    // 11. exec "$@"
    if let Ok(ready_file) = env::var("AGENT_SANDBOX_READY_FILE") {
        if !ready_file.is_empty() {
            fs::write(&ready_file, "ready\n")
                .with_context(|| format!("failed to signal readiness at {}", ready_file))?;

            if let Ok(ack_file) = env::var("AGENT_SANDBOX_READY_ACK_FILE") {
                if !ack_file.is_empty() {
                    while !Path::new(&ack_file).exists() {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
    }

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let err = Command::new(&args[1]).args(&args[2..]).exec();
        eprintln!("Failed to exec {}: {}", args[1], err);
        std::process::exit(1);
    }

    Ok(())
}

/// The bridge role: serve each port in `ports` (comma-separated sandbox
/// ports) until the container goes away.
///
/// Each port's outcome goes to stdout as a `host_bridge::Report` line for the
/// entrypoint to read, terminated by `done`: the entrypoint prints failures
/// itself, before it execs the command, where they cannot land inside it.
fn run_host_bridge(ports: &str) -> ! {
    let mut out = io::stdout().lock();
    for port in ports.split(',').filter_map(|p| p.parse::<u16>().ok()) {
        let outcome = host_bridge::bind_and_serve(Path::new(HOST_PORT_DIR), port);
        let _ = writeln!(out, "{}", host_bridge::Report::for_port(port, &outcome).to_line());
    }
    let _ = writeln!(out, "{}", host_bridge::Report::Done.to_line());
    let _ = out.flush();
    drop(out);
    loop {
        thread::park();
    }
}

/// Read the bridge's per-port reports until `done`, EOF or `timeout`, print
/// each failure, and return the ports that came up.  On a thread with a
/// deadline, because a wedged bridge must not hold the command back for good.
fn read_bridge_reports(stdout: impl Read + Send + 'static, timeout: Duration) -> HashSet<u16> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Some(report) = host_bridge::Report::parse(&line) else {
                continue;
            };
            let done = report == host_bridge::Report::Done;
            if tx.send(report).is_err() || done {
                break;
            }
        }
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut up = HashSet::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left) {
            Ok(host_bridge::Report::Up(port)) => {
                up.insert(port);
            }
            Ok(host_bridge::Report::Down(port, why)) => {
                eprintln!("agent-sandbox: could not forward host port {}: {}", port, why);
            }
            Ok(host_bridge::Report::Done) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!("agent-sandbox: the host loopback bridge did not report in time.");
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    up
}

fn nix_config_with_host_cache(existing: &str, port: u16, public_key: &str) -> Result<String> {
    if port == 0 {
        anyhow::bail!("nix-serve port must be in 1-65535");
    }
    let public_key = public_key.trim();
    if public_key.is_empty() || public_key.chars().any(char::is_whitespace) {
        anyhow::bail!("nix-serve public key must be a single non-empty line");
    }

    let mut config = existing.to_string();
    if !config.is_empty() && !config.ends_with('\n') {
        config.push('\n');
    }
    config.push_str(&format!(
        "extra-substituters = http://127.0.0.1:{}\nextra-trusted-public-keys = {}\n",
        port, public_key
    ));
    Ok(config)
}

fn host_bridge_ports(host_ports: &str, nix_serve_port: Option<&str>) -> Vec<String> {
    let mut ports: Vec<String> = host_ports
        .split(',')
        .filter(|port| !port.is_empty())
        .map(str::to_string)
        .collect();
    // The private Nix cache bridge uses the same mounted socket directory but
    // is not a user-requested host-loopback capability, so keep it out of the
    // public AGENT_SANDBOX_HOST_PORTS list.
    if let Some(port) = nix_serve_port.filter(|port| !port.is_empty()) {
        if !ports.iter().any(|existing| existing == port) {
            ports.push(port.to_string());
        }
    }
    ports
}

/// Where the entrypoint records the environment it built, for `ctl attach`.
const ATTACH_ENV: &str = ".config/agent-sandbox/env";

/// Variables an attached shell needs that only exist because this process set
/// them.  Anything the launcher passed to `podman run` is already inherited by
/// `podman exec` and is deliberately not repeated here.
///
/// `GIT_CONFIG_*` is written as the count plus that many key/value pairs, since
/// git reads them positionally and a partial set is worse than none.
const ATTACH_ENV_VARS: &[&str] = &[
    "PATH",
    "SSL_CERT_FILE",
    "NIX_SSL_CERT_FILE",
    "GIT_SSL_CAINFO",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSH_COMMAND",
    "MAVEN_ARGS",
    "MAVEN_CONFIG",
    "MAVEN_OPTS",
    "AGENT_SANDBOX_PROXY_HOST",
];

fn write_attach_env(home_path: &Path) {
    let path = home_path.join(ATTACH_ENV);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut lines = String::new();
    for name in ATTACH_ENV_VARS {
        if let Ok(value) = env::var(name) {
            // A value with a newline in it cannot survive a line-per-variable
            // file, and `attach` would otherwise pass the tail as its own
            // variable.  None of these ever legitimately contains one.
            if !value.contains('\n') {
                lines.push_str(&format!("{}={}\n", name, value));
            }
        }
    }

    // NIX_CONFIG is a multiline value. Keep the attach file line-oriented by
    // storing it as a JSON string; ctl attach decodes this private record back
    // into the environment variable.
    if let Ok(value) = env::var("NIX_CONFIG") {
        lines.push_str("AGENT_SANDBOX_NIX_CONFIG_JSON=");
        lines.push_str(&serde_json::to_string(&value).unwrap_or_else(|_| "\"\"".to_string()));
        lines.push('\n');
    }

    if let Ok(count) = env::var("GIT_CONFIG_COUNT") {
        if let Ok(n) = count.parse::<usize>() {
            lines.push_str(&format!("GIT_CONFIG_COUNT={}\n", n));
            for i in 0..n {
                for name in [
                    format!("GIT_CONFIG_KEY_{}", i),
                    format!("GIT_CONFIG_VALUE_{}", i),
                ] {
                    if let Ok(value) = env::var(&name) {
                        if !value.contains('\n') {
                            lines.push_str(&format!("{}={}\n", name, value));
                        }
                    }
                }
            }
        }
    }

    // Written whole, not appended: a container that restarts must not end up
    // with two generations of the same variable in one file.
    if let Err(e) = fs::write(&path, lines) {
        eprintln!(
            "agent-sandbox: could not write {}: {} ('ctl attach' will get a barer environment)",
            path.display(),
            e
        );
    }
}

/// `http://10.89.7.2:8888` → (`10.89.7.2`, `8888`).  An IPv6 host keeps its
/// brackets.  A URL without a port means 80, as it does to curl: the ssh
/// config built from this once got an empty `proxyport=` instead.
fn split_proxy(http_proxy: &str) -> (&str, &str) {
    let host_port = http_proxy.split("://").last().unwrap_or(http_proxy);
    let host_port = host_port.trim_end_matches('/');
    let port_from = match host_port.find(']') {
        Some(end) if host_port.starts_with('[') => end + 1,
        _ => 0,
    };
    match host_port[port_from..].rfind(':') {
        Some(colon) => (&host_port[..port_from + colon], &host_port[port_from + colon + 1..]),
        None => (host_port, "80"),
    }
}

/// Maven's global settings under `--proxy`, relative to home.  Beside the
/// generated gitconfig, and out of `~/.m2`, which belongs to the operator.
const MAVEN_GLOBAL_SETTINGS: &str = ".config/agent-sandbox/maven-settings.xml";

fn maven_settings(proxy_host: &str, proxy_port: &str) -> String {
    // One entry per scheme: Maven picks a proxy by the repository URL's
    // protocol.  nonProxyHosts repeats the launcher's NO_PROXY literals in
    // Maven's `|` syntax; XML is the one place that `|` is safe to put.
    let proxy = |protocol: &str| {
        format!(
            "    <proxy>\n\
             \x20     <id>agent-sandbox-{protocol}</id>\n\
             \x20     <active>true</active>\n\
             \x20     <protocol>{protocol}</protocol>\n\
             \x20     <host>{proxy_host}</host>\n\
             \x20     <port>{proxy_port}</port>\n\
             \x20     <nonProxyHosts>localhost|127.0.0.1|::1|[::1]</nonProxyHosts>\n\
             \x20   </proxy>\n"
        )
    };
    format!(
        "<settings>\n  <proxies>\n{}{}  </proxies>\n</settings>\n",
        proxy("https"),
        proxy("http")
    )
}

/// The JVM's own truststore, beside the merged PEM bundle it is made from.
const MAVEN_TRUSTSTORE: &str = ".cache/agent-sandbox-ca-bundle.jks";

/// The fallback, for when the global settings cannot be handed over: Maven
/// reads the user settings too, so they carry the proxy instead -- but only in
/// a file this entrypoint created, which the marker identifies, and only on
/// the container's own filesystem.
const MAVEN_USER_SETTINGS: &str = ".m2/settings.xml";
/// XML forbids `--` inside a comment, so the flag is not named here: a marker
/// spelling it out made Maven refuse the whole file.
const MAVEN_USER_SETTINGS_MARKER: &str =
    "<!-- written by agent-sandbox for its proxy; replaced or removed on every start -->";

/// Exported under `--proxy`, so a settings file the operator keeps can name
/// the sidecar, whose address changes with every launch, as
/// `<host>${env.AGENT_SANDBOX_PROXY_HOST}</host>`.  There is no port
/// counterpart: Maven 3.9 parses `<port>` as a number before it interpolates.
const PROXY_HOST_ENV: &str = "AGENT_SANDBOX_PROXY_HOST";

/// Points Maven at the proxy -- see "Maven" in docs/architecture.md.  Returns
/// the variables to set and what went wrong, and never fails: a sandbox whose
/// Maven is not proxied is still a sandbox.  `existing` is the operator's
/// value of a variable.  Without a proxy it only removes what this
/// entrypoint wrote before.
fn setup_maven(
    home_path: &Path,
    http_proxy: Option<&str>,
    ca_bundle: Option<&Path>,
    existing: &dyn Fn(&str) -> String,
) -> (Vec<(&'static str, String)>, Vec<String>) {
    let mut warnings = Vec::new();
    let global = home_path.join(MAVEN_GLOBAL_SETTINGS);
    let truststore = home_path.join(MAVEN_TRUSTSTORE);
    let user = home_path.join(MAVEN_USER_SETTINGS);
    let _ = fs::remove_file(&truststore);

    let Some(http_proxy) = http_proxy else {
        let _ = fs::remove_file(&global);
        remove_our_user_settings(&user, home_path);
        return (Vec::new(), warnings);
    };
    let (proxy_host, proxy_port) = split_proxy(http_proxy);
    let proxy_host = proxy_host.trim_start_matches('[').trim_end_matches(']');
    // The same check keeps the address safe in the XML: no `<`, `&` or `"`.
    if !shell_word(proxy_host) || !shell_word(proxy_port) {
        warnings.push(format!(
            "proxy address {proxy_host}:{proxy_port} is not a plain host and port; Maven is not configured"
        ));
        return (Vec::new(), warnings);
    }
    let settings_xml = maven_settings(proxy_host, proxy_port);

    // Written whole on every start, like the gitconfig beside it.
    let global_written = global
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(&global, &settings_xml));
    if let Err(e) = &global_written {
        warnings.push(format!("could not write {}: {e}", global.display()));
    }

    // The JVM ignores SSL_CERT_FILE and friends, so a host the proxy
    // intercepts needs the session CA in a keystore of Java's own.
    let truststore_path = ca_bundle.and_then(|bundle| {
        let written = fs::read(bundle)
            .map_err(anyhow::Error::from)
            .and_then(|pem| jks_truststore(&pem))
            .and_then(|(store, skipped)| {
                fs::write(&truststore, store)?;
                fs::set_permissions(&truststore, fs::Permissions::from_mode(0o600))?;
                Ok(skipped)
            });
        match written {
            Ok(skipped) => {
                if skipped > 0 {
                    warnings.push(format!(
                        "left {skipped} unparsable certificate(s) of {} out of Java's truststore",
                        bundle.display()
                    ));
                }
                Some(truststore.to_string_lossy().to_string())
            }
            Err(e) => {
                warnings.push(format!(
                    "no Java truststore, so hosts the proxy intercepts will fail in Maven: {e:#}"
                ));
                None
            }
        }
    });

    let settings_path = global.to_string_lossy().to_string();
    let plan = maven_env(
        proxy_host,
        proxy_port,
        global_written.is_ok().then_some(settings_path.as_str()),
        truststore_path.as_deref(),
        existing,
    );
    warnings.extend(plan.warnings);
    let mut vars = plan.vars;
    vars.push((PROXY_HOST_ENV, proxy_host.to_string()));

    if plan.unproxied.is_empty() {
        remove_our_user_settings(&user, home_path);
        return (vars, warnings);
    }

    // Some launcher will not read our global settings.  Settings the operator
    // named, or their own user settings, may carry the proxy already.
    let why = plan.unproxied.join("; ");
    let theirs: Vec<String> = ["MAVEN_ARGS", "MAVEN_CONFIG"].iter().map(|n| existing(n)).collect();
    // Maven resolves a relative settings path against the working directory,
    // which is the workspace podman starts us in.
    let cwd = env::current_dir().unwrap_or_default();
    let mut candidates: Vec<PathBuf> = theirs.iter().flat_map(|v| named_settings(v, &cwd)).collect();
    candidates.push(user.clone());
    let wired = candidates.iter().any(|path| {
        fs::read_to_string(path).is_ok_and(|content| content.contains(PROXY_HOST_ENV))
    });
    let advice = format!(
        "give it a <proxy> with <host>${{env.{PROXY_HOST_ENV}}}</host> and <port>{proxy_port}</port>"
    );
    if wired {
        remove_our_user_settings(&user, home_path);
    } else if let Some(flag) = theirs.iter().find_map(|v| names_user_settings(v)) {
        remove_our_user_settings(&user, home_path);
        warnings.push(format!(
            "{why}, and {flag} names other user settings, so a fallback in {} would not be read; \
             {advice}",
            user.display()
        ));
    } else {
        match write_our_user_settings(&user, home_path, &settings_xml) {
            Ok(true) => {}
            Ok(false) => warnings.push(format!(
                "{why}, and {} is the operator's own or mounted from the host, so it is left \
                 alone and Maven may connect directly and fail; {advice}",
                user.display()
            )),
            Err(e) => warnings.push(format!(
                "{why}, and the fallback {} could not be written: {e}",
                user.display()
            )),
        }
    }
    (vars, warnings)
}

/// Whether `path` is the fallback user settings this entrypoint wrote, on the
/// container's own filesystem.  A file behind a bind mount is the host's even
/// if it carries the marker -- another sandbox sharing that `~/.m2` may have
/// written it -- so it is never rewritten or removed from here.
fn is_our_user_settings(path: &Path, home_path: &Path) -> bool {
    on_home_device(path, home_path)
        && fs::read_to_string(path).is_ok_and(|content| content.starts_with(MAVEN_USER_SETTINGS_MARKER))
}

/// Whether the nearest existing ancestor of `path` is on the same filesystem
/// as home.  `~/.m2` bound in from the host is not, so nothing written there
/// outlives the session or leaks a per-session address into host builds.
fn on_home_device(path: &Path, home_path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(home) = fs::metadata(home_path) else {
        return false;
    };
    path.ancestors()
        .skip(1)
        .find_map(|dir| fs::metadata(dir).ok())
        .is_some_and(|dir| dir.dev() == home.dev())
        && fs::symlink_metadata(path).map_or(true, |file| file.dev() == home.dev())
}

fn remove_our_user_settings(path: &Path, home_path: &Path) {
    if is_our_user_settings(path, home_path) {
        let _ = fs::remove_file(path);
    }
}

/// Writes the fallback when there is no settings file, or only ours.  Returns
/// false, touching nothing, when the file is the operator's or `~/.m2` is a
/// mount from the host.
fn write_our_user_settings(path: &Path, home_path: &Path, settings_xml: &str) -> io::Result<bool> {
    let exists = fs::symlink_metadata(path).is_ok();
    if (exists && !is_our_user_settings(path, home_path)) || !on_home_device(path, home_path) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{MAVEN_USER_SETTINGS_MARKER}\n{settings_xml}"))?;
    Ok(true)
}

/// The settings files `existing` names with `-gs`, `-is` or `-s` and their
/// long forms, in either `-gs FILE` or `--global-settings=FILE` spelling.  A
/// relative path is resolved against `cwd`, as Maven resolves it; a leading
/// `~` is not expanded, because Maven does not expand it either.
fn named_settings(existing: &str, cwd: &Path) -> Vec<PathBuf> {
    const FLAGS: [&str; 6] = ["-gs", "-is", "-s", "--global-settings", "--install-settings", "--settings"];
    let words: Vec<&str> = existing.split_whitespace().collect();
    let mut paths = Vec::new();
    for (index, word) in words.iter().enumerate() {
        for flag in FLAGS {
            if *word == flag {
                if let Some(next) = words.get(index + 1) {
                    paths.push(cwd.join(next));
                }
            } else if let Some(value) = word.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
                paths.push(cwd.join(value));
            }
        }
    }
    paths
}

/// The flag, if `existing` replaces Maven's user settings -- in which case
/// `~/.m2/settings.xml` is never read and a fallback there would do nothing.
fn names_user_settings(existing: &str) -> Option<&'static str> {
    existing.split_whitespace().find_map(|word| {
        ["-s", "--settings"]
            .into_iter()
            .find(|flag| word == *flag || word.starts_with(&format!("{flag}=")))
    })
}

#[derive(Debug, Default, PartialEq)]
struct MavenEnv {
    /// Final values, each with the operator's own value after ours.
    vars: Vec<(&'static str, String)>,
    /// Why some launcher will not get the global settings; non-empty means
    /// the user-settings fallback is needed.
    unproxied: Vec<String>,
    warnings: Vec<String>,
}

/// What to hand Maven, given the operator's current value of each variable.
///
/// The settings go out twice because there are two launchers: `bin/mvn` (and
/// the script-only mvnw, which execs it) reads MAVEN_ARGS, while a jar-based
/// mvnw starts Maven in its own JVM and reads MAVEN_CONFIG.  Neither reads the
/// other's, so `-gs` is never passed twice.  Maven 4 calls `-gs` deprecated
/// but honours it, and Maven 3.9 knows no other spelling.
///
/// `proxy_host` and `proxy_port` are already checked with `shell_word` by
/// `setup_maven`, and the host has lost any IPv6 brackets, which the JVM's
/// properties do not take.
fn maven_env(
    proxy_host: &str,
    proxy_port: &str,
    settings: Option<&str>,
    truststore: Option<&str>,
    existing: &dyn Fn(&str) -> String,
) -> MavenEnv {
    let mut plan = MavenEnv::default();

    // The JVM properties are for what settings do not reach: plugins that
    // download through java.net themselves, and the wrapper jar fetching Maven.
    let mut opts = vec![format!(
        "-Dhttp.proxyHost={proxy_host} -Dhttp.proxyPort={proxy_port} \
         -Dhttps.proxyHost={proxy_host} -Dhttps.proxyPort={proxy_port}"
    )];
    match truststore {
        Some(path) if shell_word(path) => opts.push(format!(
            "-Djavax.net.ssl.trustStore={path} -Djavax.net.ssl.trustStoreType=JKS"
        )),
        Some(path) => plan
            .warnings
            .push(format!("truststore path {path} is not shell-safe; MAVEN_OPTS does not name it")),
        None => {}
    }
    plan.vars
        .push(("MAVEN_OPTS", prepend_flags(&opts.join(" "), &existing("MAVEN_OPTS"))));

    for name in ["MAVEN_ARGS", "MAVEN_CONFIG"] {
        let theirs = existing(name);
        match settings {
            _ if names_global_settings(&theirs) => plan
                .unproxied
                .push(format!("{name} already names global settings")),
            Some(path) if shell_word(path) => {
                plan.vars.push((name, prepend_flags(&format!("-gs {path}"), &theirs)))
            }
            Some(path) => plan
                .unproxied
                .push(format!("settings path {path} is not shell-safe for {name}")),
            None => plan.unproxied.push(format!("no global settings for {name}")),
        }
    }
    plan
}

/// Ours first, so an operator's own value -- later on the java command line,
/// where the last `-D` wins -- still overrides a property it repeats.
fn prepend_flags(ours: &str, existing: &str) -> String {
    match existing.trim() {
        "" => ours.to_string(),
        existing => format!("{ours} {existing}"),
    }
}

/// Whether the operator already chose Maven's global (Maven 4: installation)
/// settings in this variable.  Theirs wins then: of two `-gs`, Maven keeps
/// the first, which would be ours.
fn names_global_settings(existing: &str) -> bool {
    existing.split_whitespace().any(|word| {
        ["-gs", "-is", "--global-settings", "--install-settings"]
            .iter()
            .any(|flag| word == *flag || word.starts_with(&format!("{flag}=")))
    })
}

/// True when `word` stays one word, unchanged, through word splitting and a
/// shell's `eval` -- Maven 4's `mvn` evals MAVEN_OPTS, where a `|` once made
/// every invocation fail.  Checked per component, not on the joined value, so
/// a space inside a path cannot pass as a separator.
fn shell_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.,/:=@+".contains(c))
}

/// A JKS keystore of trusted-certificate entries, one per certificate in
/// `pem`, and how many it left out because they would not parse.  JKS rather
/// than PKCS#12 because it is a few lines of framing and every JDK reads it.
/// Each certificate is parsed before it goes in: one Java cannot read fails
/// the whole keystore, and with it every TLS connection Maven makes.  The
/// integrity digest is keyed with the JDK's stock `changeit`; Java skips the
/// check anyway when no password is given.
fn jks_truststore(pem: &[u8]) -> Result<(Vec<u8>, usize)> {
    use rustls_pki_types::{pem::PemObject, CertificateDer};

    let mut certs = Vec::new();
    let mut skipped = 0;
    // A block that does not even decode -- bad base64, no END line -- is
    // skipped like one that does not parse; the iterator resumes after it.
    for cert in CertificateDer::pem_slice_iter(pem) {
        match cert {
            Ok(cert) if webpki::anchor_from_trusted_cert(&cert).is_ok() => certs.push(cert),
            _ => skipped += 1,
        }
    }
    anyhow::ensure!(!certs.is_empty(), "the CA bundle holds no usable CERTIFICATE block");

    let utf = |out: &mut Vec<u8>, text: &str| {
        out.extend_from_slice(&(text.len() as u16).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    };
    let mut store = Vec::new();
    store.extend_from_slice(&0xFEED_FEEDu32.to_be_bytes());
    store.extend_from_slice(&2u32.to_be_bytes());
    store.extend_from_slice(&(certs.len() as u32).to_be_bytes());
    for (index, cert) in certs.iter().enumerate() {
        store.extend_from_slice(&2u32.to_be_bytes()); // trusted certificate
        utf(&mut store, &format!("ca-{index}"));
        store.extend_from_slice(&0u64.to_be_bytes()); // creation date
        utf(&mut store, "X.509");
        store.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        store.extend_from_slice(cert);
    }

    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    for unit in "changeit".encode_utf16() {
        digest.update(&unit.to_be_bytes());
    }
    digest.update(b"Mighty Aphrodite");
    digest.update(&store);
    store.extend_from_slice(digest.finish().as_ref());
    Ok((store, skipped))
}

fn which(cmd: &str) -> Result<PathBuf, ()> {
    if let Ok(paths) = env::var("PATH") {
        for path in paths.split(':') {
            let p = Path::new(path).join(cmd);
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err(())
}

fn ensure_skills_symlinks_impl(home_path: &Path, canonical_skills: &Path) {
    if !canonical_skills.exists() {
        return;
    }

    let links = [
        home_path.join(".claude/skills"),
        home_path.join(".codex/skills"),
        home_path.join(".copilot/skills"),
        home_path.join(".cursor/skills"),
        home_path.join(".gemini/skills"),
        home_path.join(".gemini/config/skills"),
    ];

    for link in &links {
        if !link.exists() {
            if fs::symlink_metadata(link).is_ok() {
                let _ = fs::remove_file(link);
            }
            if let Some(parent) = link.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = std::os::unix::fs::symlink(canonical_skills, link);
        }
    }
}

fn ensure_skills_symlinks(home_path: &Path) {
    ensure_skills_symlinks_impl(home_path, Path::new("/home/user/.agents/skills"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_reports_yield_the_ports_that_came_up() {
        let reports = "ok 9222\nerr 7419 Address already in use (os error 98)\nnoise\ndone\nok 1\n";
        let up = read_bridge_reports(io::Cursor::new(reports), Duration::from_secs(5));
        assert_eq!(up, HashSet::from([9222]), "a port after `done` is not read");

        // A bridge that died mid-report: what it said still counts.
        let up = read_bridge_reports(io::Cursor::new("ok 5\n"), Duration::from_secs(5));
        assert_eq!(up, HashSet::from([5]));
    }

    #[test]
    fn a_silent_bridge_does_not_hold_the_command_back() {
        let (reader, _writer_kept_open) = std::os::unix::net::UnixStream::pair().unwrap();
        let started = std::time::Instant::now();
        let up = read_bridge_reports(reader, Duration::from_millis(200));
        assert!(up.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn test_ensure_skills_symlinks_creates_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let fake_canonical = tmp.path().join("canonical_skills");
        fs::create_dir_all(&fake_canonical).unwrap();

        ensure_skills_symlinks_impl(home, &fake_canonical);

        let link = home.join(".gemini/config/skills");
        assert!(fs::symlink_metadata(&link).is_ok());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            fake_canonical
        );
    }

    #[test]
    fn test_ensure_skills_symlinks_noop_when_canonical_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let missing_canonical = tmp.path().join("nonexistent_skills");

        ensure_skills_symlinks_impl(home, &missing_canonical);

        let link = home.join(".gemini/config/skills");
        assert!(fs::symlink_metadata(&link).is_err());
    }

    #[test]
    fn nix_config_keeps_existing_settings_and_adds_the_host_cache() {
        let config = nix_config_with_host_cache(
            "experimental-features = nix-command flakes",
            7419,
            "agent-sandbox-nix-serve-1:abc123=\n",
        )
        .unwrap();
        assert_eq!(
            config,
            "experimental-features = nix-command flakes\n\
             extra-substituters = http://127.0.0.1:7419\n\
             extra-trusted-public-keys = agent-sandbox-nix-serve-1:abc123=\n"
        );
    }

    #[test]
    fn nix_config_rejects_invalid_ports_and_multiline_keys() {
        assert!(nix_config_with_host_cache("", 0, "key:value").is_err());
        assert!(nix_config_with_host_cache("", 7419, "").is_err());
        assert!(nix_config_with_host_cache("", 7419, "first\nsecond").is_err());
    }

    const SETTINGS: &str = "/home/user/.config/agent-sandbox/maven-settings.xml";
    const TRUSTSTORE: &str = "/home/user/.cache/agent-sandbox-ca-bundle.jks";

    fn operator<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> String + 'a {
        move |name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        }
    }

    fn var<'a>(plan: &'a MavenEnv, name: &str) -> Option<&'a str> {
        plan.vars.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn both_launchers_get_the_settings_and_the_jvm_gets_the_proxy() {
        let plan = maven_env("10.89.7.2", "8888", Some(SETTINGS), None, &operator(&[]));
        let gs = format!("-gs {SETTINGS}");
        assert_eq!(var(&plan, "MAVEN_ARGS"), Some(gs.as_str()));
        assert_eq!(var(&plan, "MAVEN_CONFIG"), Some(gs.as_str()));
        assert_eq!(
            var(&plan, "MAVEN_OPTS"),
            Some(
                "-Dhttp.proxyHost=10.89.7.2 -Dhttp.proxyPort=8888 \
                 -Dhttps.proxyHost=10.89.7.2 -Dhttps.proxyPort=8888"
            )
        );
        assert!(plan.unproxied.is_empty() && plan.warnings.is_empty(), "{plan:?}");
    }

    #[test]
    fn the_truststore_is_named_only_when_there_is_one() {
        let plan = maven_env("10.89.7.2", "8888", Some(SETTINGS), Some(TRUSTSTORE), &operator(&[]));
        let opts = var(&plan, "MAVEN_OPTS").unwrap();
        assert!(opts.contains(&format!("-Djavax.net.ssl.trustStore={TRUSTSTORE}")));
        assert!(opts.contains("-Djavax.net.ssl.trustStoreType=JKS"));
    }

    #[test]
    fn the_operators_values_follow_ours() {
        let theirs = [("MAVEN_OPTS", " -Xmx1g "), ("MAVEN_ARGS", "-T 4")];
        let plan = maven_env("10.89.7.2", "8888", Some(SETTINGS), None, &operator(&theirs));
        assert!(var(&plan, "MAVEN_OPTS").unwrap().ends_with("-Dhttps.proxyPort=8888 -Xmx1g"));
        assert_eq!(var(&plan, "MAVEN_ARGS").unwrap(), format!("-gs {SETTINGS} -T 4"));
    }

    #[test]
    fn an_operators_global_settings_suppress_ours_in_that_variable_only() {
        let theirs = [("MAVEN_ARGS", "-is /etc/maven.xml")];
        let plan = maven_env("10.89.7.2", "8888", Some(SETTINGS), None, &operator(&theirs));
        assert_eq!(var(&plan, "MAVEN_ARGS"), None, "left exactly as the operator set it");
        assert_eq!(var(&plan, "MAVEN_CONFIG"), Some(format!("-gs {SETTINGS}").as_str()));
        assert_eq!(plan.unproxied, ["MAVEN_ARGS already names global settings"]);
    }

    #[test]
    fn an_operators_global_settings_are_recognised_in_every_spelling() {
        for existing in [
            "-gs /etc/m.xml",
            "-T 4 --global-settings /etc/m.xml",
            "--global-settings=/etc/m.xml",
            "-is /etc/m.xml",
            "--install-settings=/etc/m.xml",
        ] {
            assert!(names_global_settings(existing), "{existing}");
        }
        for existing in ["", "-T 4", "-s /etc/user.xml", "-gsx", "/root/.m2"] {
            assert!(!names_global_settings(existing), "{existing}");
        }
    }

    #[test]
    fn nothing_that_would_change_under_eval_is_handed_to_maven() {
        // A space in a path is the case a check on the joined value missed.
        let plan = maven_env(
            "10.89.7.2",
            "8888",
            Some("/home/a user/settings.xml"),
            Some("/home/a user/ca.jks"),
            &operator(&[]),
        );
        assert_eq!(var(&plan, "MAVEN_ARGS"), None);
        assert_eq!(var(&plan, "MAVEN_CONFIG"), None);
        assert_eq!(plan.unproxied.len(), 2, "so the fallback takes over: {plan:?}");
        let opts = var(&plan, "MAVEN_OPTS").unwrap();
        assert!(!opts.contains("trustStore"), "{opts}");
        assert_eq!(plan.warnings.len(), 1, "{plan:?}");

        for word in ["a|b", "a;b", "$HOME", "'q'", "a*", "a b", "`x`", "a&b", "[::1]", ""] {
            assert!(!shell_word(word), "{word:?}");
        }
        for word in [SETTINGS, TRUSTSTORE, "10.89.7.2", "fd00::1", "8888"] {
            assert!(shell_word(word), "{word:?}");
        }
    }

    #[test]
    fn an_ipv6_sidecar_is_named_without_brackets_for_the_jvm() {
        let tmp = tempfile::tempdir().unwrap();
        let (vars, warnings) = setup_maven(tmp.path(), Some("http://[fd00::2]:8888"), None, &operator(&[]));
        assert!(warnings.is_empty(), "{warnings:?}");
        let opts = &vars.iter().find(|(n, _)| *n == "MAVEN_OPTS").unwrap().1;
        assert!(opts.contains("-Dhttps.proxyHost=fd00::2 "), "{opts}");
        assert!(vars.contains(&(PROXY_HOST_ENV, "fd00::2".to_string())));
        let settings = fs::read_to_string(tmp.path().join(MAVEN_GLOBAL_SETTINGS)).unwrap();
        assert!(settings.contains("<host>fd00::2</host>"), "{settings}");
    }

    #[test]
    fn without_global_settings_every_launcher_needs_the_fallback() {
        let plan = maven_env("10.89.7.2", "8888", None, None, &operator(&[]));
        assert_eq!(plan.unproxied.len(), 2);
        assert!(var(&plan, "MAVEN_OPTS").is_some(), "the JVM properties still go out");
    }

    #[test]
    fn maven_settings_point_both_schemes_at_the_proxy() {
        let settings = maven_settings("10.89.7.2", "8888");
        assert!(settings.contains("<protocol>https</protocol>"));
        assert!(settings.contains("<protocol>http</protocol>"));
        assert_eq!(settings.matches("<host>10.89.7.2</host>").count(), 2);
        assert_eq!(settings.matches("<port>8888</port>").count(), 2);
        assert!(settings.contains("<nonProxyHosts>localhost|127.0.0.1|"));
    }

    #[test]
    fn the_marker_is_a_well_formed_xml_comment() {
        let body = MAVEN_USER_SETTINGS_MARKER
            .strip_prefix("<!--")
            .and_then(|rest| rest.strip_suffix("-->"))
            .expect("a comment");
        assert!(!body.contains("--") && !body.ends_with('-'), "{body}");
    }

    const PROXY: &str = "http://10.89.7.2:8888";

    fn setup(home: &Path, theirs: &[(&str, &str)]) -> (Vec<(&'static str, String)>, Vec<String>) {
        setup_maven(home, Some(PROXY), None, &operator(theirs))
    }

    #[test]
    fn the_normal_path_writes_global_settings_only_and_is_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let (vars, warnings) = setup(tmp.path(), &[]);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(tmp.path().join(MAVEN_GLOBAL_SETTINGS).exists());
        assert!(!tmp.path().join(MAVEN_USER_SETTINGS).exists());
        let names: Vec<_> = vars.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["MAVEN_OPTS", "MAVEN_ARGS", "MAVEN_CONFIG", PROXY_HOST_ENV]);
        assert!(vars.contains(&(PROXY_HOST_ENV, "10.89.7.2".to_string())));
    }

    #[test]
    fn the_fallback_comes_and_goes_with_the_need_for_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let user = home.join(MAVEN_USER_SETTINGS);
        let theirs = [("MAVEN_ARGS", "-gs /etc/theirs.xml")];

        let (vars, warnings) = setup(home, &theirs);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(!vars.iter().any(|(n, _)| *n == "MAVEN_ARGS"), "theirs is left as it is");
        let content = fs::read_to_string(&user).unwrap();
        assert!(content.starts_with(MAVEN_USER_SETTINGS_MARKER), "{content}");
        assert!(content.contains("<host>10.89.7.2</host>"), "{content}");

        // Not needed any more: ours goes.
        setup(home, &[]);
        assert!(!user.exists());
        // Needed again, then no proxy at all: ours goes, and so do the global settings.
        setup(home, &theirs);
        assert!(user.exists());
        let (vars, warnings) = setup_maven(home, None, None, &operator(&[]));
        assert!(vars.is_empty() && warnings.is_empty());
        assert!(!user.exists() && !home.join(MAVEN_GLOBAL_SETTINGS).exists());
    }

    #[test]
    fn an_operators_user_settings_are_never_touched_and_the_advice_is_portable() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let user = home.join(MAVEN_USER_SETTINGS);
        fs::create_dir_all(user.parent().unwrap()).unwrap();
        fs::write(&user, "<settings/>\n").unwrap();
        let theirs = [("MAVEN_ARGS", "-gs /etc/theirs.xml")];

        let (_, warnings) = setup(home, &theirs);
        assert_eq!(fs::read_to_string(&user).unwrap(), "<settings/>\n");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("${env.AGENT_SANDBOX_PROXY_HOST}"), "{warnings:?}");
        assert!(!warnings[0].contains("10.89.7.2"), "that address changes every launch: {warnings:?}");

        // Once the operator follows the advice, the warning stops.
        fs::write(&user, "<proxy><host>${env.AGENT_SANDBOX_PROXY_HOST}</host></proxy>\n").unwrap();
        let (_, warnings) = setup(home, &theirs);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn global_settings_the_operator_wired_to_the_proxy_need_no_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let theirs_file = tmp.path().join("theirs.xml");
        fs::write(&theirs_file, "<host>${env.AGENT_SANDBOX_PROXY_HOST}</host>").unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let args = format!("--global-settings={}", theirs_file.display());

        let (_, warnings) = setup(&home, &[("MAVEN_ARGS", &args)]);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(!home.join(MAVEN_USER_SETTINGS).exists());
    }

    #[test]
    fn an_operators_dash_s_means_the_fallback_would_not_be_read() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, warnings) = setup(tmp.path(), &[("MAVEN_ARGS", "-gs /etc/g.xml -s /etc/u.xml")]);
        assert!(!tmp.path().join(MAVEN_USER_SETTINGS).exists());
        assert!(warnings.iter().any(|w| w.contains("-s names other user settings")), "{warnings:?}");
    }

    #[test]
    fn a_settings_directory_on_another_filesystem_is_the_hosts() {
        // A tmpfs stands in for a bind mount from the host: another device
        // than a tempdir under /tmp, unless /tmp is a tmpfs too.
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let Ok(elsewhere) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        if fs::metadata(tmp.path()).unwrap().dev() == fs::metadata(elsewhere.path()).unwrap().dev() {
            return;
        }
        std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join(".m2")).unwrap();
        let path = tmp.path().join(MAVEN_USER_SETTINGS);

        let xml = maven_settings("10.89.7.2", "8888");
        assert!(!write_our_user_settings(&path, tmp.path(), &xml).unwrap());
        assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none(), "nothing written there");

        // Even a file carrying our marker is not removed from there.
        let marked = elsewhere.path().join("settings.xml");
        fs::write(&marked, format!("{MAVEN_USER_SETTINGS_MARKER}\n")).unwrap();
        remove_our_user_settings(&path, tmp.path());
        assert!(marked.exists());
    }

    #[test]
    fn named_settings_are_found_in_every_spelling() {
        assert_eq!(
            named_settings("-T 4 -gs /a.xml --settings=/b.xml -is /c.xml", Path::new("/w")),
            [PathBuf::from("/a.xml"), PathBuf::from("/b.xml"), PathBuf::from("/c.xml")]
        );
        // Relative to the working directory, as Maven reads them; no `~`.
        assert_eq!(
            named_settings("-gs conf/g.xml --settings=~/u.xml", Path::new("/w")),
            [PathBuf::from("/w/conf/g.xml"), PathBuf::from("/w/~/u.xml")]
        );
        assert_eq!(names_user_settings("-gs /a.xml"), None);
        assert_eq!(names_user_settings("-s /u.xml"), Some("-s"));
        assert_eq!(names_user_settings("--settings=/u.xml"), Some("--settings"));
    }

    #[test]
    fn an_address_that_is_not_plain_configures_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (vars, warnings) = setup_maven(tmp.path(), Some("http://a&b<c:8888"), None, &operator(&[]));
        assert!(vars.is_empty());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(!tmp.path().join(MAVEN_GLOBAL_SETTINGS).exists(), "no unescaped XML");
    }

    #[test]
    fn split_proxy_takes_host_and_port_from_the_url() {
        assert_eq!(split_proxy("http://10.89.7.2:8888"), ("10.89.7.2", "8888"));
        assert_eq!(split_proxy("http://10.89.7.2:8888/"), ("10.89.7.2", "8888"));
        assert_eq!(split_proxy("http://[fd00::2]:8888"), ("[fd00::2]", "8888"));
        // No port is HTTP's own, for ssh's proxyport= as much as for Maven.
        assert_eq!(split_proxy("http://10.89.7.2"), ("10.89.7.2", "80"));
        assert_eq!(split_proxy("http://[fd00::2]/"), ("[fd00::2]", "80"));
    }

    fn test_ca(name: &str) -> (String, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), cert.der().to_vec())
    }

    #[test]
    fn the_java_truststore_holds_every_certificate_of_the_bundle() {
        let (pem_a, der_a) = test_ca("base");
        let (pem_b, der_b) = test_ca("proxy");
        let (store, skipped) = jks_truststore(format!("{pem_a}{pem_b}").as_bytes()).unwrap();
        assert_eq!(skipped, 0);

        assert_eq!(&store[..4], &[0xFE, 0xED, 0xFE, 0xED]);
        assert_eq!(u32::from_be_bytes(store[8..12].try_into().unwrap()), 2);
        let find = |needle: &[u8]| store.windows(needle.len()).any(|w| w == needle);
        assert!(find(&der_a) && find(&der_b));

        let (body, digest) = store.split_at(store.len() - 20);
        let mut expected = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        for unit in "changeit".encode_utf16() {
            expected.update(&unit.to_be_bytes());
        }
        expected.update(b"Mighty Aphrodite");
        expected.update(body);
        assert_eq!(digest, expected.finish().as_ref());
    }

    #[test]
    fn a_block_java_could_not_read_is_left_out_rather_than_poisoning_the_store() {
        let (pem, der) = test_ca("good");
        // Valid base64, not a certificate: Java would refuse the whole store.
        let junk = "-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQ==\n-----END CERTIFICATE-----\n";
        let other = "-----BEGIN TRUSTED CERTIFICATE-----\nAAEC\n-----END TRUSTED CERTIFICATE-----\n";
        // Not even base64: the PEM reader errors, and resumes after the block.
        let undecodable = "-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n";
        let bundle = format!("{junk}{undecodable}{other}{pem}");
        let (store, skipped) = jks_truststore(bundle.as_bytes()).unwrap();
        assert_eq!(skipped, 2, "the unknown label is not a certificate to count");
        assert_eq!(u32::from_be_bytes(store[8..12].try_into().unwrap()), 1);
        assert!(store.windows(der.len()).any(|w| w == der));

        // A block with no END line, at the end of a bundle, costs only itself.
        let unterminated = "-----BEGIN CERTIFICATE-----\nAAEC\n";
        let (_, skipped) = jks_truststore(format!("{pem}{unterminated}").as_bytes()).unwrap();
        assert_eq!(skipped, 1);

        assert!(jks_truststore(other.as_bytes()).is_err(), "nothing usable is an error");
        assert!(jks_truststore(undecodable.as_bytes()).is_err());
        assert!(jks_truststore(b"not a certificate").is_err());
    }

    #[test]
    fn a_failing_truststore_is_a_warning_not_a_dead_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle.pem");
        fs::write(&bundle, "-----BEGIN TRUSTED CERTIFICATE-----\nAAEC\n-----END TRUSTED CERTIFICATE-----\n").unwrap();
        let home = tmp.path().join("home");

        fs::create_dir_all(&home).unwrap();
        let (_, warnings) = setup_maven(&home, Some(PROXY), Some(&bundle), &operator(&[]));
        assert!(warnings.iter().any(|w| w.contains("no Java truststore")), "{warnings:?}");
        assert!(!home.join(MAVEN_TRUSTSTORE).exists());
        assert!(home.join(MAVEN_GLOBAL_SETTINGS).exists(), "the proxy itself still goes out");
    }

    #[test]
    fn host_bridge_includes_nix_port_without_changing_public_host_ports() {
        assert_eq!(host_bridge_ports("3000,8000", Some("7419")), ["3000", "8000", "7419"]);
        assert_eq!(host_bridge_ports("3000", Some("3000")), ["3000"]);
        assert_eq!(host_bridge_ports("", None), Vec::<String>::new());
    }
}
