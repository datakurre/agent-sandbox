#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    // 1. nix-store load db
    let skip_nix_init = env::var("AGENT_SANDBOX_SKIP_NIX_INIT").unwrap_or_else(|_| "0".to_string());
    let host_nix = env::var("AGENT_SANDBOX_HOST_NIX").unwrap_or_default();
    if skip_nix_init != "1" && host_nix != "1" {
        let db_path = Path::new("/nix/var/nix/db/db.sqlite");
        let reg_path = Path::new("/nix/registration");
        if !db_path.exists() && reg_path.exists() {
            let file = fs::File::open(reg_path).context("Failed to open /nix/registration")?;
            let status = Command::new("nix-store")
                .arg("--load-db")
                .stdin(Stdio::from(file))
                .status();
            if let Err(e) = status {
                eprintln!("Warning: failed to run nix-store --load-db: {}", e);
            }
        }
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
    if Path::new("/agent.sock").exists() {
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

        let mut needs_append = false;
        if let Ok(content) = fs::read_to_string(&known_hosts) {
            if !content.contains("github.com") {
                needs_append = true;
            }
        } else {
            needs_append = true;
        }

        if needs_append {
            let known_hosts_content = "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\ngithub.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\ngithub.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=\ngitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=\ngitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf\ngitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9\nbitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=\nbitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO\nbitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=\n";
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts)?;
            file.write_all(known_hosts_content.as_bytes())?;
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
                let proxy_host_port = http_proxy.split("://").last().unwrap_or(&http_proxy);
                let mut parts = proxy_host_port.splitn(2, ':');
                let proxy_host = parts.next().unwrap_or("");
                let proxy_port = parts.next().unwrap_or("");

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
        }
    }

    // 6. Git config
    let gitconfig = home_path.join(".config/agent-sandbox/gitconfig");
    if env::var("AGENT_SANDBOX_RELAY_GPG").unwrap_or_default() == "1" {
        if let Some(parent) = gitconfig.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gitconfig)?;
        file.write_all(b"[gpg]\n\tprogram = relay-gpg\n")?;
    }

    if env::var("AGENT_SANDBOX_NO_GPG_SIGN").unwrap_or_default() == "1" {
        if let Some(parent) = gitconfig.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gitconfig)?;
        // Tags as well as commits: the host config that switched signing on
        // usually switches on both, and either one fails the same way without
        // a forwarded agent.
        file.write_all(b"[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n")?;
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

    if gitconfig.exists() {
        env::set_var("GIT_CONFIG_COUNT", (base_count + 1).to_string());
        env::set_var(format!("GIT_CONFIG_KEY_{}", base_count), "include.path");
        env::set_var(
            format!("GIT_CONFIG_VALUE_{}", base_count),
            gitconfig.to_string_lossy().to_string(),
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
    // The launcher mounted one socket per mapping and is splicing the far end
    // to a port on the host's loopback; this puts a TCP listener in front of
    // each, because the clients that want them -- CDP, a database driver --
    // speak TCP and not unix sockets.  127.0.0.1 both because NO_PROXY already
    // exempts it under --proxy and because Chrome's DevTools host check accepts
    // an IP but not an arbitrary name.
    //
    // Spawned, not threaded: this process execs below, which would take any
    // thread of ours with it.  socat outlives that as a child of PID 1 and dies
    // with the container.
    if let Ok(ports) = env::var("AGENT_SANDBOX_HOST_PORTS") {
        for port in ports.split(',').filter(|p| !p.is_empty()) {
            let socket = format!("/run/agent-sandbox-host/{}.sock", port);
            let spawned = Command::new("socat")
                .arg(format!("TCP-LISTEN:{},bind=127.0.0.1,fork,reuseaddr", port))
                .arg(format!("UNIX-CONNECT:{}", socket))
                .spawn();
            if let Err(e) = spawned {
                eprintln!("agent-sandbox: could not forward host port {}: {}", port, e);
            }
        }
    }

    // 9. Browser MCP server
    // `playwright-mcp` is on the image PATH, so the only thing missing is a
    // client that knows about it.  Writing the config here rather than baking
    // it in is not a preference: ~/.config is a tmpfs mount, so anything baked
    // into the image at that path is gone before the agent starts.
    //
    // Off unless asked for.  A default launch must behave exactly as it did
    // before this step existed -- the config file below is only useful when
    // something arranged a browser to point it at, and appending an argument to
    // the agent's own command line is not something to do to every session.
    let mcp_args = browser_mcp_setup();

    // 10. exec "$@"
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let err = Command::new(&args[1]).args(&args[2..]).args(&mcp_args).exec();
        eprintln!("Failed to exec {}: {}", args[1], err);
        std::process::exit(1);
    }

    Ok(())
}

/// Where the generated MCP config lands.  Under `~/.config`, which is a tmpfs:
/// deliberately *not* one of the agent state paths the launcher bind-mounts
/// from the host, so this never edits the operator's real agent configuration.
const MCP_CONFIG: &str = "/home/user/.config/agent-sandbox/mcp.json";

/// Write an MCP config for `playwright-mcp` and return any arguments the agent
/// needs to pick it up.
///
/// Two modes, both explicit:
///
/// * `AGENT_SANDBOX_BROWSER_CDP_PORT=N` -- drive the browser `agent-sandbox
///   browser` started on the host, over the loopback port the launcher mapped.
///   This is what the line that command prints asks for.
/// * `AGENT_SANDBOX_BROWSER_MCP=headless` -- launch a headless browser in here
///   instead, needing no host cooperation at all.
///
/// `AGENT_SANDBOX_BROWSER_MCP=off` turns both off.
fn browser_mcp_setup() -> Vec<String> {
    let mode = env::var("AGENT_SANDBOX_BROWSER_MCP").unwrap_or_default();
    if mode == "off" {
        return Vec::new();
    }
    let cdp_port = env::var("AGENT_SANDBOX_BROWSER_CDP_PORT")
        .ok()
        .filter(|v| !v.is_empty());

    let server_args: Vec<String> = match (&cdp_port, mode.as_str()) {
        (Some(port), _) => vec![
            "--cdp-endpoint".to_string(),
            // 127.0.0.1 rather than localhost: the entrypoint's socat listener
            // is on the v4 loopback, and Chrome's DevTools host check accepts
            // an IP but not an arbitrary name.
            format!("http://127.0.0.1:{}", port),
        ],
        (None, "headless") => vec!["--headless".to_string(), "--isolated".to_string()],
        (None, _) => return Vec::new(),
    };

    let Ok(server) = which("mcp-server-playwright").or_else(|_| which("playwright-mcp")) else {
        eprintln!("agent-sandbox: playwright-mcp is not on PATH; skipping browser MCP setup");
        return Vec::new();
    };

    let config = serde_json::json!({
        "mcpServers": {
            "playwright": {
                "command": server.to_string_lossy(),
                "args": server_args,
            }
        }
    });
    if let Some(parent) = Path::new(MCP_CONFIG).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let rendered = match serde_json::to_string_pretty(&config) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("agent-sandbox: could not render the browser MCP config: {}", e);
            return Vec::new();
        }
    };
    if let Err(e) = fs::write(MCP_CONFIG, rendered) {
        eprintln!("agent-sandbox: could not write {}: {}", MCP_CONFIG, e);
        return Vec::new();
    }

    // Only Claude Code gets the argument appended, because `--mcp-config` is
    // additive there and leaves the operator's own servers alone.  Every other
    // agent is told where the file is and registers it itself -- rewriting five
    // config formats, each of which is a host-mounted state file, would trade a
    // one-line hint for a way to corrupt someone's real configuration.
    let argv0 = env::args().nth(1).unwrap_or_default();
    let agent = Path::new(&argv0)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if agent == "claude" {
        return vec!["--mcp-config".to_string(), MCP_CONFIG.to_string()];
    }
    eprintln!(
        "agent-sandbox: browser MCP config written to {} (register it with e.g. `codex mcp add`)",
        MCP_CONFIG
    );
    Vec::new()
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
