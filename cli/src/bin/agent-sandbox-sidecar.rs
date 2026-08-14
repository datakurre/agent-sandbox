#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

const POLICY_FILE: &str = "/sidecar_policy/policy";
const SECRET_BINDINGS_FILE: &str = "/sidecar_secrets/bindings";
const METRICS_LOG: &str = "/sidecar_shared/connections.jsonl";
const DETAIL_LOG: &str = "/sidecar_shared/denied-requests.jsonl";
const EXEMPT_PROTO: &str = "200";
const RESOLV_CONF: &str = "/etc/resolv.conf";

struct Config {
    dry_run: bool,
    policy_file: String,
    resolv_conf: String,
    metrics_log: String,
}

impl Config {
    fn new() -> Self {
        let dry_run = env::var("AGENT_SANDBOX_SIDECAR_DRY_RUN").unwrap_or_default() == "1";
        let policy_file = if dry_run {
            env::var("AGENT_SANDBOX_SIDECAR_POLICY").unwrap_or_else(|_| POLICY_FILE.to_string())
        } else {
            POLICY_FILE.to_string()
        };
        let resolv_conf = if dry_run {
            env::var("AGENT_SANDBOX_SIDECAR_RESOLV_CONF")
                .unwrap_or_else(|_| RESOLV_CONF.to_string())
        } else {
            RESOLV_CONF.to_string()
        };
        let metrics_log = if dry_run {
            "/dev/null".to_string()
        } else {
            METRICS_LOG.to_string()
        };

        Self {
            dry_run,
            policy_file,
            resolv_conf,
            metrics_log,
        }
    }

    fn run_ip(&self, args: &[&str]) -> Result<()> {
        if self.dry_run {
            println!("ip {}", args.join(" "));
            return Ok(());
        }
        let status = Command::new("ip").args(args).status()?;
        if !status.success() {
            anyhow::bail!("ip command failed");
        }
        Ok(())
    }
}

fn policy_values(file: &str, key_filter: &str) -> Vec<String> {
    let mut values = Vec::new();
    if let Ok(contents) = fs::read_to_string(file) {
        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            if let Some(key) = parts.next() {
                if key == key_filter {
                    if let Some(val) = parts.next() {
                        values.push(val.to_string());
                    }
                }
            }
        }
    }
    values
}

fn resolv_nameservers(file: &str) -> Vec<String> {
    let mut ns = Vec::new();
    if let Ok(contents) = fs::read_to_string(file) {
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("nameserver ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    ns.push(parts[1].to_string());
                }
            }
        }
    }
    ns
}

fn route_prefix(entry: &str) -> String {
    if entry.ends_with("/32") && !entry.contains(':') {
        entry.trim_end_matches("/32").to_string()
    } else if entry.ends_with("/128") {
        entry.trim_end_matches("/128").to_string()
    } else {
        entry.to_string()
    }
}

fn want_exemptions(config: &Config) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    let mut entries = policy_values(&config.policy_file, "allow_ips");
    entries.extend(resolv_nameservers(&config.resolv_conf));

    for mut entry in entries {
        if entry == "0.0.0.0/0" || entry == "::/0" {
            continue;
        }
        entry = route_prefix(&entry);
        if seen.insert(entry.clone()) {
            result.push(entry);
        }
    }
    result
}

fn want_blackholes(config: &Config) -> Vec<String> {
    let exempt = want_exemptions(config);
    let exempt_set: HashSet<String> = exempt.into_iter().collect();
    let mut result = Vec::new();

    let entries = policy_values(&config.policy_file, "deny_ips");
    for mut entry in entries {
        entry = route_prefix(&entry);
        if !exempt_set.contains(&entry) {
            result.push(entry);
        }
    }
    result
}

fn installed_exemptions(config: &Config) -> Vec<String> {
    if config.dry_run {
        return Vec::new();
    }
    let mut result = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["-o", "route", "show", "proto", EXEMPT_PROTO])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                result.push(parts[0].to_string());
            }
        }
    }
    result
}

fn installed_blackholes(config: &Config) -> Vec<String> {
    if config.dry_run {
        return Vec::new();
    }
    let mut result = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["-o", "route", "show", "type", "blackhole"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                result.push(parts[1].to_string());
            }
        }
    }
    result
}

fn default_gateway(config: &Config, family: &str) -> Option<(String, String)> {
    if config.dry_run {
        return Some(("10.88.0.1".to_string(), "eth0".to_string()));
    }
    if let Ok(output) = Command::new("ip")
        .args(["-o", family, "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let mut via = None;
            let mut dev = None;
            for i in 0..parts.len() {
                if parts[i] == "via" && i + 1 < parts.len() {
                    via = Some(parts[i + 1].to_string());
                }
                if parts[i] == "dev" && i + 1 < parts.len() {
                    dev = Some(parts[i + 1].to_string());
                }
            }
            if let (Some(v), Some(d)) = (via, dev) {
                return Some((v, d));
            }
        }
    }
    None
}

fn sync_routes(config: &Config) {
    let want_ex = want_exemptions(config);
    let have_ex = installed_exemptions(config);
    let want_ex_set: HashSet<_> = want_ex.iter().cloned().collect();
    let have_ex_set: HashSet<_> = have_ex.iter().cloned().collect();

    for entry in &want_ex {
        if have_ex_set.contains(entry) {
            continue;
        }
        let family = if entry.contains(':') { "-6" } else { "-4" };
        if let Some((via, dev)) = default_gateway(config, family) {
            let args = vec![
                "route",
                "add",
                entry,
                "via",
                &via,
                "dev",
                &dev,
                "proto",
                EXEMPT_PROTO,
            ];
            if config.run_ip(&args).is_err() {
                eprintln!("sidecar: cannot exempt {}", entry);
            }
        } else {
            eprintln!("sidecar: no default route to exempt {} through", entry);
        }
    }

    for entry in &have_ex {
        if want_ex_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "del", entry, "proto", EXEMPT_PROTO];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot un-exempt {}", entry);
        }
    }

    let want_bh = want_blackholes(config);
    let have_bh = installed_blackholes(config);
    let want_bh_set: HashSet<_> = want_bh.iter().cloned().collect();
    let have_bh_set: HashSet<_> = have_bh.iter().cloned().collect();

    for entry in &want_bh {
        if have_bh_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "add", "blackhole", entry];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot blackhole {}", entry);
        }
    }

    for entry in &have_bh {
        if want_bh_set.contains(entry) {
            continue;
        }
        let args = vec!["route", "del", "blackhole", entry];
        if config.run_ip(&args).is_err() {
            eprintln!("sidecar: cannot un-blackhole {}", entry);
        }
    }
}

fn contains(subnet_cidr: &str, ip_cidr: &str) -> bool {
    let parse_cidr = |cidr: &str| -> Option<(IpAddr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let ip = IpAddr::from_str(parts[0]).ok()?;
        let len = parts[1].parse::<u8>().ok()?;
        Some((ip, len))
    };

    let (sub_ip, sub_len) = match parse_cidr(subnet_cidr) {
        Some(s) => s,
        None => return false,
    };

    let ip_str = if ip_cidr.contains('/') {
        ip_cidr.split('/').next().unwrap()
    } else {
        ip_cidr
    };
    let ip = match IpAddr::from_str(ip_str) {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (sub_ip, ip) {
        (IpAddr::V4(sub), IpAddr::V4(ip)) => {
            let mask = if sub_len == 0 {
                0
            } else {
                (!0u32) << (32 - sub_len)
            };
            (u32::from(sub) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(sub), IpAddr::V6(ip)) => {
            let mask = if sub_len == 0 {
                0
            } else {
                (!0u128) << (128 - sub_len)
            };
            (u128::from(sub) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

fn get_sidecar_listen() -> Result<String> {
    let subnet = env::var("SIDECAR_SUBNET")
        .context("SIDECAR_SUBNET is not set; refusing to bind on all interfaces")?;

    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let ip_cidr = parts[3];
            if contains(&subnet, ip_cidr) {
                return Ok(ip_cidr.split('/').next().unwrap().to_string());
            }
        }
    }
    anyhow::bail!("no local address falls inside {}", subnet);
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() -> Result<()> {
    let config = Config::new();

    if !Path::new(&config.policy_file).exists() {
        eprintln!("sidecar: {} is missing", config.policy_file);
        std::process::exit(1);
    }

    let mut proxy_args = vec![
        "--log".to_string(),
        config.metrics_log.clone(),
        "--detail-log".to_string(),
        if config.dry_run {
            "/dev/null".to_string()
        } else {
            DETAIL_LOG.to_string()
        },
        "--policy".to_string(),
        config.policy_file.clone(),
    ];

    if Path::new(SECRET_BINDINGS_FILE).exists() {
        proxy_args.push("--secret-fd".to_string());
        proxy_args.push("3".to_string());
    }

    let mut sidecar_listen = String::new();
    if !config.dry_run {
        match get_sidecar_listen() {
            Ok(listen) => sidecar_listen = listen,
            Err(e) => {
                eprintln!("sidecar: {}", e);
                std::process::exit(1);
            }
        }
        proxy_args.push("--listen".to_string());
        proxy_args.push(format!("{}:8888", sidecar_listen));
    }

    if config.dry_run {
        println!("agent-sandbox-proxy {}", proxy_args.join(" "));
        sync_routes(&config);
        return Ok(());
    }

    let mut proxy_cmd = if Path::new(SECRET_BINDINGS_FILE).exists() {
        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        cmd.arg(format!(
            "exec 3<'{}'; exec agent-sandbox-proxy \"$@\"",
            SECRET_BINDINGS_FILE
        ));
        cmd.arg("--"); // $0 for bash
        cmd
    } else {
        Command::new("agent-sandbox-proxy")
    };
    proxy_cmd.args(&proxy_args);

    let proxy_child = proxy_cmd.spawn().context("failed to spawn proxy")?;
    let mut proxy_child = ChildGuard(proxy_child);

    if Path::new("/run/host-ssh-agent").exists() || Path::new("/run/host-gpg-agent").exists() {
        Command::new("relay-server")
            .args([
                "--listen",
                &format!("{}:8889", sidecar_listen),
                "--policy",
                &config.policy_file,
            ])
            .spawn()
            .ok();
    }

    let mut ready = false;
    for _ in 0..350 {
        if Path::new("/sidecar_shared/proxy-ready").exists() {
            ready = true;
            break;
        }
        if let Ok(Some(_)) = proxy_child.0.try_wait() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if let Ok(Some(status)) = proxy_child.0.try_wait() {
        eprintln!("sidecar: the proxy exited before signalling readiness");
        std::process::exit(status.code().unwrap_or(1));
    }
    if !ready {
        eprintln!("sidecar: the proxy exited before signalling readiness");
        std::process::exit(1);
    }

    sync_routes(&config);

    fs::write("/sidecar_shared/ready", "ready\n").context("failed to write ready file")?;

    while matches!(proxy_child.0.try_wait(), Ok(None)) {
        thread::sleep(Duration::from_secs(1));
        sync_routes(&config);
    }

    let status = proxy_child.0.wait()?;
    std::process::exit(status.code().unwrap_or(0));
}
