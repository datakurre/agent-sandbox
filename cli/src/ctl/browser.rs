//! `agent-sandbox browser` -- a throwaway Chromium on the host, behind the
//! project's own deny-by-default proxy, with a CDP port the sandbox can be
//! given.
//!
//! The problem this solves is stated in `docs/trust-model.md`: a CDP port
//! mapped with `--host-loopback-port` is the one capability the egress policy
//! cannot bound, because the proxy governs what the *sandbox* connects to and a
//! browser on the host fetches on its own account.  So this command starts a
//! browser that carries a policy of its own -- the same `agent-sandbox-proxy`
//! binary, the same policy file format, the same `ctl proxy allow` escalation,
//! the same connection log and exit summary.
//!
//! Two layers, and they are not equals:
//!
//!   1. **The proxy** is the bound.  Chromium is launched with
//!      `--proxy-server` pointing at a loopback port only this instance knows,
//!      and the proxy denies by default.
//!   2. **The managed policy** (`URLBlocklist`/`URLAllowlist`) is a second,
//!      coarser net over the same allow list.  It exists because a CDP client
//!      can ask for a browser context with a proxy of its own, which layer 1
//!      would not see; `URLBlocklist` is enforced in the browser process and
//!      survives that.  It is best-effort: it needs a `bwrap` bind over
//!      `/etc/chromium/policies/managed`, and when that is unavailable the
//!      command says so rather than failing.
//!
//! Nothing here constrains the person at the keyboard -- they own the machine
//! and could edit the same policy directory.  It constrains the agent driving
//! CDP, which is the threat this is for.

use super::resolve::*;
use crate::agents::{format_proxy_policy, parse_proxy, parse_proxy_profile, ProxyPolicy};
use crate::launch::{proxy_profile_path, BASELINE_DENY_IPS};
use crate::net_summary;
use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::io::BufReader;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Where the browser's CDP listener lands by default.  Matches what the
/// `browser` skill and every CDP tutorial reach for, so the printed relaunch
/// line is the one people already recognise.
pub const DEFAULT_CDP_PORT: u16 = 9222;
/// How far to walk up from `--cdp-port` before giving up.  Enough for a
/// realistic number of concurrent browsers, small enough that a machine with
/// nothing free says so instead of scanning.
const CDP_PORT_SCAN: u16 = 64;
/// Prefix of the per-invocation runtime directory, under `$XDG_RUNTIME_DIR`.
const RUNTIME_PREFIX: &str = "agent-sandbox-browser-";

#[derive(Parser, Debug, Default)]
#[command(
    name = "agent-sandbox-browser",
    about = "Start a throwaway host browser behind a deny-by-default allow list"
)]
pub struct BrowserArgs {
    #[arg(help = "Sandbox name to take published ports from (positional)")]
    pub word: Option<String>,
    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
    #[arg(
        long,
        value_name = "PORT",
        help = "CDP port to listen on; walks up if taken (default 9222)"
    )]
    pub cdp_port: Option<u16>,
    #[arg(
        long,
        value_name = "HOST[:PORT]",
        help = "Allow a domain, IP/CIDR or host:port; repeatable"
    )]
    pub allow: Vec<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Merge a host-owned network profile; repeatable"
    )]
    pub proxy_profile: Vec<String>,
    #[arg(
        long,
        help = "Also merge the [network] block from AGENTS.md in the current directory"
    )]
    pub network: bool,
    #[arg(
        long,
        help = "Do not seed the allow list from the sandbox's published loopback ports"
    )]
    pub no_published_ports: bool,
    #[arg(
        long,
        value_name = "DIR",
        help = "Load an unpacked extension; repeatable"
    )]
    pub extension: Vec<String>,
    #[arg(
        long,
        help = "Load no extensions, including any built into this wrapper"
    )]
    pub no_extensions: bool,
    #[arg(
        long,
        value_name = "DIR",
        help = "Reuse a profile directory instead of an ephemeral one"
    )]
    pub keep_profile: Option<String>,
    #[arg(
        long,
        help = "Skip the bwrap managed-policy layer (the proxy still applies)"
    )]
    pub no_policy_overlay: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Chromium binary to launch (default: chromium on PATH)"
    )]
    pub chromium: Option<String>,
}

// ── Allow list ──────────────────────────────────────────────────────────────

/// The allow list, before it becomes either a proxy policy or a `URLAllowlist`.
///
/// Kept as parsed policy lines rather than two independently-derived lists:
/// the whole claim of this command is that both layers describe the same
/// permission, and two derivations would eventually disagree.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AllowList {
    /// `allow_host`/`allow_ip`/`allow_port` lines, in policy-file syntax.
    pub rules: Vec<String>,
}

/// Loopback ports a running sandbox publishes, as `podman inspect` reports
/// them.  Anything bound to a wider interface is skipped: the browser is on the
/// host, so it reaches a loopback bind, and a wider one is not evidence that
/// this sandbox wanted the browser to have it.
pub fn published_loopback_ports(ports_json: &str) -> Vec<u16> {
    let parsed: serde_json::Value = match serde_json::from_str(ports_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = BTreeSet::new();
    if let Some(map) = parsed.as_object() {
        for binds in map.values() {
            let Some(binds) = binds.as_array() else {
                continue;
            };
            for bind in binds {
                let ip = bind.get("HostIp").and_then(|v| v.as_str()).unwrap_or("");
                // "" is podman's way of saying 0.0.0.0.  Only an explicit
                // loopback bind counts.
                if ip != "127.0.0.1" && ip != "::1" {
                    continue;
                }
                if let Some(port) = bind
                    .get("HostPort")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    out.insert(port);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Turn everything the operator named into one ordered rule list.
///
/// Order is additive and deliberately boring -- published ports, then profiles
/// and `AGENTS.md`, then `--allow` -- because the proxy resolves specificity
/// itself and a rule's position in the file has never meant anything.
pub fn build_allow_list(
    published: &[u16],
    declared: &ProxyPolicy,
    explicit: &[String],
) -> AllowList {
    let mut rules = Vec::new();

    for port in published {
        rules.push(format!("allow_ip 127.0.0.1/32:{}", port));
    }

    // `format_proxy_policy` renders a whole file, header and `default` line
    // included; only the rule lines are wanted here.
    for line in format_proxy_policy(declared, "AGENTS.md and proxy profiles").lines() {
        let line = line.trim_end();
        if line.starts_with("allow_host ")
            || line.starts_with("allow_ip ")
            || line.starts_with("allow_port ")
            || line.starts_with("allow_route\t")
        {
            rules.push(line.to_string());
        }
    }

    for target in explicit {
        rules.push(explicit_allow_line(target));
    }

    rules.dedup();
    AllowList { rules }
}

/// `--allow` takes what `ctl proxy allow` takes, so the two are one thing to
/// learn.  A bare port is not accepted here: on the host it would mean "this
/// port on every host", which is never what someone testing a local app wants.
fn explicit_allow_line(target: &str) -> String {
    let host = target.split(':').next().unwrap_or(target);
    if crate::agents::is_ip_or_cidr(host) {
        // `allow_ip` wants a CIDR; a bare address is a /32 or /128.
        let (addr, ports) = match target.rsplit_once(':') {
            Some((a, p)) if !a.is_empty() && p.chars().all(|c| c.is_ascii_digit() || c == '-') => {
                (a, Some(p))
            }
            _ => (target, None),
        };
        let cidr = if addr.contains('/') {
            addr.to_string()
        } else if addr.contains(':') {
            format!("{}/128", addr)
        } else {
            format!("{}/32", addr)
        };
        match ports {
            Some(p) => format!("allow_ip {}:{}", cidr, p),
            None => format!("allow_ip {}", cidr),
        }
    } else {
        format!("allow_host {}", target)
    }
}

/// The full policy file: the allow list, then the built-in denies.
///
/// The baseline is the launcher's, unchanged -- including `127.0.0.0/8`.  That
/// looks wrong for a browser whose whole job may be to reach a local dev
/// server, and it is exactly right: the published-port rules above are
/// `/32`-with-port and beat the `/8`, so the browser reaches the ports this
/// sandbox published and no other service on the operator's loopback.
pub fn policy_file(allow: &AllowList) -> String {
    let mut out = String::from("default deny\n");
    for rule in &allow.rules {
        out.push_str(rule);
        out.push('\n');
    }
    for cidr in BASELINE_DENY_IPS {
        out.push_str(&format!("deny_ip {}\n", cidr));
    }
    out
}

/// Just the baseline lines, for `policy.baseline`.
pub fn baseline_file() -> String {
    BASELINE_DENY_IPS
        .iter()
        .map(|cidr| format!("deny_ip {}\n", cidr))
        .collect()
}

// ── Managed policy ──────────────────────────────────────────────────────────

/// `URLAllowlist` entries for the same permission the proxy holds.
///
/// Chromium's filter format is `[scheme://][.]host[:port][/path]`, which cannot
/// express a CIDR or a port range, so this layer is coarser than the proxy by
/// construction: a rule it cannot represent exactly is widened to the host, and
/// the proxy remains the thing that actually decides.  Widening here can only
/// ever let through what layer 1 still refuses.
pub fn url_allowlist(allow: &AllowList) -> Vec<String> {
    let mut out = Vec::new();
    for rule in &allow.rules {
        if let Some(rest) = rule.strip_prefix("allow_host ") {
            let (host, ports) = split_target(rest);
            out.push(match single_port(ports) {
                Some(p) => format!("{}:{}", host, p),
                None => host.to_string(),
            });
        } else if let Some(rest) = rule.strip_prefix("allow_ip ") {
            let (cidr, ports) = split_target(rest);
            // Only a single address is expressible; a real network is not.
            let host = match cidr.split_once('/') {
                Some((addr, "32")) | Some((addr, "128")) => addr,
                Some(_) => continue,
                None => cidr,
            };
            out.push(match single_port(ports) {
                Some(p) => format!("{}:{}", host, p),
                None => host.to_string(),
            });
        } else if let Some(rest) = rule.strip_prefix("allow_route\t") {
            // `domain\tmethod\tpath`; the domain is the only part this layer
            // can express.
            if let Some(domain) = rest.split('\t').next() {
                out.push(domain.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Split a policy target into its host part and its optional `:ports` suffix,
/// keeping IPv6 addresses (which are full of colons) intact.
fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.rsplit_once(':') {
        Some((host, ports))
            if !host.is_empty()
                && ports
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '-' || c == ',') =>
        {
            (host, Some(ports))
        }
        _ => (target, None),
    }
}

/// A port suffix is only usable in a Chromium filter when it names exactly one
/// port; a list or a range has to widen to the whole host.
fn single_port(ports: Option<&str>) -> Option<&str> {
    let p = ports?;
    if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
        Some(p)
    } else {
        None
    }
}

/// The managed policy written into the per-instance policy directory.
pub fn managed_policy_json(
    allow: &AllowList,
    proxy_port: u16,
    extensions: &[String],
) -> serde_json::Value {
    let mut policy = json!({
        // Default deny, then the same permission the proxy holds.  This is the
        // layer that still applies inside a CDP-created context with a proxy of
        // its own.
        "URLBlocklist": ["*"],
        "URLAllowlist": url_allowlist(allow),
        // Pin the proxy so it cannot be switched off from the settings UI.
        "ProxySettings": {
            "ProxyMode": "fixed_servers",
            "ProxyServer": format!("http://127.0.0.1:{}", proxy_port),
            "ProxyBypassList": "<-loopback>",
        },
        // The profile is ephemeral and holds no credentials.  These keep it
        // that way, so a driven browser cannot accumulate any.
        "BrowserSignin": 0,
        "SyncDisabled": true,
        "IncognitoModeAvailability": 1,
        "PasswordManagerEnabled": false,
        "AutofillAddressEnabled": false,
        "AutofillCreditCardEnabled": false,
        "MetricsReportingEnabled": false,
        "BackgroundModeEnabled": false,
        // Without this an omnibox typo becomes a search query, which is a
        // request to a host nobody allowed.
        "DefaultSearchProviderEnabled": false,
    });

    if !extensions.is_empty() {
        // Unpacked extensions arrive by `--load-extension`; this stops anything
        // *else* from being installed into the profile afterwards.
        policy["ExtensionSettings"] = json!({
            "*": { "installation_mode": "blocked" },
        });
    }
    policy
}

// ── Launching ───────────────────────────────────────────────────────────────

/// Everything the two argv builders need, so both stay pure and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLaunch {
    pub profile_dir: String,
    pub cdp_port: u16,
    pub proxy_port: u16,
    pub extensions: Vec<String>,
}

/// Chromium's own arguments.
pub fn chromium_args(cfg: &BrowserLaunch) -> Vec<String> {
    let mut args = vec![
        // Not optional: Chromium 136+ refuses --remote-debugging-port on the
        // default profile, and a separate profile is what keeps this browser
        // from touching the operator's own cookies.
        format!("--user-data-dir={}", cfg.profile_dir),
        format!("--remote-debugging-port={}", cfg.cdp_port),
        // Never 0.0.0.0: CDP has no authentication, so reachability is the only
        // thing between this and anyone on the network.
        "--remote-debugging-address=127.0.0.1".to_string(),
        format!("--proxy-server=http://127.0.0.1:{}", cfg.proxy_port),
        // Chromium bypasses loopback by default, which would put the sandbox's
        // published ports outside the policy that is supposed to name them.
        "--proxy-bypass-list=<-loopback>".to_string(),
        // QUIC does not traverse an HTTP proxy, so this changes nothing today
        // and forecloses a silent direct path if that ever changes.
        "--disable-quic".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
    ];
    if !cfg.extensions.is_empty() {
        // Still supported here because nixpkgs ships Chromium, not branded
        // Chrome -- which removed --load-extension in 137 and
        // --disable-extensions-except in 139.
        args.push(format!("--load-extension={}", cfg.extensions.join(",")));
        args.push(format!(
            "--disable-extensions-except={}",
            cfg.extensions.join(",")
        ));
    }
    args
}

/// Chromium's policy directory, a compile-time constant in the browser with no
/// flag or environment override.  A bind mount in a user namespace is the only
/// way to make it per-instance.
const CHROMIUM_POLICY_DIR: &str = "/etc/chromium/policies/managed";

/// How the managed policy gets to `CHROMIUM_POLICY_DIR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayMode {
    /// The directory already exists, so it can simply be bound over.
    Bind,
    /// It does not.  bwrap can only create a mount point where the namespace's
    /// root can write, and a real `/etc` is not that -- so `/etc` gets a
    /// throwaway overlay first, and the directory is created inside it.  Needs
    /// bubblewrap 0.9+ and unprivileged overlayfs.
    OverlayEtc,
}

/// The bwrap wrapper that puts this instance's managed policy where Chromium
/// looks for it.
///
/// `--dev-bind / /` keeps the rest of the filesystem exactly as it was: this
/// adds one override, it is not a sandbox and does not pretend to be.
pub fn bwrap_args(
    managed_dir: &str,
    mode: OverlayMode,
    program: &str,
    program_args: &[String],
) -> Vec<String> {
    let mut args = vec!["--dev-bind".to_string(), "/".to_string(), "/".to_string()];
    if mode == OverlayMode::OverlayEtc {
        // Writes go to an invisible tmpfs, so the host's /etc is untouched and
        // nothing survives the process.
        args.push("--tmp-overlay".to_string());
        args.push("/etc".to_string());
    }
    args.push("--bind".to_string());
    args.push(managed_dir.to_string());
    args.push(CHROMIUM_POLICY_DIR.to_string());
    args.push("--".to_string());
    args.push(program.to_string());
    args.extend(program_args.iter().cloned());
    args
}

/// Pick an overlay mode by *trying* each one, rather than guessing from a
/// bubblewrap version and a kernel config.
///
/// Both halves of this are load-bearing and neither is knowable in advance:
/// whether the host has a Chromium policy directory at all (most do not --
/// nixpkgs' Chromium is installed into a profile, not into `/etc`), and whether
/// this kernel gives an unprivileged user overlayfs.  A probe costs one process
/// and turns both into a fact.
fn select_overlay_mode(managed_dir: &str) -> std::result::Result<OverlayMode, String> {
    if which("bwrap").is_none() {
        return Err("bwrap is not on PATH".to_string());
    }
    let probe = which("true")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/bin/true".to_string());

    let mut modes = Vec::new();
    if Path::new(CHROMIUM_POLICY_DIR).is_dir() {
        modes.push(OverlayMode::Bind);
    }
    modes.push(OverlayMode::OverlayEtc);

    for mode in modes {
        let ok = Command::new("bwrap")
            .args(bwrap_args(managed_dir, mode, &probe, &[]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(mode);
        }
    }
    Err(format!(
        "bwrap cannot bind over {} (no such directory, and no unprivileged overlayfs for /etc)",
        CHROMIUM_POLICY_DIR
    ))
}

/// Which browser to start: `--chromium`, then the one the Nix wrapper pinned,
/// then whatever the host has.
///
/// Chromium-family only, and Chromium by preference: branded Chrome removed
/// `--load-extension` in 137 and `--disable-extensions-except` in 139, so an
/// extension list quietly does nothing there.
pub fn resolve_chromium(explicit: Option<&str>) -> Result<String> {
    if let Some(path) = explicit {
        return Ok(path.to_string());
    }
    if let Ok(path) = std::env::var("AGENT_SANDBOX_BROWSER_CHROMIUM") {
        if !path.is_empty() {
            return Ok(path);
        }
    }
    for name in [
        "chromium",
        "chromium-browser",
        "google-chrome-stable",
        "google-chrome",
    ] {
        if let Some(path) = which(name) {
            return Ok(path.to_string_lossy().to_string());
        }
    }
    anyhow::bail!(
        "no Chromium found on PATH.\n\
         Run one with a pinned browser instead:\n\
         \x20 nix run github:datakurre/agent-sandbox#browser\n\
         or point this at your own with --chromium PATH."
    )
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// Split the wrapper's `AGENT_SANDBOX_BROWSER_EXTENSIONS`.  Colon-separated
/// like `PATH`, because these are store paths and a store path never contains
/// one.
pub fn parse_extension_paths(value: &str) -> Vec<String> {
    value
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// First free port at or above `start`, asking `is_free` rather than binding,
/// so the scan is testable without a network.
pub fn pick_port(start: u16, is_free: impl Fn(u16) -> bool) -> Option<u16> {
    (0..CDP_PORT_SCAN)
        .filter_map(|offset| start.checked_add(offset))
        .find(|port| is_free(*port))
}

fn port_is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// A browser this user has running, as `ctl proxy --browser` sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The runtime directory, which is also the policy directory.
    pub dir: String,
    /// The uuid suffix, used as the name to disambiguate with.
    pub name: String,
    pub cdp_port: u16,
    pub pid: u32,
}

/// Every browser whose process is still alive.
///
/// A crashed browser can leave its runtime directory behind -- `Drop` does not
/// run on SIGKILL -- so liveness is checked rather than assumed, and the stale
/// directory is swept while we are here.  Otherwise `ctl proxy allow --browser`
/// would report an ambiguity between a live browser and a dead one.
pub fn running_instances() -> Vec<Instance> {
    let runtime_root = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", nix::unistd::getuid().as_raw()));
    let Ok(entries) = fs::read_dir(&runtime_root) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(RUNTIME_PREFIX) else {
            continue;
        };
        let Ok(meta) = fs::read_to_string(path.join("meta.json")) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta) else {
            continue;
        };
        let pid = meta.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        if pid == 0 || !process_is_alive(pid) {
            let _ = fs::remove_dir_all(&path);
            continue;
        }
        out.push(Instance {
            dir: path.to_string_lossy().to_string(),
            name: suffix.to_string(),
            cdp_port: meta.get("cdp_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
            pid,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Signal 0: asks the kernel whether the pid exists without disturbing it.
fn process_is_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

// ── Cleanup ─────────────────────────────────────────────────────────────────

/// Stops the proxy, renders the session's traffic, and removes the runtime
/// directory.  Everything runs from `Drop` so a signal on the way out leaves
/// nothing behind; nothing here may panic.
struct BrowserGuard {
    runtime_dir: String,
    proxy: Option<Child>,
    keep_profile: bool,
}

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        if let Some(child) = self.proxy.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let log = format!("{}/connections.jsonl", self.runtime_dir);
        if let Ok(file) = fs::File::open(&log) {
            let records = net_summary::read_records(BufReader::new(file));
            if !records.is_empty() {
                net_summary::process_summary(records);
            }
        }
        if self.keep_profile {
            // The operator asked for the profile to survive; the rest of the
            // directory is this session's and still goes.
            for name in [
                "policy",
                "policy.base",
                "policy.baseline",
                "connections.jsonl",
                "denied-requests.jsonl",
                "meta.json",
            ] {
                let _ = fs::remove_file(format!("{}/{}", self.runtime_dir, name));
            }
            let _ = fs::remove_dir_all(format!("{}/policies", self.runtime_dir));
            let _ = fs::remove_dir(&self.runtime_dir);
        } else {
            let _ = fs::remove_dir_all(&self.runtime_dir);
        }
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn run(args: BrowserArgs) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_default();
    // Extensions baked in by the Nix wrapper (`browserExtensions`), as a
    // colon-separated path list.  Command-line `--extension` adds to these;
    // `--no-extensions` drops the lot.
    let default_extensions = parse_extension_paths(
        &std::env::var("AGENT_SANDBOX_BROWSER_EXTENSIONS").unwrap_or_default(),
    );

    // A sandbox is optional.  Without one there are no published ports to seed
    // from, which is a thinner allow list, not an error -- someone may well
    // want a policed browser before the sandbox exists.
    let sandbox = match resolve_target(&args) {
        // An empty name is "nothing is running", which is ordinary enough not
        // to be worth a line of its own.
        Ok(name) if name.is_empty() => None,
        Ok(name) => Some(name),
        Err(reason) => {
            eprintln!("browser: {}", reason);
            None
        }
    };

    let published = match (&sandbox, args.no_published_ports) {
        (Some(name), false) => {
            let ports = podman_published_ports(name).unwrap_or_default();
            if ports.is_empty() {
                eprintln!(
                    "browser: {} publishes no loopback ports; the allow list starts empty",
                    name
                );
            }
            ports
        }
        _ => Vec::new(),
    };

    // Declared rules: profiles first, then AGENTS.md if asked for.  Same
    // parsers and same merge order the launcher uses.
    let mut declared = ProxyPolicy {
        default: vec!["deny".to_string()],
        ..Default::default()
    };
    for name in &args.proxy_profile {
        let path = proxy_profile_path(&home, name).map_err(|e| anyhow::anyhow!(e))?;
        let text = fs::read_to_string(&path).with_context(|| {
            format!("cannot read proxy profile '{}' ({})", name, path.display())
        })?;
        let policy = parse_proxy_profile(&text)
            .map_err(|e| anyhow::anyhow!("invalid proxy profile '{}': {}", name, e))?;
        declared.merge(policy);
    }
    if args.network {
        let path = PathBuf::from("AGENTS.md");
        let text =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let policy =
            parse_proxy(&text).map_err(|e| anyhow::anyhow!("invalid [network] block: {}", e))?;
        declared.merge(policy);
    }

    let allow = build_allow_list(&published, &declared, &args.allow);

    // Ports before any files: a clash should fail before there is anything to
    // clean up.
    let cdp_port =
        pick_port(args.cdp_port.unwrap_or(DEFAULT_CDP_PORT), port_is_free).ok_or_else(|| {
            anyhow::anyhow!(
                "no free port in {} starting at {}",
                CDP_PORT_SCAN,
                args.cdp_port.unwrap_or(DEFAULT_CDP_PORT)
            )
        })?;
    // The proxy port is never advertised, so it can be anything free.
    let proxy_port = TcpListener::bind("127.0.0.1:0")
        .context("cannot reserve a proxy port")?
        .local_addr()
        .context("cannot read the reserved proxy port")?
        .port();

    let runtime_dir = make_runtime_dir()?;
    let profile_dir = match &args.keep_profile {
        Some(dir) => {
            fs::create_dir_all(dir)
                .with_context(|| format!("cannot create profile directory {}", dir))?;
            dir.clone()
        }
        None => format!("{}/profile", runtime_dir),
    };
    let mut guard = BrowserGuard {
        runtime_dir: runtime_dir.clone(),
        proxy: None,
        keep_profile: args.keep_profile.is_some(),
    };

    let policy_text = policy_file(&allow);
    fs::write(format!("{}/policy", runtime_dir), &policy_text)?;
    fs::write(format!("{}/policy.base", runtime_dir), &policy_text)?;
    fs::write(format!("{}/policy.baseline", runtime_dir), baseline_file())?;

    let extensions = if args.no_extensions {
        Vec::new()
    } else {
        let mut list = default_extensions.clone();
        list.extend(args.extension.iter().cloned());
        list
    };

    let managed_dir = format!("{}/policies/managed", runtime_dir);
    fs::create_dir_all(&managed_dir)?;
    fs::write(
        format!("{}/agent-sandbox.json", managed_dir),
        serde_json::to_string_pretty(&managed_policy_json(&allow, proxy_port, &extensions))?,
    )?;

    fs::write(
        format!("{}/meta.json", runtime_dir),
        serde_json::to_string_pretty(&json!({
            "cdp_port": cdp_port,
            "proxy_port": proxy_port,
            "sandbox": sandbox,
            "pid": std::process::id(),
        }))?,
    )?;

    // The proxy first: Chromium's very first request must already meet a policy.
    let mut proxy_cmd = Command::new("agent-sandbox-proxy");
    proxy_cmd
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", proxy_port))
        .arg("--policy")
        .arg(format!("{}/policy", runtime_dir))
        .arg("--log")
        .arg(format!("{}/connections.jsonl", runtime_dir))
        .arg("--detail-log")
        .arg(format!("{}/denied-requests.jsonl", runtime_dir))
        .arg("--shared-dir")
        .arg(&runtime_dir)
        // On the host egress readiness is not in question, and the 30s ceiling
        // would only be a stall on the way to a browser window.
        .arg("--no-egress-probe")
        .stdout(Stdio::null());
    guard.proxy = Some(
        proxy_cmd
            .spawn()
            .context("cannot start agent-sandbox-proxy (is agent-sandbox installed?)")?,
    );
    wait_for_proxy(&runtime_dir);

    let launch = BrowserLaunch {
        profile_dir,
        cdp_port,
        proxy_port,
        extensions,
    };
    let chromium = resolve_chromium(args.chromium.as_deref())?;
    let cargs = chromium_args(&launch);

    let overlay = if args.no_policy_overlay {
        Err("--no-policy-overlay".to_string())
    } else {
        select_overlay_mode(&managed_dir)
    };
    let mut browser_cmd = match overlay {
        Ok(mode) => {
            let mut c = Command::new("bwrap");
            c.args(bwrap_args(&managed_dir, mode, &chromium, &cargs));
            c
        }
        Err(reason) => {
            eprintln!("browser: no managed-policy layer ({}).", reason);
            eprintln!("browser: egress is still proxied and denied by default, but a CDP client");
            eprintln!("browser: can create a browser context with a proxy of its own and bypass");
            eprintln!("browser: that, and this is the layer that would have caught it.");
            let mut c = Command::new(&chromium);
            c.args(&cargs);
            c
        }
    };

    print_banner(cdp_port, &allow, sandbox.as_deref());

    let status = browser_cmd
        .status()
        .with_context(|| format!("cannot start {}", chromium))?;
    drop(guard);
    if !status.success() {
        anyhow::bail!("{} exited with {}", chromium, status);
    }
    Ok(())
}

/// Resolve the sandbox to take published ports from, or say why there is none.
///
/// Every failure here is a note, not an error: a browser with a thinner allow
/// list is still a browser, and someone may well want one before the sandbox
/// it will test exists.  Only an explicitly named sandbox that cannot be found
/// is worth more than one line.
fn resolve_target(args: &BrowserArgs) -> std::result::Result<String, String> {
    let explicit = args.container.as_deref().or(args.word.as_deref());
    match sandbox_containers() {
        Err(e) if explicit.is_none() => Err(format!(
            "cannot ask podman what is running ({}); the allow list comes from \
             --allow and profiles only",
            e
        )),
        Ok(running) if running.is_empty() && explicit.is_none() => Ok(String::new()),
        _ => resolve_sandbox(explicit, true).map_err(|e| e.to_string()),
    }
}

fn podman_published_ports(sandbox: &str) -> Option<Vec<u16>> {
    let out = Command::new("podman")
        .args([
            "inspect",
            sandbox,
            "--format",
            "{{json .NetworkSettings.Ports}}",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(published_loopback_ports(
        String::from_utf8_lossy(&out.stdout).trim(),
    ))
}

fn make_runtime_dir() -> Result<String> {
    let runtime_root = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", nix::unistd::getuid().as_raw()));
    let dir = format!(
        "{}/{}{}",
        runtime_root,
        RUNTIME_PREFIX,
        &uuid::Uuid::new_v4().to_string()[0..8]
    );
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir))?;
    // Only this user's, whatever the umask: the policy in here decides what a
    // browser holding the operator's session may fetch.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot restrict {}", dir))?;
    Ok(dir)
}

/// Block briefly until the proxy has written its readiness marker, so the
/// browser does not race it and show a connection error on the first tab.
fn wait_for_proxy(runtime_dir: &str) {
    let marker = format!("{}/proxy-ready", runtime_dir);
    for _ in 0..100 {
        if Path::new(&marker).exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("browser: the proxy did not report ready; starting anyway");
}

fn print_banner(cdp_port: u16, allow: &AllowList, sandbox: Option<&str>) {
    let allowed = url_allowlist(allow);
    eprintln!(
        "browser: CDP on 127.0.0.1:{}, egress deny-by-default",
        cdp_port
    );
    if allowed.is_empty() {
        eprintln!("browser: nothing is allowed yet -- widen it with:");
    } else {
        eprintln!("browser: allowed: {}", allowed.join(" "));
    }
    eprintln!("browser:   agent-sandbox ctl proxy allow <host>:443 --browser");
    eprintln!("browser:");
    eprintln!("browser: now run, keeping whatever flags you already use:");
    eprintln!(
        "browser:   agent-sandbox --host-loopback-port {port} -e AGENT_SANDBOX_BROWSER_CDP_PORT={port} -- claude",
        port = cdp_port
    );
    if sandbox.is_some() {
        eprintln!("browser:");
        eprintln!(
            "browser: that sandbox is already running -- the flag only takes effect at launch,"
        );
        eprintln!("browser: so this applies to the next one you start.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_of(rules: &[&str]) -> AllowList {
        AllowList {
            rules: rules.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn only_loopback_binds_are_taken_as_published() {
        // A 0.0.0.0 bind is reachable from the browser too, but it is not
        // evidence that this sandbox meant the browser to have it.
        let json = r#"{
            "3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}],
            "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
            "5432/tcp": [{"HostIp": "", "HostPort": "5432"}]
        }"#;
        assert_eq!(published_loopback_ports(json), vec![3000]);
    }

    #[test]
    fn no_ports_is_not_an_error() {
        assert!(published_loopback_ports("null").is_empty());
        assert!(published_loopback_ports("{}").is_empty());
        assert!(published_loopback_ports("not json").is_empty());
    }

    #[test]
    fn published_ports_become_specific_loopback_rules() {
        let allow = build_allow_list(&[3000, 8000], &ProxyPolicy::default(), &[]);
        assert_eq!(
            allow.rules,
            vec!["allow_ip 127.0.0.1/32:3000", "allow_ip 127.0.0.1/32:8000"]
        );
    }

    #[test]
    fn the_policy_file_denies_by_default_and_keeps_the_baseline() {
        let text = policy_file(&build_allow_list(&[3000], &ProxyPolicy::default(), &[]));
        assert!(text.starts_with("default deny\n"), "{text}");
        // The /32-with-port rule is more specific than the /8, which is what
        // lets the browser reach the published port and nothing else on
        // loopback.
        assert!(text.contains("allow_ip 127.0.0.1/32:3000"), "{text}");
        assert!(text.contains("deny_ip 127.0.0.0/8"), "{text}");
    }

    #[test]
    fn the_generated_policy_is_one_the_proxy_actually_accepts() {
        // The proxy exits 2 on a policy it cannot parse, which would show up as
        // a browser that never starts.  Check against the real parser rather
        // than against the string we just wrote.
        let allow = build_allow_list(
            &[3000, 8000],
            &ProxyPolicy::default(),
            &[
                "example.com:443".to_string(),
                "10.1.2.3".to_string(),
                "192.168.0.0/16:8080".to_string(),
            ],
        );
        let text = policy_file(&allow);
        let config = agent_sandbox_proxy::policy::parse_policy(&text)
            .unwrap_or_else(|e| panic!("generated policy must parse: {e}\n{text}"));
        assert!(
            !config.default_allow,
            "the browser policy must deny by default"
        );

        // And it must decide the way the banner claims it does.
        assert!(config.is_allowed("127.0.0.1", 3000), "the published port");
        assert!(
            !config.is_allowed("127.0.0.1", 5432),
            "another service on the operator's loopback must stay unreachable"
        );
        assert!(config.is_allowed("example.com", 443));
        assert!(!config.is_allowed("example.com", 80), "only the named port");
        assert!(!config.is_allowed("evil.example", 443));
    }

    #[test]
    fn explicit_allows_take_what_ctl_proxy_allow_takes() {
        let allow = build_allow_list(
            &[],
            &ProxyPolicy::default(),
            &[
                "example.com:443".to_string(),
                "10.1.2.3".to_string(),
                "192.168.0.0/16:8080".to_string(),
            ],
        );
        assert_eq!(
            allow.rules,
            vec![
                "allow_host example.com:443",
                "allow_ip 10.1.2.3/32",
                "allow_ip 192.168.0.0/16:8080",
            ]
        );
    }

    #[test]
    fn the_url_allowlist_mirrors_the_proxy_rules() {
        let allow = allow_of(&[
            "allow_ip 127.0.0.1/32:3000",
            "allow_host example.com:443",
            "allow_host docs.example.org",
        ]);
        assert_eq!(
            url_allowlist(&allow),
            vec!["127.0.0.1:3000", "docs.example.org", "example.com:443"]
        );
    }

    #[test]
    fn a_range_widens_to_the_host_rather_than_being_dropped_wrongly() {
        // Chromium filters cannot express a port range, so the browser layer
        // widens; the proxy still holds the narrow rule.
        let allow = allow_of(&["allow_host example.com:8000-8100"]);
        assert_eq!(url_allowlist(&allow), vec!["example.com"]);
    }

    #[test]
    fn a_real_cidr_has_no_url_filter_equivalent_and_is_skipped() {
        let allow = allow_of(&["allow_ip 10.0.0.0/8:443"]);
        assert!(url_allowlist(&allow).is_empty());
    }

    #[test]
    fn the_managed_policy_denies_everything_then_allows_the_list() {
        let allow = allow_of(&["allow_ip 127.0.0.1/32:3000"]);
        let policy = managed_policy_json(&allow, 41234, &[]);
        assert_eq!(policy["URLBlocklist"], json!(["*"]));
        assert_eq!(policy["URLAllowlist"], json!(["127.0.0.1:3000"]));
        assert_eq!(
            policy["ProxySettings"]["ProxyServer"],
            json!("http://127.0.0.1:41234")
        );
        // An omnibox typo must not become a request to a search engine nobody
        // allowed.
        assert_eq!(policy["DefaultSearchProviderEnabled"], json!(false));
    }

    #[test]
    fn chromium_gets_its_own_profile_and_the_proxy() {
        let args = chromium_args(&BrowserLaunch {
            profile_dir: "/run/x/profile".to_string(),
            cdp_port: 9222,
            proxy_port: 41234,
            extensions: Vec::new(),
        });
        assert!(args.contains(&"--user-data-dir=/run/x/profile".to_string()));
        assert!(args.contains(&"--remote-debugging-port=9222".to_string()));
        assert!(args.contains(&"--remote-debugging-address=127.0.0.1".to_string()));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:41234".to_string()));
        // Chromium bypasses loopback by default, which would put the published
        // ports outside the policy naming them.
        assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--load-extension")));
    }

    #[test]
    fn extensions_are_loaded_and_nothing_else_is() {
        let args = chromium_args(&BrowserLaunch {
            profile_dir: "/p".to_string(),
            cdp_port: 9222,
            proxy_port: 1,
            extensions: vec!["/a".to_string(), "/b".to_string()],
        });
        assert!(args.contains(&"--load-extension=/a,/b".to_string()));
        assert!(args.contains(&"--disable-extensions-except=/a,/b".to_string()));
    }

    #[test]
    fn bwrap_binds_the_policy_dir_and_then_execs_chromium() {
        let args = bwrap_args(
            "/run/x/policies/managed",
            OverlayMode::Bind,
            "chromium",
            &["--foo".to_string()],
        );
        assert_eq!(
            args,
            vec![
                "--dev-bind",
                "/",
                "/",
                "--bind",
                "/run/x/policies/managed",
                "/etc/chromium/policies/managed",
                "--",
                "chromium",
                "--foo",
            ]
        );
    }

    #[test]
    fn without_a_policy_dir_etc_gets_a_throwaway_overlay_first() {
        // bwrap cannot create a mount point in a real /etc, which is why most
        // hosts -- where Chromium came from a Nix profile and never wrote to
        // /etc -- need this variant rather than the plain bind.
        let args = bwrap_args(
            "/run/x/policies/managed",
            OverlayMode::OverlayEtc,
            "chromium",
            &[],
        );
        let overlay = args.windows(2).position(|w| w[0] == "--tmp-overlay");
        let bind = args.windows(2).position(|w| w[0] == "--bind");
        assert_eq!(args[overlay.expect("overlay") + 1], "/etc");
        assert!(
            overlay < bind,
            "/etc has to be writable before the bind can create its mount point: {args:?}"
        );
    }

    #[test]
    fn the_cdp_port_walks_up_past_a_busy_one() {
        assert_eq!(pick_port(9222, |p| p >= 9224), Some(9224));
        assert_eq!(pick_port(9222, |_| true), Some(9222));
        assert_eq!(pick_port(9222, |_| false), None);
    }
}
