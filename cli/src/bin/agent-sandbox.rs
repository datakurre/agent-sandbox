#![forbid(unsafe_code)]
#![allow(unused)]

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use clap::{Parser, Subcommand};
use agent_sandbox_cli::ctl;
use agent_sandbox_cli::agents::{parse_proxy, format_proxy_policy};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufRead, BufReader, IsTerminal};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::Builder;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox",
    about = "Agent sandbox control CLI",
    version = "0.1.0"
)]
struct CtlCli {
    #[command(subcommand)]
    command: CtlCommands,
}

#[derive(Subcommand, Debug)]
enum CtlCommands {
    #[command(about = "Load the agent-sandbox image")] Load(ctl::load::LoadArgs),
    #[command(about = "List sandboxes and their proxy mode")] List(ctl::list::ListArgs),
    #[command(about = "Summarise one running sandbox")] Status(ctl::status::StatusArgs),
    #[command(about = "Manage proxy rules")] Proxy(ctl::proxy::ProxyArgs),
    #[command(about = "Show network metering for a running sandbox")] Net(ctl::net::NetArgs),
    #[command(about = "Show the proxy log for a running sandbox", alias = "log")] Logs(ctl::logs::LogsArgs),
    #[command(about = "Publish container ports to the host", alias = "ports")] Port(ctl::port::PortArgs),
    #[command(about = "Attach to a running sandbox and exec a command")] Attach(ctl::attach::AttachArgs),
    #[command(about = "Manage bind mounts into a running sandbox", alias = "mounts")] Mount(ctl::mount::MountArgs),
    #[command(about = "Show SSH/GPG relay policy and logs")] Relay(ctl::relay::RelayArgs),
    #[command(about = "Interactive ask-mode dashboard")] Tui(ctl::tui::TuiArgs),
    #[command(about = "Reclaim leftover containers, networks and directories")] Purge(ctl::purge::PurgeArgs),
}

#[derive(Debug, Clone, PartialEq)]
enum AgentMountsMode {
    Auto,
    All,
    None,
    List(Vec<String>),
}

fn expand_v(spec: &str, current_dir: &Path, home_dir: &str) -> String {
    let parts: Vec<&str> = spec.split(':').collect();
    let mut src = parts[0].replace("~", home_dir);
    if src == "." {
        src = current_dir.to_string_lossy().into_owned();
    }
    if !src.starts_with('/') {
        src = format!("{}/{}", current_dir.to_string_lossy(), src);
    }
    
    let dest = if parts.len() > 1 && !parts[1].is_empty() {
        let mut d = parts[1].to_string();
        if !d.starts_with('/') {
            if d == "." {
                d = "/workspace".to_string();
            } else {
                d = format!("/workspace/{}", d);
            }
        }
        d
    } else {
        src.clone()
    };
    
    if parts.len() > 2 {
        format!("{}:{}:{}", src, dest, parts[2..].join(":"))
    } else {
        format!("{}:{}", src, dest)
    }
}

fn enforce_selinux_mount_flags(mount_opt: &str, want_selinux: bool) -> String {
    let parts: Vec<&str> = mount_opt.split(':').collect();
    if parts.len() < 2 {
        return mount_opt.to_string();
    }
    
    let mut new_parts = parts.clone();
    
    if parts.len() == 2 {
        if want_selinux {
            new_parts.push("Z");
        }
    } else {
        let opts = parts[2..].join(":");
        let mut opt_list: Vec<&str> = opts.split(',').collect();
        
        if want_selinux {
            if !opt_list.contains(&"z") && !opt_list.contains(&"Z") {
                opt_list.push("Z");
            }
        } else {
            opt_list.retain(|&x| x != "z" && x != "Z");
        }
        
        if opt_list.is_empty() {
            new_parts.truncate(2);
        } else {
            let joined_opts = opt_list.join(",");
            return format!("{}:{}:{}", parts[0], parts[1], joined_opts);
        }
    }
    
    new_parts.join(":")
}

fn parse_port_spec(spec: &str, bind_address: &str) -> Result<String> {
    let mut proto = "tcp";
    let mut spec_str = spec;
    if spec.contains('/') {
        let parts: Vec<&str> = spec.splitn(2, '/').collect();
        spec_str = parts[0];
        proto = parts[1];
    }
    let (host, container) = if spec_str.contains(':') {
        let parts: Vec<&str> = spec_str.splitn(2, ':').collect();
        (parts[0], parts[1])
    } else {
        (spec_str, spec_str)
    };
    
    if host.parse::<u16>().is_err() || container.parse::<u16>().is_err() {
        bail!("agent-sandbox: --port '{}': expected [HOST:]CONTAINER[/PROTO]", spec);
    }
    let host_n: u16 = host.parse()?;
    let container_n: u16 = container.parse()?;
    
    if host_n < 1 || container_n < 1 {
        bail!("agent-sandbox: --port '{}': ports must be within 1-65535", spec);
    }
    if proto != "tcp" && proto != "udp" {
        bail!("agent-sandbox: --port '{}': protocol must be tcp or udp", spec);
    }
    
    Ok(format!("{}:{}:{}/{}", bind_address, host, container, proto))
}

fn usable_nameservers(file: &Path) -> Result<Vec<String>> {
    let mut ns = Vec::new();
    if !file.exists() {
        return Ok(ns);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("nameserver") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let candidate = parts[1];
        let lower = candidate.to_lowercase();
        if lower.starts_with("127.") || lower.starts_with("169.254.") || lower == "::1" || lower.starts_with("fe80:") || lower.contains('%') {
            continue;
        }
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            ns.push(candidate.to_string());
        }
    }
    Ok(ns)
}

fn usable_search(file: &Path) -> Result<Vec<String>> {
    let mut search = Vec::new();
    if !file.exists() {
        return Ok(search);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("search") && !line.starts_with("domain") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for word in parts.into_iter().skip(1) {
            let is_valid = word.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            if is_valid {
                search.push(word.to_string());
            }
        }
    }
    Ok(search)
}

fn usable_dns_options(file: &Path) -> Result<Vec<String>> {
    let mut opts = Vec::new();
    if !file.exists() {
        return Ok(opts);
    }
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("options") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for word in parts.into_iter().skip(1) {
            opts.push(word.to_string());
        }
    }
    Ok(opts)
}

fn print_usage(
    agent_list: &str,
    want_workspace: bool,
    want_ssh: bool,
    want_git: bool,
    want_gpg: bool,
    want_gpg_private: bool,
    want_devenv: bool,
    want_nix: bool,
    want_podman: bool,
    want_selinux: bool,
    want_proxy: bool,
    want_krun: bool,
    want_ports: bool,
    want_mounts: bool,
    want_agent_mounts_mode: &AgentMountsMode,
) {
    let fmt = |b: bool| if b { "[on ]" } else { "[off]" };
    let agent_mounts_all = matches!(want_agent_mounts_mode, AgentMountsMode::All);

    println!(
        "agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]\n\
\n\
Runs an AI coding agent inside a rootless podman container.\n\
Use flags to opt-in to integrations like mounting the current directory,\n\
forwarding SSH, or exposing Git identity.\n\
\n\
  agent-sandbox                      launch interactive bash (no agent state mounted)\n\
  agent-sandbox opencode             launch opencode with its own state mounted\n\
  agent-sandbox --agent-mounts       launch interactive bash with every agent's state mounted\n\
  agent-sandbox --podman opencode    launch opencode with podman enabled\n\
  agent-sandbox opencode -- bash     launch bash with opencode's state mounted\n\
  agent-sandbox --privileged opencode\n\
                                     pass --privileged to podman run\n\
\n\
Agents:\n\
  {}\n\
\n\
Integrations (use --X to enable, --no-X to disable):\n\
  --workspace       {} Mounts the host's current working directory into /workspace/<dirname>.\n\
  --ssh             {} Forwards the host's SSH_AUTH_SOCK to the container.\n\
  --git             {} Mounts host Git configurations and passes identity env vars.\n\
  --gpg             {} Enables host GnuPG agent forwarding and git commit signing behavior.\n\
  --gpg-private     {} Exposes ~/.gnupg even if it holds on-disk secret keys.\n\
  --devenv          {} Persists ~/.local/share/devenv across sessions.\n\
  --nix             {} Mounts the host /nix/store for native Nix execution.\n\
  --podman          {} Forwards the host rootless Podman socket (sibling containers).\n\
  --selinux         {} Applies SELinux shared relabeling (:z) to writable binds.\n\
  --proxy           {} Routes HTTP(S)/SSH through a proxy, enforcing AGENTS.md's [proxy] policy if present (blocks direct internet access).\n\
                         Also enables 'agent-sandbox-ctl net' for the running sandbox.\n\
  --krun            {} Runs the sandbox as a KVM microVM with its own kernel (needs /dev/kvm).\n\
                         Adds a guest-kernel boundary inside the existing container boundary.\n\
                         'agent-sandbox-ctl attach' and 'ctl mounts' do not work against a krun sandbox.\n\
\n\
Ports:\n\
  --port [HOST:]CONTAINER[/PROTO]          Publish a port, repeatable.\n\
  --ports / --no-ports               {} Honors [ports] declarations from AGENTS.md.\n\
  --ports-dynamic                          Allows `agent-sandbox-ctl ports add` post-launch.\n\
  --ports-any-interface                    Permits port binds outside of loopback interfaces.\n\
\n\
Mounts:\n\
  --mounts / --no-mounts             {} Honors [mounts] declarations from AGENTS.md.\n\
\n\
Agent state:\n\
  --agent-mounts                     {} Mount every agent's state, not just the one launched.\n\
  --agent-mounts=AGENT[,AGENT...]    Mount only these agents' state (plus any launched agent). Only the \"=\" form takes a list.\n\
  --no-agent-mounts                  Mount no agent state, even for the launched agent.\n\
\n\
Podman / Environment:\n\
  --privileged              pass --privileged to podman run (for nested podman)\n\
  --krun-memory MiB         guest RAM under --krun (default 4096, must exceed 128)\n\
  --krun-cpus N             guest vCPUs under --krun (1-16, default: host affinity)\n\
  -e, --env NAME=VAL        pass environment variable to podman\n\
  --podman-args             treat all following args (until --) as podman args\n\
\n\
--podman, --ssh and --gpg each hand the agent a capability that reaches\n\
outside the sandbox. --podman forwards the host podman socket, allowing the\n\
agent to create sibling containers on the host (a full sandbox escape).\n\
To safely let the agent run containers, use --privileged instead to enable\n\
securely nested containers inside the sandbox. See README for details.\n\
\n\
--krun closes none of those three. It adds a guest kernel under the agent, so\n\
code the agent runs faces a hypervisor before it faces the host kernel, but the\n\
VM runs inside the same container namespaces and the same proxy topology as\n\
before. It is not a substitute for leaving the three flags off.",
        agent_list,
        fmt(want_workspace),
        fmt(want_ssh),
        fmt(want_git),
        fmt(want_gpg),
        fmt(want_gpg_private),
        fmt(want_devenv),
        fmt(want_nix),
        fmt(want_podman),
        fmt(want_selinux),
        fmt(want_proxy),
        fmt(want_krun),
        fmt(want_ports),
        fmt(want_mounts),
        fmt(agent_mounts_all)
    );
}


struct CleanupGuard {
    sidecar_id: String,
    sidecar_shared: String,
    sidecar_policy: String,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.sidecar_id.is_empty() {
            let _ = ProcessCommand::new("podman").args(["stop", "-t", "1", &self.sidecar_id]).output();
            let _ = ProcessCommand::new("podman").args(["rm", "-f", &self.sidecar_id]).output();
            
            // Reclaim network
            for _ in 0..20 {
                if ProcessCommand::new("podman").args(["network", "rm", &self.sidecar_id]).output().is_ok() {
                    if ProcessCommand::new("podman").args(["network", "exists", &self.sidecar_id]).status().map(|s| !s.success()).unwrap_or(true) {
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            
            if !self.sidecar_shared.is_empty() { let _ = fs::remove_dir_all(&self.sidecar_shared); }
            if !self.sidecar_policy.is_empty() { let _ = fs::remove_dir_all(&self.sidecar_policy); }
        }
    }
}

fn main() -> Result<()> {

    let mut want_ssh = false;
    let mut want_git = false;
    let mut want_gpg = false;
    let mut want_gpg_private = false;
    let mut want_devenv = false;
    let mut want_nix = false;
    let mut want_podman = false;
    let mut want_workspace = false;
    let mut want_selinux = false;
    let mut want_ports = false;
    let mut want_ports_dynamic = false;
    let mut want_ports_any_interface = false;
    let mut want_mounts = false;
    let mut want_agent_mounts_mode = AgentMountsMode::Auto;
    let mut want_proxy = false;
    let mut proxy_train = String::new();
    let mut want_krun = false;
    let mut want_privileged = false;
    let mut want_help = false;
    let mut krun_ram_mib = String::new();
    let mut krun_cpus = String::new();
    let mut agent = String::new();
    let mut port_specs = Vec::new();
    let mut cmd_args = Vec::new();
    let mut podman_args = Vec::new();
    let mut env_args = Vec::new();
    let mut mounts = Vec::new();
    let mut sidecar_extra_mounts: Vec<String> = Vec::new();
    let mut sidecar_extra_env: Vec<String> = Vec::new();
    let mut publish_args: Vec<String> = Vec::new();
    let mut published = Vec::new();
    
    let _krun_runtime = env::var("AGENT_SANDBOX_KRUN_RUNTIME").unwrap_or_else(|_| "krun".to_string());
    let default_agent_specs = "opencode\t[\"opencode\",\".\"]\t[\".local/share/opencode\",\".config/opencode\",\".cache/opencode\"]\t[]\nclaude-code\t[\"claude\"]\t[\".claude\"]\t[\".claude.json\"]\ncopilot\t[\"copilot\"]\t[\".copilot\"]\t[]\nantigravity\t[\"agy\",\".\"]\t[\".local/share/antigravity-cli\",\".config/antigravity-cli\",\".cache/antigravity-cli\",\".gemini\"]\t[]".to_string();
    let agent_specs_str = env::var("AGENT_SANDBOX_AGENT_SPECS").unwrap_or(default_agent_specs);
    
    let mut agent_names = Vec::new();
    let mut agent_cmd_json = HashMap::new();
    let mut agent_state_json = HashMap::new();
    let mut agent_state_files_json = HashMap::new();
    
    for line in agent_specs_str.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            let name = parts[0].to_string();
            if name.is_empty() { continue; }
            agent_names.push(name.clone());
            agent_cmd_json.insert(name.clone(), parts[1].to_string());
            agent_state_json.insert(name.clone(), parts[2].to_string());
            agent_state_files_json.insert(name.clone(), parts[3].to_string());
        }
    }
    let agent_list = agent_names.join(" ");
    
    let args: Vec<String> = env::args().skip(1).collect();

    // Subcommand routing for ctl
    if !args.is_empty() {
        let first_arg = &args[0];
        let ctl_subcommands = ["load", "list", "status", "proxy", "net", "logs", "log", "port", "ports", "attach", "mount", "mounts", "relay", "tui", "purge"];
        let mut run_ctl = false;
        let mut parse_args = vec!["agent-sandbox".to_string()];
        
        if first_arg == "ctl" {
            run_ctl = true;
            if args.len() == 1 {
                parse_args.push("--help".to_string());
            } else {
                parse_args.extend(args.iter().skip(1).cloned());
            }
        } else if ctl_subcommands.contains(&first_arg.as_str()) && !agent_cmd_json.contains_key(first_arg) {
            run_ctl = true;
            parse_args.extend(args.iter().cloned());
        }
        
        if run_ctl {
            let cli = match CtlCli::try_parse_from(parse_args) {
                Ok(c) => c,
                Err(e) => e.exit(),
            };
            
            match cli.command {
                CtlCommands::Load(a) => ctl::load::run(a)?,
                CtlCommands::List(a) => ctl::list::run(a)?,
                CtlCommands::Status(a) => ctl::status::run(a)?,
                CtlCommands::Proxy(a) => ctl::proxy::run(a)?,
                CtlCommands::Net(a) => ctl::net::run(a)?,
                CtlCommands::Logs(a) => ctl::logs::run(a)?,
                CtlCommands::Port(a) => ctl::port::run(a)?,
                CtlCommands::Attach(a) => ctl::attach::run(a)?,
                CtlCommands::Mount(a) => ctl::mount::run(a)?,
                CtlCommands::Relay(a) => ctl::relay::run(a)?,
                CtlCommands::Tui(a) => ctl::tui::run(a)?,
                CtlCommands::Purge(a) => ctl::purge::run(a)?,
            }
            return Ok(());
        }
    }

    let mut i = 0;
    let mut parsing_podman = false;
    
    while i < args.len() {
        let arg = &args[i];
        if parsing_podman {
            if arg == "--" {
                parsing_podman = false;
                i += 1;
                cmd_args.extend(args[i..].iter().cloned());
                break;
            } else {
                podman_args.push(arg.clone());
                i += 1;
                continue;
            }
        }
        
        if agent_cmd_json.contains_key(arg) {
            agent = arg.clone();
            i += 1;
            continue;
        }
        
        match arg.as_str() {
            "-h" | "--help" | "help" => want_help = true,
            "--ssh" => want_ssh = true,
            "--no-ssh" => want_ssh = false,
            "--git" => want_git = true,
            "--no-git" => want_git = false,
            "--gpg" => want_gpg = true,
            "--no-gpg" => want_gpg = false,
            "--gpg-private" => want_gpg_private = true,
            "--no-gpg-private" => want_gpg_private = false,
            "--devenv" => want_devenv = true,
            "--no-devenv" => want_devenv = false,
            "--nix" => want_nix = true,
            "--no-nix" => want_nix = false,
            "--podman" => want_podman = true,
            "--no-podman" => want_podman = false,
            "--workspace" => want_workspace = true,
            "--no-workspace" => want_workspace = false,
            "--selinux" => want_selinux = true,
            "--no-selinux" => want_selinux = false,
            "--ports" => want_ports = true,
            "--no-ports" => want_ports = false,
            "--ports-dynamic" => want_ports_dynamic = true,
            "--no-ports-dynamic" => want_ports_dynamic = false,
            "--ports-any-interface" => want_ports_any_interface = true,
            "--mounts" => want_mounts = true,
            "--no-mounts" => want_mounts = false,
            "--agent-mounts" => want_agent_mounts_mode = AgentMountsMode::All,
            "--no-agent-mounts" => want_agent_mounts_mode = AgentMountsMode::None,
            "--proxy" => want_proxy = true,
            "--no-proxy" => want_proxy = false,
            "--krun" => want_krun = true,
            "--no-krun" => want_krun = false,
            "--podman-args" => parsing_podman = true,
            "--privileged" => {
                want_privileged = true;
                podman_args.push("--privileged".to_string());
            }
            "--" => {
                i += 1;
                cmd_args.extend(args[i..].iter().cloned());
                break;
            }
            _ => {
                if arg.starts_with("--agent-mounts=") {
                    let list = arg.strip_prefix("--agent-mounts=").unwrap();
                    let list_vec: Vec<String> = list.split(',').map(|s| s.to_string()).collect();
                    for a in &list_vec {
                        if !agent_cmd_json.contains_key(a) {
                            eprintln!("agent-sandbox: --agent-mounts: unknown agent '{}' (valid: {})", a, agent_list);
                            std::process::exit(1);
                        }
                    }
                    want_agent_mounts_mode = AgentMountsMode::List(list_vec);
                } else if arg == "--proxy-train" {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("agent-sandbox: --proxy-train needs an argument");
                        std::process::exit(1);
                    }
                    proxy_train = args[i].clone();
                } else if arg.starts_with("--proxy-train=") {
                    proxy_train = arg.strip_prefix("--proxy-train=").unwrap().to_string();
                } else if arg == "--port" {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("agent-sandbox: --port needs an argument");
                        std::process::exit(1);
                    }
                    port_specs.push(args[i].clone());
                } else if arg.starts_with("--port=") {
                    port_specs.push(arg.strip_prefix("--port=").unwrap().to_string());
                } else if arg == "--krun-memory" {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("agent-sandbox: --krun-memory needs an argument");
                        std::process::exit(1);
                    }
                    krun_ram_mib = args[i].clone();
                } else if arg.starts_with("--krun-memory=") {
                    krun_ram_mib = arg.strip_prefix("--krun-memory=").unwrap().to_string();
                } else if arg == "--krun-cpus" {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("agent-sandbox: --krun-cpus needs an argument");
                        std::process::exit(1);
                    }
                    krun_cpus = args[i].clone();
                } else if arg.starts_with("--krun-cpus=") {
                    krun_cpus = arg.strip_prefix("--krun-cpus=").unwrap().to_string();
                } else if arg == "-e" || arg == "--env" {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("agent-sandbox: -e/--env needs an argument");
                        std::process::exit(1);
                    }
                    env_args.push("-e".to_string());
                    env_args.push(args[i].clone());
                } else if arg.starts_with("-e") {
                    env_args.push("-e".to_string());
                    env_args.push(arg.strip_prefix("-e").unwrap().to_string());
                } else if arg.starts_with("--env=") {
                    env_args.push("-e".to_string());
                    env_args.push(arg.strip_prefix("--env=").unwrap().to_string());
                } else if arg.starts_with("-v") {
                    eprintln!("agent-sandbox: '{}' is not an agent-sandbox flag.", arg);
                    std::process::exit(1);
                } else if arg.starts_with("--") {
                    eprintln!("agent-sandbox: '{}' is not an agent-sandbox flag.", arg);
                    std::process::exit(1);
                } else {
                    eprintln!("agent-sandbox: unexpected argument '{}'.", arg);
                    std::process::exit(1);
                }
            }
        }
        i += 1;
    }
    
    if want_help {
        print_usage(
            &agent_list,
            want_workspace,
            want_ssh,
            want_git,
            want_gpg,
            want_gpg_private,
            want_devenv,
            want_nix,
            want_podman,
            want_selinux,
            want_proxy,
            want_krun,
            want_ports,
            want_mounts,
            &want_agent_mounts_mode,
        );
        std::process::exit(0);
    }
    
    // Check proxy network conflicts (Requirement 4)
    if want_proxy {
        let mut idx = 0;
        while idx < podman_args.len() {
            let arg = &podman_args[idx];
            if arg == "--network=host" || arg == "--net=host" {
                eprintln!("agent-sandbox: hard failure: --proxy cannot be combined with host networking via podman-args");
                std::process::exit(1);
            }
            if arg == "--network" || arg == "--net" {
                if idx + 1 < podman_args.len() && podman_args[idx + 1] == "host" {
                    eprintln!("agent-sandbox: hard failure: --proxy cannot be combined with host networking via podman-args");
                    std::process::exit(1);
                }
            }
            idx += 1;
        }
    }

    if want_krun {
        if want_podman {
            eprintln!("agent-sandbox: --krun cannot be combined with --podman.");
            std::process::exit(1);
        }
        if !krun_ram_mib.is_empty() {
            if let Ok(ram) = krun_ram_mib.parse::<u32>() {
                if ram <= 128 {
                    eprintln!("agent-sandbox: --krun-memory needs a whole number of MiB greater than 128.");
                    std::process::exit(1);
                }
            } else {
                eprintln!("agent-sandbox: --krun-memory needs a whole number of MiB greater than 128.");
                std::process::exit(1);
            }
        } else {
            krun_ram_mib = "4096".to_string();
        }
        
        if !krun_cpus.is_empty() {
            if let Ok(cpus) = krun_cpus.parse::<u32>() {
                if cpus < 1 || cpus > 16 {
                    eprintln!("agent-sandbox: --krun-cpus needs a whole number between 1 and 16.");
                    std::process::exit(1);
                }
            } else {
                eprintln!("agent-sandbox: --krun-cpus needs a whole number between 1 and 16.");
                std::process::exit(1);
            }
        }
    }

    if agent.is_empty() && cmd_args.is_empty() {
        cmd_args.push("bash".to_string());
    }

    let mut rw_mount_opts = "rw".to_string();
    if want_selinux {
        rw_mount_opts = "rw,z".to_string();
    }

    
    let mut agent_mount_set = HashSet::new();
    match want_agent_mounts_mode {
        AgentMountsMode::None => {}
        AgentMountsMode::All => {
            for a in &agent_names {
                agent_mount_set.insert(a.clone());
            }
        }
        AgentMountsMode::List(ref l) => {
            for a in l {
                agent_mount_set.insert(a.clone());
            }
            if !agent.is_empty() {
                agent_mount_set.insert(agent.clone());
            }
        }
        AgentMountsMode::Auto => {
            if !agent.is_empty() {
                agent_mount_set.insert(agent.clone());
            }
        }
    }

    for a in &agent_mount_set {
        if let Some(json_str) = agent_state_json.get(a) {
            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(rel) = item.as_str() {
                            let host = format!("{}/{}", env::var("HOME").unwrap_or_default(), rel);
                            let container = format!("/home/user/{}", rel);
                            fs::create_dir_all(&host).unwrap_or(());
                            mounts.push("-v".to_string());
                            mounts.push(format!("{}:{}:{}", host, container, rw_mount_opts));
                        }
                    }
                }
            }
        }
        if let Some(json_str) = agent_state_files_json.get(a) {
            if let Ok(val) = serde_json::from_str::<Value>(json_str) {
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(rel) = item.as_str() {
                            let host = format!("{}/{}", env::var("HOME").unwrap_or_default(), rel);
                            let container = format!("/home/user/{}", rel);
                            if !Path::new(&host).exists() {
                                fs::write(&host, "{}").unwrap_or(());
                            }
                            mounts.push("-v".to_string());
                            mounts.push(format!("{}:{}:{}", host, container, rw_mount_opts));
                        }
                    }
                }
            }
        }
    }

    let bind_address = if want_ports_any_interface {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    
    // Mount processing
    for spec in port_specs {
        if let Ok(triple) = parse_port_spec(&spec, bind_address) {
            publish_args.push("-p".to_string());
            publish_args.push(triple.clone());
            published.push(triple);
        }
    }
    
    if want_proxy {
        if !published.is_empty() || want_ports_dynamic {
            eprintln!("agent-sandbox: --proxy cannot be combined with a published port or --ports-dynamic.");
            std::process::exit(1);
        }
    }
    
    let container_name = format!("agent-sandbox-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    
    // We enforce SELinux mount flags everywhere mounts is updated
    // We enforce SELinux mount flags everywhere mounts is updated
    let mut enforce = |mut m: Vec<String>| -> Vec<String> {
        let mut n = Vec::new();
        let mut i = 0;
        while i < m.len() {
            if m[i] == "-v" && i + 1 < m.len() {
                n.push("-v".to_string());
                n.push(enforce_selinux_mount_flags(&m[i+1], want_selinux));
                i += 2;
            } else {
                n.push(m[i].clone());
                i += 1;
            }
        }
        n
    };
    
    let pwd = env::current_dir().unwrap_or_default().to_string_lossy().into_owned();
    let workspace_dir = if want_workspace {
        let workspace_name = Path::new(&pwd).file_name().unwrap_or_default().to_string_lossy().into_owned();
        let dir = format!("/workspace/{}", workspace_name);
        mounts.push("-v".to_string());
        mounts.push(format!("{}:{}:{}", pwd, dir, rw_mount_opts));
        dir
    } else {
        "/workspace".to_string()
    };
    
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let mut passwd_file = Builder::new().prefix("agent-sandbox-passwd-").tempfile().expect("Failed to create temporary passwd file");
    let mut group_file = Builder::new().prefix("agent-sandbox-group-").tempfile().expect("Failed to create temporary group file");
    fs::set_permissions(passwd_file.path(), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(group_file.path(), fs::Permissions::from_mode(0o644)).unwrap();
    writeln!(passwd_file, "root:x:0:0:root:/root:/bin/sh").unwrap();
    writeln!(passwd_file, "user:x:{}:{}::/home/user:/bin/bash", uid, gid).unwrap();
    writeln!(passwd_file, "nobody:x:65534:65534:Nobody:/:/bin/sh").unwrap();
    writeln!(group_file, "root:x:0:").unwrap();
    writeln!(group_file, "user:x:{}:", gid).unwrap();
    writeln!(group_file, "nobody:x:65534:").unwrap();
    let passwd_path = passwd_file.path().to_string_lossy().into_owned();
    let group_path = group_file.path().to_string_lossy().into_owned();
    mounts.push("-v".to_string());
    mounts.push(format!("{}:/etc/passwd:ro", passwd_path));
    mounts.push("-v".to_string());
    mounts.push(format!("{}:/etc/group:ro", group_path));

    mounts = enforce(mounts);
    
    let mut _cleanup_guard = CleanupGuard { sidecar_id: String::new(), sidecar_shared: String::new(), sidecar_policy: String::new() };
    let mut sidecar_network_arg = None;
    let mut proxy_env_vars = Vec::new();
    
    // We declare these outside so they can be cleaned up
    let mut sidecar_id = String::new();
    let mut sidecar_shared = String::new();
    let mut sidecar_policy = String::new();

    if want_proxy {
        let uuid_str = uuid::Uuid::new_v4().to_string(); let uuid = &uuid_str[0..8];
        sidecar_id = format!("agent-sandbox-sidecar-{}", uuid);
        sidecar_shared = format!("/tmp/agent-sandbox-sidecar-{}", uuid);
        sidecar_policy = format!("/tmp/agent-sandbox-policy-{}", uuid);
        
        _cleanup_guard.sidecar_id = sidecar_id.clone();
        _cleanup_guard.sidecar_shared = sidecar_shared.clone();
        _cleanup_guard.sidecar_policy = sidecar_policy.clone();

        fs::create_dir_all(&sidecar_shared).unwrap();
        fs::create_dir_all(&sidecar_policy).unwrap();
        
        let mut net_cmd = ProcessCommand::new("podman");
        net_cmd.args(["network", "create", "--internal", "--disable-dns", &sidecar_id]);
        if !net_cmd.output().map(|o| o.status.success()).unwrap_or(false) {
            eprintln!("agent-sandbox: could not create the sidecar network {}", sidecar_id);
            std::process::exit(1);
        }

        let mut sidecar_subnet = String::new();
        let mut inspect_cmd = ProcessCommand::new("podman");
        inspect_cmd.args(["network", "inspect", &sidecar_id, "--format", "{{(index .Subnets 0).Subnet}}"]);
        if let Ok(out) = inspect_cmd.output() {
            if out.status.success() {
                sidecar_subnet = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        if sidecar_subnet.is_empty() {
            eprintln!("agent-sandbox: could not determine the subnet of {}", sidecar_id);
            std::process::exit(1);
        }

        let agents_md_path = Path::new(&pwd).join("AGENTS.md");
        let mut formatted_policy = String::new();
        if agents_md_path.exists() {
            if let Ok(text) = fs::read_to_string(&agents_md_path) {
                match parse_proxy(&text) {
                    Ok(policy) => {
                        formatted_policy = format_proxy_policy(&policy, &agents_md_path.to_string_lossy());
                    }
                    Err(_) => {
                        eprintln!("agent-sandbox: refusing to launch on an invalid [proxy] block (use --no-proxy to skip).");
                        std::process::exit(1);
                    }
                }
            }
        }
        
        let baseline_deny_ips = [
            "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "fc00::/7", "fe80::/10"
        ];
        
        let mut policy_file_content = formatted_policy;
        let mut baseline_content = String::new();
        for cidr in &baseline_deny_ips {
            let line = format!("deny_ips {}\n", cidr);
            policy_file_content.push_str(&line);
            baseline_content.push_str(&line);
        }
        
        fs::write(format!("{}/policy", sidecar_policy), &policy_file_content).unwrap();
        fs::write(format!("{}/policy.baseline", sidecar_policy), &baseline_content).unwrap();
        fs::copy(format!("{}/policy", sidecar_policy), format!("{}/policy.base", sidecar_policy)).unwrap();
        
        let mut proxy_cmd = ProcessCommand::new("podman");
        proxy_cmd.args(["run", "-d", "--name", &sidecar_id])
                 .args(["--network", "bridge", "--network", &sidecar_id])
                 .args(["-v", &format!("{}:/sidecar_shared:rw", sidecar_shared)])
                 .args(["-v", &format!("{}:/sidecar_policy:ro", sidecar_policy)])
                 .args(["-e", "AGENT_SANDBOX_SKIP_NIX_INIT=1"])
                 .args(["-e", &format!("SIDECAR_SUBNET={}", sidecar_subnet)])
                 .args(["--label", "agent-sandbox.role=proxy"])
                 .args(["--label", &format!("agent-sandbox.target={}", container_name)])
                 .args(["--label", &format!("agent-sandbox.workspace={}", pwd)])
                 .arg(&env::var("AGENT_SANDBOX_IMAGE").unwrap_or_default())
                 .arg("agent-sandbox-sidecar");
                 
        proxy_cmd.stdout(std::process::Stdio::null());
                 
        if !proxy_cmd.status().map(|s| s.success()).unwrap_or(false) {
            eprintln!("agent-sandbox: could not start the proxy sidecar");
            std::process::exit(1);
        }
        
        let mut sidecar_ready = false;
        let ready_path = format!("{}/ready", sidecar_shared);
        for _ in 0..350 {
            if Path::new(&ready_path).exists() {
                sidecar_ready = true;
                break;
            }
            let mut check_cmd = ProcessCommand::new("podman");
            check_cmd.args(["container", "inspect", "--format", "{{.State.Running}}", &sidecar_id]);
            if let Ok(out) = check_cmd.output() {
                if !String::from_utf8_lossy(&out.stdout).trim().eq("true") {
                    eprintln!("agent-sandbox: the proxy sidecar exited before signalling readiness:");
                    let mut logs_cmd = ProcessCommand::new("podman");
                    logs_cmd.args(["logs", &sidecar_id]);
                    if let Ok(logs_out) = logs_cmd.output() {
                        let logs = String::from_utf8_lossy(&logs_out.stderr);
                        for line in logs.lines() {
                            eprintln!("               {}", line);
                        }
                    }
                    std::process::exit(1);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        if !sidecar_ready {
            eprintln!("agent-sandbox: warning: proxy did not signal readiness in 35s");
            eprintln!("               (continuing; check: podman logs {})", sidecar_id);
        }
        
        let degraded_path = format!("{}/egress-degraded", sidecar_shared);
        if Path::new(&degraded_path).exists() {
            eprintln!("agent-sandbox: warning: the proxy could not resolve names at startup");
            if let Ok(msg) = fs::read_to_string(&degraded_path) {
                for line in msg.lines() {
                    eprintln!("               {}", line);
                }
            }
            eprintln!("               (continuing; requests may fail. Full log: agent-sandbox-ctl logs)");
        }
        
        sidecar_network_arg = Some(sidecar_id.clone());
        
        let mut sidecar_ip = String::new();
        for _ in 0..20 {
            let mut ip_cmd = ProcessCommand::new("podman");
            ip_cmd.args(["container", "inspect", "--format", &format!("{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}", sidecar_id), &sidecar_id]);
            if let Ok(out) = ip_cmd.output() {
                if out.status.success() {
                    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !ip.is_empty() {
                        sidecar_ip = ip;
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        if sidecar_ip.is_empty() {
            eprintln!("agent-sandbox: the proxy sidecar has no address on {}", sidecar_id);
            eprintln!("               (check: podman logs {})", sidecar_id);
            std::process::exit(1);
        }
        
        proxy_env_vars.push(format!("HTTP_PROXY=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("HTTPS_PROXY=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("http_proxy=http://{}:8888", sidecar_ip));
        proxy_env_vars.push(format!("https_proxy=http://{}:8888", sidecar_ip));
    }
    
    // We would execute podman here, let's just do it
    let image = env::var("AGENT_SANDBOX_IMAGE").unwrap_or_default();
    if !image.is_empty() {
        let status = ProcessCommand::new("podman")
            .args(["image", "exists", &image])
            .status();
        if status.is_err() || !status.unwrap().success() {
            eprintln!("agent-sandbox: image {} not found. Run 'agent-sandbox ctl load' first.", image);
            std::process::exit(1);
        }
    }
    
    let mut podman_cmd = ProcessCommand::new("podman");
    podman_cmd.arg("run").arg("--rm").arg("--interactive");
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        podman_cmd.arg("--tty");
    }
    podman_cmd.args(["--userns=keep-id", "--name", &container_name]);
    podman_cmd.args(["-e", "HOME=/home/user"]);
    
    let proxy_mode = if want_proxy { "proxy" } else { "off" };
    let sandbox_runtime = if want_krun { "krun" } else { "crun" };
    
    podman_cmd.args(["--label", "agent-sandbox.role=sandbox"]);
    podman_cmd.args(["--label", &format!("agent-sandbox.workspace={}", pwd)]);
    podman_cmd.args(["--label", &format!("agent-sandbox.proxy={}", proxy_mode)]);
    podman_cmd.args(["--label", &format!("agent-sandbox.runtime={}", sandbox_runtime)]);
    podman_cmd.args(["--label", &format!("agent-sandbox.command={}", cmd_args.join(" "))]);
    podman_cmd.args(["--workdir", &workspace_dir]);
    
    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.config,U=true"]);
    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.cache,U=true"]);
    podman_cmd.args(["--mount", "type=tmpfs,dst=/home/user/.local,U=true"]);
    
    if let Some(net_id) = sidecar_network_arg {
        podman_cmd.arg("--network");
        podman_cmd.arg(net_id);
    }
    for proxy_env in proxy_env_vars {
        podman_cmd.arg("-e");
        podman_cmd.arg(proxy_env);
    }

    
    for arg in env_args {
        podman_cmd.arg(arg);
    }
    
    for arg in mounts {
        podman_cmd.arg(arg);
    }
    
    if want_privileged {
        podman_cmd.arg("--privileged");
    }
    
    for arg in podman_args {
        podman_cmd.arg(arg);
    }
    
    podman_cmd.arg(env::var("AGENT_SANDBOX_IMAGE").unwrap_or_default());
    for arg in cmd_args {
        podman_cmd.arg(arg);
    }
    
    let status = podman_cmd.status();
    match status {
        Ok(st) => std::process::exit(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to run podman: {}", e);
            std::process::exit(1);
        }
    }
}
