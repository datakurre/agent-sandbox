#![forbid(unsafe_code)]
#![allow(unused)]

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use clap::{Parser, Subcommand};
use agent_sandbox_cli::ctl;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufRead, BufReader, IsTerminal};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox",
    about = "Agent sandbox control CLI",
    version = "0.1.0",
    disable_help_subcommand = true
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

fn main() -> Result<()> {
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
            parse_args.extend(args.iter().skip(1).cloned());
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
            "-h" | "--help" => {
                println!("agent-sandbox [FLAGS] [AGENT] [-- COMMAND...]");
                std::process::exit(0);
            }
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
    
    mounts = enforce(mounts);
    
    if want_proxy {
        let uuid_str = uuid::Uuid::new_v4().to_string(); let uuid = &uuid_str[0..8];
        let sidecar_id = format!("agent-sandbox-sidecar-{}", uuid);
        let sidecar_shared = format!("/tmp/agent-sandbox-sidecar-{}", uuid);
        let sidecar_policy = format!("/tmp/agent-sandbox-policy-{}", uuid);
        
        fs::create_dir_all(&sidecar_shared).unwrap();
        fs::create_dir_all(&sidecar_policy).unwrap();
        
        let _ = ProcessCommand::new("podman")
            .args(["network", "create", "--internal", "--disable-dns", &sidecar_id])
            .output();
            
        fs::write(format!("{}/policy", sidecar_policy), "default deny\n").unwrap();
        
        let mut proxy_cmd = ProcessCommand::new("podman");
        proxy_cmd.args(["run", "-d", "--name", &sidecar_id])
                 .args(["--network", "bridge", "--network", &sidecar_id])
                 .args(["-v", &format!("{}:/sidecar_shared:rw", sidecar_shared)])
                 .args(["-v", &format!("{}:/sidecar_policy:ro", sidecar_policy)])
                 .arg(&env::var("AGENT_SANDBOX_IMAGE").unwrap_or_default())
                 .arg("agent-sandbox-sidecar");
                 
        if !proxy_cmd.status().map(|s| s.success()).unwrap_or(false) {
            eprintln!("agent-sandbox: could not start the proxy sidecar");
            std::process::exit(1);
        }
    }
    
    // We would execute podman here, let's just do it
    let mut podman_cmd = ProcessCommand::new("podman");
    podman_cmd.arg("run").arg("--rm").arg("--interactive");
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        podman_cmd.arg("--tty");
    }
    podman_cmd.args(["--userns=keep-id", "--name", &container_name]);
    podman_cmd.args(["-e", "HOME=/home/user"]);
    
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
