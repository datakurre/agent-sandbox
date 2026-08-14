use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::fs;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-relay",
    about = "Show the SSH/GPG relay policy of a running sandbox, and what it has been asked for"
)]
pub struct RelayArgs {
    #[arg(short, long, help = "keep streaming relay decisions until Ctrl-C")]
    pub follow: bool,

    #[arg(help = "Sandbox name (positional)")]
    pub word: Option<String>,

    #[arg(long, visible_aliases = ["sandbox"], help = "Container ID or name")]
    pub container: Option<String>,
}

/// The relay refuses every request while this list is empty, so it is the
/// first thing to print: an empty policy explains every denial below it.
fn allow_signing_rules(policy_dir: &str) -> Vec<String> {
    fs::read_to_string(format!("{}/policy", policy_dir))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.strip_prefix("allow_signing ")
                .map(|r| r.trim().to_string())
        })
        .filter(|r| !r.is_empty())
        .collect()
}

pub fn run(args: RelayArgs) -> Result<()> {
    let explicit = args.container.clone().or_else(|| args.word.clone());
    let sandbox = resolve_sandbox(explicit.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox)?;

    let policy_dir = sidecar_mount(&sidecar, "/sidecar_policy")?;
    if policy_dir.is_empty() {
        eprintln!(
            "agent-sandbox ctl relay: cannot find the policy mount for sandbox '{}'",
            sandbox
        );
        std::process::exit(1);
    }

    let rules = allow_signing_rules(&policy_dir);
    println!("{}", sandbox);
    if rules.is_empty() {
        println!("  allow_signing  (none) -- ssh and gpg through the relay are refused");
        println!(
            "                 Declare an SSH port in AGENTS.md, e.g. allow_hosts = [\"github.com:22\"]."
        );
    } else {
        for rule in &rules {
            println!("  allow_signing  {}", rule);
        }
    }

    let has_ssh = Command::new("podman")
        .args(["exec", &sidecar, "test", "-S", "/run/host-ssh-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let has_gpg = Command::new("podman")
        .args(["exec", &sidecar, "test", "-S", "/run/host-gpg-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    println!(
        "  ssh agent      {}",
        if has_ssh {
            "forwarded"
        } else {
            "not forwarded (relaunch with --ssh)"
        }
    );
    println!(
        "  gpg agent      {}",
        if has_gpg {
            "forwarded"
        } else {
            "not forwarded (relaunch with --gpg)"
        }
    );

    // Read through the sidecar, like `ctl net` and `ctl logs`: the shared
    // directory is deliberately not mounted into the sandbox, and the host
    // path is an implementation detail of the launcher.
    let log = "/sidecar_shared/relay.jsonl";
    println!("  requests");
    let mut podman = Command::new("podman");
    podman.args(["exec", &sidecar]);
    if args.follow {
        podman.args(["tail", "-n", "+1", "-F", "--", log]);
    } else {
        podman.args(["cat", log]);
    }
    let output = podman.output()?;
    if !output.status.success() {
        println!("    (none yet)");
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        println!("    (none yet)");
    } else {
        for line in text.lines() {
            println!("    {}", line);
        }
    }
    Ok(())
}
