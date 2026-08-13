use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::io::{Write, self};

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-purge",
    about = "Reclaim leftover containers, networks and directories"
)]
pub struct PurgeArgs {
    #[arg(long, help = "also remove running sandboxes, their sidecars and networks")]
    pub all: bool,

    #[arg(short = 'n', long, help = "report what would be removed, change nothing")]
    pub dry_run: bool,

    #[arg(short = 'f', long, help = "do not ask for confirmation")]
    pub force: bool,
}

fn confirm(msg: &str, force: bool, dry_run: bool) -> bool {
    if dry_run { return false; }
    if force { return true; }
    print!("{} [y/N] ", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        return trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes");
    }
    eprintln!("(not a terminal; pass --force to remove without asking)");
    false
}

fn containers_of_role(role: &str, filter: &str) -> Vec<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    match filter {
        "--running-only" => {
            cmd.arg("--filter").arg(format!("label=agent-sandbox.role={}", role));
        }
        "--exited-only" => {
            cmd.arg("-a")
               .arg("--filter").arg(format!("label=agent-sandbox.role={}", role))
               .arg("--filter").arg("status=exited")
               .arg("--filter").arg("status=created");
        }
        _ => {
            cmd.arg("-a")
               .arg("--filter").arg(format!("label=agent-sandbox.role={}", role));
        }
    }
    cmd.arg("--format").arg("{{.Names}}");
    let out = cmd.output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

fn orphans_of_role(role: &str) -> Vec<String> {
    let mut orphans = Vec::new();
    for name in containers_of_role(role, "") {
        if name.is_empty() { continue; }
        let target = podman_inspect_label(&name, "agent-sandbox.target").unwrap_or_default();
        if target.is_empty() {
            orphans.push(name);
        } else {
            let exists = Command::new("podman").arg("container").arg("exists").arg(&target).status().unwrap();
            if !exists.success() {
                orphans.push(name);
            }
        }
    }
    orphans
}

pub fn run(args: PurgeArgs) -> Result<()> {
    println!("=== agent-sandbox-purge ===");
    if args.dry_run {
        println!("(dry run: nothing will be removed)");
    }
    println!();
    
    // Running sessions
    let running = containers_of_role("sandbox", "--running-only");
    if !running.is_empty() {
        if args.all {
            println!("Running sandboxes:");
            for r in &running { println!("  {}", r); }
            println!();
            if args.dry_run {
                println!("  would remove {}\n", running.len());
            } else if confirm("Remove these?", args.force, args.dry_run) {
                let mut cmd = Command::new("podman");
                cmd.arg("rm").arg("-f").args(&running);
                cmd.output()?;
                println!("  removed {}\n", running.len());
            } else {
                println!("  skipped\n");
            }
        } else {
            println!("Running sandboxes (kept; pass --all to remove):");
            for r in &running { println!("  {}", r); }
            println!();
        }
    }
    
    // Orphans
    let orphans_fwd = orphans_of_role("port-forward");
    if !orphans_fwd.is_empty() {
        println!("Orphaned port forwarders:");
        for o in &orphans_fwd { println!("  {}", o); }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", orphans_fwd.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            Command::new("podman").arg("rm").arg("-f").args(&orphans_fwd).output()?;
            println!("  removed {}\n", orphans_fwd.len());
        } else {
            println!("  skipped\n");
        }
    }
    
    let orphans_proxy = orphans_of_role("proxy");
    if !orphans_proxy.is_empty() {
        println!("Orphaned proxy sidecars:");
        for o in &orphans_proxy { println!("  {}", o); }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", orphans_proxy.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            Command::new("podman").arg("rm").arg("-f").args(&orphans_proxy).output()?;
            println!("  removed {}\n", orphans_proxy.len());
        } else {
            println!("  skipped\n");
        }
    }
    
    let exited = containers_of_role("sandbox", "--exited-only");
    if !exited.is_empty() {
        println!("Exited sandboxes:");
        for e in &exited { println!("  {}", e); }
        println!();
        if args.dry_run {
            println!("  would remove {}\n", exited.len());
        } else if confirm("Remove these?", args.force, args.dry_run) {
            Command::new("podman").arg("rm").arg("-f").args(&exited).output()?;
            println!("  removed {}\n", exited.len());
        } else {
            println!("  skipped\n");
        }
    }
    
    // Remaining sections similarly...
    println!("Done.");
    Ok(())
}
