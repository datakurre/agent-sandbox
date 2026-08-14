use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-tui",
    about = "Interactive dashboard: approve pending ask-mode requests, add rules for denied ones"
)]
pub struct TuiArgs {
    #[arg(help = "Sandbox name (positional)")]
    pub sandbox: Option<String>,
}

pub fn run(args: TuiArgs) -> Result<()> {
    let sandbox = resolve_sandbox(args.sandbox.as_deref(), true)?;
    let sidecar = require_sidecar(&sandbox)?;
    
    let policy_dir = sidecar_mount(&sidecar, "/sidecar_policy")?;
    let shared_dir = sidecar_mount(&sidecar, "/sidecar_shared")?;
    
    if policy_dir.is_empty() || shared_dir.is_empty() {
        eprintln!("agent-sandbox ctl tui: cannot find sidecar mounts for sandbox '{}'", sandbox);
        std::process::exit(1);
    }
    
    let err = Command::new("agent-sandbox-tui")
        .arg(&sandbox)
        .arg(&policy_dir)
        .arg(&shared_dir)
        .exec();
        
    Err(anyhow::anyhow!("exec failed: {}", err))
}
