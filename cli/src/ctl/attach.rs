use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-attach",
    about = "Executes an interactive command inside a running sandbox.\nIf no command is provided, starts an interactive bash shell."
)]
pub struct AttachArgs {
    #[arg(help = "The session word or full container name of the sandbox.\nIf omitted, acts on the current workspace's sandbox.")]
    pub word: Option<String>,
    
    #[arg(last = true, help = "The command to execute (default: bash)")]
    pub cmd: Vec<String>,
}

pub fn run(args: AttachArgs) -> Result<()> {
    let sandbox = resolve_sandbox(args.word.as_deref(), true)?;
    
    refuse_if_krun(&sandbox, "attach", &[
        "crun's libkrun handler implements no exec, so there is no way into the guest.",
        "Either launch a second sandbox on the same workspace, or run the shell as",
        "the sandbox's own command:  agent-sandbox --krun -- bash"
    ])?;
    
    let mut cmd = args.cmd;
    if cmd.is_empty() {
        cmd.push("bash".to_string());
    }
    
    let mut podman = Command::new("podman");
    podman.arg("exec").arg("-it").arg(&sandbox).args(&cmd);
    
    let err = podman.exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}
