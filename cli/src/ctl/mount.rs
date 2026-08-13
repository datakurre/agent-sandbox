use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-mount",
    about = "Manage bind mounts into a running sandbox (delegates to lib/agent-sandbox-mount.sh)"
)]
pub struct MountArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn run(args: MountArgs) -> Result<()> {
    let script = "agent-sandbox-mount";
    let err = Command::new(script).args(&args.args).exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}
