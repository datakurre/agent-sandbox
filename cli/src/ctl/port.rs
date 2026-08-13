use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-port",
    about = "Publish container ports to the host (delegates to lib/agent-sandbox-port.sh)"
)]
pub struct PortArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn run(args: PortArgs) -> Result<()> {
    let script = "agent-sandbox-port";
    let err = Command::new(script).args(&args.args).exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}
