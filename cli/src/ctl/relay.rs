use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-relay",
    about = "Show SSH/GPG relay policy and logs (delegates to lib/agent-sandbox-relay-ctl.sh)"
)]
pub struct RelayArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn run(args: RelayArgs) -> Result<()> {
    let script = "agent-sandbox-relay-ctl";
    let err = Command::new(script).args(&args.args).exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}
