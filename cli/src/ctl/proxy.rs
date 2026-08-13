use anyhow::Result;
use clap::Parser;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-proxy",
    about = "Manage proxy rules (delegates to lib/agent-sandbox-firewall.sh)"
)]
pub struct ProxyArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

pub fn run(args: ProxyArgs) -> Result<()> {
    let script = "agent-sandbox-firewall";
    let err = Command::new(script).args(&args.args).exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}
