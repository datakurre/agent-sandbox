use super::resolve::*;
use anyhow::Result;
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "agent-sandbox-attach",
    about = "Executes an interactive command inside a running sandbox.\nIf no command is provided, starts an interactive bash shell."
)]
pub struct AttachArgs {
    #[arg(
        help = "The session word or full container name of the sandbox.\nIf omitted, acts on the current workspace's sandbox."
    )]
    pub word: Option<String>,

    #[arg(last = true, help = "The command to execute (default: bash)")]
    pub cmd: Vec<String>,
}

pub fn run(args: AttachArgs) -> Result<()> {
    let sandbox = resolve_sandbox(args.word.as_deref(), true)?;

    refuse_if_krun(
        &sandbox,
        "attach",
        &[
            "crun's libkrun handler implements no exec, so there is no way into the guest.",
            "Either launch a second sandbox on the same workspace, or run the shell as",
            "the sandbox's own command:  agent-sandbox --krun -- bash",
        ],
    )?;

    let interactive = args.cmd.is_empty();
    let mut cmd = args.cmd;
    if cmd.is_empty() {
        cmd.push("bash".to_string());
    }

    let mut podman = Command::new("podman");
    podman.arg("exec");
    if interactive {
        podman.arg("-it");
    } else {
        podman.arg("-i");
    }

    for var in runtime_env(&sandbox) {
        podman.arg("--env").arg(var);
    }

    podman.arg(&sandbox).args(&cmd);

    let err = podman.exec();
    Err(anyhow::anyhow!("exec failed: {}", err))
}

/// The environment the entrypoint built after `podman run` handed it the
/// container's own.
///
/// `podman exec` starts from the container's configured environment, which is
/// what the launcher passed to `podman run` -- so everything the entrypoint
/// derived at startup (the merged CA bundle, the SSH relay wiring, the
/// flattened host git config) was missing from an attached shell, and
/// `git clone git@github.com:...` failed there while succeeding in the session
/// the launcher started.  The entrypoint writes those variables to
/// `ENV_FILE`; this reads them back.
///
/// Best-effort by design: a sandbox from an older image has no such file, and
/// attaching to it must still work, just with the barer environment it had
/// before.
fn runtime_env(sandbox: &str) -> Vec<String> {
    const ENV_FILE: &str = "/home/user/.config/agent-sandbox/env";

    let Ok(out) = Command::new("podman")
        .args(["exec", sandbox, "cat", ENV_FILE])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(attached_env_line)
        .collect()
}

fn attached_env_line(line: &str) -> Option<String> {
    if let Some(encoded) = line.strip_prefix("AGENT_SANDBOX_NIX_CONFIG_JSON=") {
        return serde_json::from_str::<String>(encoded)
            .ok()
            .map(|value| format!("NIX_CONFIG={}", value));
    }
    // NAME=VALUE with a non-empty name; anything else would be passed to podman
    // as a request to *forward* a host variable of that name.
    line.split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .map(|_| line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_nix_config_decodes_multiline_json_record() {
        assert_eq!(
            attached_env_line("AGENT_SANDBOX_NIX_CONFIG_JSON=\"one\\ntwo\\n\""),
            Some("NIX_CONFIG=one\ntwo\n".to_string())
        );
    }

    #[test]
    fn attached_environment_keeps_plain_records_and_rejects_malformed_lines() {
        assert_eq!(
            attached_env_line("PATH=/bin:/usr/bin"),
            Some("PATH=/bin:/usr/bin".to_string())
        );
        assert_eq!(attached_env_line("not-an-assignment"), None);
        assert_eq!(
            attached_env_line("AGENT_SANDBOX_NIX_CONFIG_JSON=not-json"),
            None
        );
    }
}
