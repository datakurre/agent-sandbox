use std::process::Command;
use anyhow::{anyhow, Result};
use std::env;

pub fn podman_ps_names(all: bool, filter: &str) -> Result<Vec<String>> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps");
    if all {
        cmd.arg("-a");
    }
    cmd.arg("--filter").arg(filter);
    cmd.arg("--format").arg("{{.Names}}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(anyhow!("podman ps failed"));
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

pub fn sandbox_containers() -> Result<Vec<String>> {
    podman_ps_names(false, "label=agent-sandbox.role=sandbox")
}

pub fn sandbox_containers_all() -> Result<Vec<String>> {
    podman_ps_names(true, "label=agent-sandbox.role=sandbox")
}

pub fn sandbox_workspace(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.workspace")
}

pub fn sandbox_running(name: &str) -> Result<bool> {
    let names = sandbox_containers()?;
    Ok(names.iter().any(|n| n == name))
}

pub fn sandbox_word(name: &str) -> String {
    name.rsplit('-').next().unwrap_or(name).to_string()
}

pub fn sandbox_proxy_mode(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.proxy")
}

pub fn sandbox_runtime(name: &str) -> Result<String> {
    podman_inspect_label(name, "agent-sandbox.runtime")
}

pub fn podman_inspect_label(name: &str, label: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("inspect")
       .arg("--format")
       .arg(format!("{{{{index .Config.Labels \"{}\"}}}}", label))
       .arg(name);
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.trim().to_string())
}

pub fn refuse_if_krun(sandbox: &str, verb: &str, msgs: &[&str]) -> Result<()> {
    if sandbox_runtime(sandbox)? == "krun" {
        eprintln!("agent-sandbox ctl: '{}' is a --krun microVM; {} is not available.", sandbox, verb);
        for m in msgs {
            eprintln!("               {}", m);
        }
        std::process::exit(1);
    }
    Ok(())
}

pub fn sidecar_for_sandbox(sandbox: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("ps")
       .arg("--filter").arg("label=agent-sandbox.role=proxy")
       .arg("--filter").arg(format!("label=agent-sandbox.target={}", sandbox))
       .arg("--format").arg("{{.Names}}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().next().unwrap_or("").to_string())
}

pub fn sidecar_mount(sidecar: &str, dest: &str) -> Result<String> {
    let mut cmd = Command::new("podman");
    cmd.arg("inspect")
       .arg("--format")
       .arg(format!("{{{{range .Mounts}}}}{{{{if eq .Destination \"{}\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}", dest))
       .arg(sidecar);
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.trim().to_string())
}

pub fn require_sidecar(sandbox: &str) -> Result<String> {
    let sidecar = sidecar_for_sandbox(sandbox)?;
    if sidecar.is_empty() {
        eprintln!("agent-sandbox ctl: '{}' is running without a proxy.", sandbox);
        eprintln!("               Relaunch it with:  agent-sandbox --proxy");
        std::process::exit(1);
    }
    Ok(sidecar)
}

pub fn resolve_sandbox(explicit: Option<&str>, want_running: bool) -> Result<String> {
    if let Some(explicit) = explicit {
        let all_names = sandbox_containers_all()?;
        let mut valid_matches = Vec::new();
        for name in &all_names {
            if name == explicit || name.ends_with(&format!("-{}", explicit)) {
                valid_matches.push(name.clone());
            }
        }
        if valid_matches.len() == 1 {
            if want_running && !sandbox_running(&valid_matches[0])? {
                if explicit == valid_matches[0] {
                    eprintln!("agent-sandbox ctl: '{}' is not running", explicit);
                } else {
                    eprintln!("agent-sandbox ctl: '{}' is not running", valid_matches[0]);
                }
                std::process::exit(1);
            }
            return Ok(valid_matches[0].clone());
        } else if valid_matches.len() > 1 {
            eprintln!("agent-sandbox ctl: '{}' is ambiguous, matches multiple sandboxes:", explicit);
            for m in &valid_matches {
                eprintln!("  {}\t{}", sandbox_word(m), sandbox_workspace(m).unwrap_or_default());
                eprintln!("    full name: {}", m);
            }
            std::process::exit(1);
        }
        eprintln!("agent-sandbox ctl: no container named '{}'", explicit);
        std::process::exit(1);
    }

    let names = if want_running { sandbox_containers()? } else { sandbox_containers_all()? };
    if names.is_empty() {
        if want_running {
            eprintln!("agent-sandbox ctl: no running sandboxes.");
        } else {
            eprintln!("agent-sandbox ctl: no sandboxes found.");
        }
        std::process::exit(1);
    }
    if names.len() == 1 {
        return Ok(names[0].clone());
    }

    let pwd = env::current_dir()?.to_string_lossy().to_string();
    let mut matches = Vec::new();
    for name in &names {
        if sandbox_workspace(name).unwrap_or_default() == pwd {
            matches.push(name.clone());
        }
    }
    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    eprintln!("agent-sandbox ctl: several sandboxes are running; pass --sandbox NAME:");
    for name in &names {
        eprintln!("  {}\t{}", name, sandbox_workspace(name).unwrap_or_default());
    }
    std::process::exit(1);
}
