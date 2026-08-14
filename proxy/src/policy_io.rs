use crate::policy;
use std::fs;

/// Reads the raw `KEY VALUE` lines of a policy file, or an empty list if it
/// doesn't exist yet (e.g. a sandbox launched without any `[network]` rules).
pub fn load_policy_lines(policy_dir: &str) -> Vec<String> {
    let policy_path = format!("{}/policy", policy_dir);
    if let Ok(content) = fs::read_to_string(&policy_path) {
        content.lines().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    }
}

/// Validates `entries` as a policy file, then installs it atomically (write a
/// temp file, then rename over the live one) so the proxy's file watcher
/// never observes a half-written policy.
pub fn install_policy(policy_dir: &str, entries: &[String]) -> Result<(), String> {
    let policy_path = format!("{}/policy", policy_dir);
    let new_path = format!("{}/.policy.new", policy_dir);

    let content = entries.join("\n") + "\n";
    policy::parse_policy(&content)?;

    if let Err(e) = fs::write(&new_path, &content) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    if let Err(e) = fs::rename(&new_path, &policy_path) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    Ok(())
}
