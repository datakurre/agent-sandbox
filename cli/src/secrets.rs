#![forbid(unsafe_code)]
use std::path::Path;
use std::process::Command;
use thiserror::Error;
use crate::agents::parse_host_port;

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub host: String,
    pub method: String,
    pub path: String,
    pub secret: String,
    pub header: String,
    pub prefix: String,
}

impl SecretRule {
    pub fn matches_host_binding(&self, hb: &HostBinding) -> bool {
        let (self_domain, self_port) = parse_host_port(&self.host);
        let (hb_domain, hb_port) = parse_host_port(&hb.host);

        self_domain.to_lowercase() == hb_domain.to_lowercase()
            && self_port == hb_port
            && self.method.to_uppercase() == hb.method.to_uppercase()
            && self.path == hb.path
            && self.secret == hb.secret
            && self.header.to_lowercase() == hb.header.to_lowercase()
            && self.prefix == hb.prefix.as_deref().unwrap_or("")
    }
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct HostConfig {
    pub profile: Option<String>,
    pub provider: Option<String>,
    pub scope: Option<String>,
    #[serde(default, alias = "secret", alias = "secrets", alias = "rules")]
    pub bindings: Vec<HostBinding>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct HostBinding {
    #[serde(alias = "domain")]
    pub host: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_path")]
    pub path: String,
    pub secret: String,
    #[serde(default = "default_header")]
    pub header: String,
    pub prefix: Option<String>,
}

fn default_method() -> String { "GET".to_string() }
fn default_path() -> String { "/".to_string() }
fn default_header() -> String { "Authorization".to_string() }

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("empty domain")]
    EmptyDomain,
    #[error("malformed dot placement")]
    MalformedDotPlacement,
    #[error("contains invalid characters")]
    ContainsInvalidCharacters,
    #[error("must begin and end with an alphanumeric character")]
    InvalidStartEnd,
    #[error("contains non-token characters")]
    ContainsNonTokenCharacters,
    #[error("reserved header name")]
    ReservedHeaderName,
}

pub fn iter_tagged_blocks(content: &str) -> Vec<String> {
    use pulldown_cmark::{Event, Parser, Tag, CodeBlockKind};
    let mut blocks = Vec::new();
    let parser = Parser::new(content);
    let mut current_block = String::new();
    let mut in_target_block = false;

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(info))) => {
                let info_str = info.into_string();
                if info_str.split_whitespace().any(|s| s == "agent-sandbox") {
                    in_target_block = true;
                    current_block.clear();
                }
            }
            Event::Text(text) => {
                if in_target_block {
                    current_block.push_str(&text);
                }
            }
            Event::End(Tag::CodeBlock(_)) => {
                if in_target_block {
                    blocks.push(current_block.clone());
                    in_target_block = false;
                }
            }
            _ => {}
        }
    }
    blocks
}

pub fn get_requested_rules(workspace: &Path) -> Vec<SecretRule> {
    let mut requested_rules = Vec::new();
    if let Ok(content) = std::fs::read_to_string(workspace) {
        let blocks = iter_tagged_blocks(&content);
        for block in blocks {
            if let Ok(block_data) = block.parse::<toml::Value>() {
                if let Some(network) = block_data.get("network").and_then(|v| v.as_table()) {
                    if let Some(rules) = network.get("rules").and_then(|v| v.as_array()) {
                        for rule in rules {
                            if let Some(rule_table) = rule.as_table() {
                                if let (Some(secret_val), Some(host_val)) = (rule_table.get("secret"), rule_table.get("host")) {
                                    if let (Some(secret), Some(host)) = (secret_val.as_str(), host_val.as_str()) {
                                        let method = rule_table.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
                                        let path = rule_table.get("path").and_then(|v| v.as_str()).unwrap_or("/");
                                        let header = rule_table.get("header").and_then(|v| v.as_str()).unwrap_or("Authorization");
                                        let prefix = rule_table.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
                                        requested_rules.push(SecretRule {
                                            host: host.to_string(),
                                            method: method.to_string(),
                                            path: path.to_string(),
                                            secret: secret.to_string(),
                                            header: header.to_string(),
                                            prefix: prefix.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    requested_rules
}

pub fn domain_match(domain: &str, pattern: &str) -> bool {
    if let Some(base) = pattern.strip_prefix("*.") {
        domain == base || domain.ends_with(&format!(".{}", base))
    } else {
        domain == pattern
    }
}

pub fn overlap_samples(pattern: &str) -> (String, String) {
    if let Some(base) = pattern.strip_prefix("*.") {
        (base.to_string(), format!("sample.{}", base))
    } else {
        (pattern.to_string(), pattern.to_string())
    }
}

pub fn patterns_overlap(a: &str, b: &str) -> bool {
    let (a0, a1) = overlap_samples(a);
    let (b0, b1) = overlap_samples(b);
    domain_match(&a0, b) || domain_match(&a1, b) || domain_match(&b0, a) || domain_match(&b1, a)
}

pub fn validate_domain(domain: &str) -> Result<(), ValidationError> {
    let bare = if let Some(base) = domain.strip_prefix("*.") { base } else { domain };
    if bare.is_empty() {
        return Err(ValidationError::EmptyDomain);
    }
    if bare.starts_with('.') || bare.ends_with('.') || bare.contains("..") {
        return Err(ValidationError::MalformedDotPlacement);
    }
    for c in bare.chars() {
        if !(c.is_alphanumeric() || c == '-' || c == '.' || c == '_') {
            return Err(ValidationError::ContainsInvalidCharacters);
        }
    }
    let chars: Vec<char> = bare.chars().collect();
    if !chars.first().unwrap().is_alphanumeric() || !chars.last().unwrap().is_alphanumeric() {
        return Err(ValidationError::InvalidStartEnd);
    }
    Ok(())
}

pub fn is_header_char(c: char) -> bool {
    c.is_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

pub fn validate_header(header: &str) -> Result<(), ValidationError> {
    if !header.chars().all(is_header_char) {
        return Err(ValidationError::ContainsNonTokenCharacters);
    }
    let lower = header.to_lowercase();
    if lower == "host" || lower == "connection" || lower == "content-length" || lower == "transfer-encoding" || lower.starts_with("proxy-") {
        return Err(ValidationError::ReservedHeaderName);
    }
    Ok(())
}

/// Resolve the bindings the policy's `secret_domains` authorize, returning one
/// `domain\theader\tvalue` line per binding.  The caller decides where those
/// go: the launcher writes them straight into the sidecar's `bindings` file
/// rather than through a pipe, so the values never reach a terminal.
pub fn resolve_secrets_logic(policy: &Path, config: &Path, file: &Path, workspace: &Path) -> anyhow::Result<Vec<String>> {
    let mut secret_domains = Vec::new();
    if let Ok(f) = std::fs::File::open(policy) {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(f);
        for line in reader.lines().flatten() {
            let line = line.trim();
            if let Some(domain) = line.strip_prefix("secret_domains ") {
                secret_domains.push(domain.trim().to_lowercase());
            }
        }
    }

    if secret_domains.is_empty() {
        return Ok(Vec::new());
    }

    let requested_rules = get_requested_rules(workspace);

    let (host_config, _toml_val) = match std::fs::read_to_string(config) {
        Ok(c) => {
            let val: toml::Value = match toml::from_str(&c) {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!("agent-sandbox: Secrets config at {} is malformed: {}", config.display(), e);
                }
            };
            if let Some(bindings) = val.get("bindings") {
                if !bindings.is_array() {
                    anyhow::bail!("agent-sandbox: 'bindings' must be a list in secrets config");
                }
            }
            let mut host_config: HostConfig = match toml::from_str(&c) {
                Ok(v) => v,
                Err(e) => {
                    anyhow::bail!("agent-sandbox: Secrets config at {} is malformed: {}", config.display(), e);
                }
            };
            
            // manually extract [[network.rules]] and add to bindings
            if let Some(network) = val.get("network").and_then(|v| v.as_table()) {
                if let Some(rules) = network.get("rules").and_then(|v| v.as_array()) {
                    for rule in rules {
                        if let Ok(hb) = rule.clone().try_into::<HostBinding>() {
                            host_config.bindings.push(hb);
                        }
                    }
                }
            }

            (host_config, val)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (HostConfig::default(), toml::Value::Table(Default::default()))
        }
        Err(e) => {
            anyhow::bail!("agent-sandbox: Secrets config at {} is malformed: {}", config.display(), e);
        }
    };

    let mut filtered_bindings = Vec::new();
    let mut seen_domains: Vec<String> = Vec::new();

    let mut missing_rules = Vec::new();

    for req in requested_rules {
        let mut authorized = false;
        let mut matched_host_binding = None;

        for hb in &host_config.bindings {
            if req.matches_host_binding(hb) {
                authorized = true;
                matched_host_binding = Some(hb.clone());
                break;
            }
        }

        if !authorized {
            missing_rules.push(req);
            continue;
        }

        let hb = matched_host_binding.unwrap();
        let (hb_domain, _hb_port) = parse_host_port(&hb.host);
        let hb_domain = hb_domain.to_lowercase();

        if let Err(e) = validate_domain(&hb_domain) {
            anyhow::bail!("agent-sandbox: Invalid domain '{}' in binding: {}", hb_domain, e);
        }

        if let Err(e) = validate_header(&hb.header) {
            anyhow::bail!("agent-sandbox: Invalid header '{}' in binding: {}", hb.header, e);
        }

        for seen in &seen_domains {
            if patterns_overlap(&hb_domain, seen) {
                anyhow::bail!("agent-sandbox: domain '{}' overlaps with existing binding domain '{}'", hb_domain, seen);
            }
        }

        if secret_domains.iter().any(|pd| patterns_overlap(&hb_domain, pd)) {
            filtered_bindings.push(hb);
            seen_domains.push(hb_domain.clone());
        }
    }

    if !missing_rules.is_empty() {
        let mut err_msg = String::new();
        for req in missing_rules {
            err_msg.push_str(&format!("agent-sandbox: AGENTS.md requests secret '{}' for rule:\n", req.secret));
            err_msg.push_str(&format!("               host = \"{}\", method = \"{}\", path = \"{}\"\n", req.host, req.method, req.path));
            err_msg.push_str(&format!("               but this secret definition is not authorized in {}.\n\n", config.display()));
            err_msg.push_str(&format!("               To authorize this secret definition, add the following block to {}:\n\n", config.display()));
            err_msg.push_str("               [[network.rules]]\n");
            err_msg.push_str(&format!("               host = \"{}\"\n", req.host));
            err_msg.push_str(&format!("               method = \"{}\"\n", req.method));
            err_msg.push_str(&format!("               path = \"{}\"\n", req.path));
            err_msg.push_str(&format!("               secret = \"{}\"\n", req.secret));
            err_msg.push_str(&format!("               header = \"{}\"\n", req.header));
            err_msg.push_str(&format!("               prefix = \"{}\"\n\n", req.prefix));
            err_msg.push_str("               Or remove 'secret' from the [[network.rules]] in AGENTS.md if untrusted.\n\n");
        }
        anyhow::bail!("{}", err_msg.trim_end());
    }

    if filtered_bindings.is_empty() {
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("secretspec");
    cmd.args(["export", "--file"]);
    cmd.arg(file);
    cmd.args(["--format", "json", "--reason", "agent-sandbox secret injection"]);

    if let Some(profile) = &host_config.profile {
        cmd.args(["--profile", profile]);
    }
    if let Some(provider) = &host_config.provider {
        cmd.args(["--provider", provider]);
    }
    if let Some(scope) = &host_config.scope {
        cmd.args(["--scope", scope]);
    }

    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("agent-sandbox: secretspec executable not found\n");
        }
        Err(e) => {
            anyhow::bail!("agent-sandbox: secretspec export failed:\n{}\n", e);
        }
    };

    if !output.status.success() {
        anyhow::bail!("agent-sandbox: secretspec export failed:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let secrets_data: serde_json::Value = match serde_json::from_str(&stdout_str) {
        Ok(v) => v,
        Err(e) => {
            anyhow::bail!("agent-sandbox: secretspec output was not valid JSON: {}\n", e);
        }
    };

    let secrets_map = if let Some(map) = secrets_data.get("secrets").and_then(|s| s.as_object()) {
        map
    } else if let Some(map) = secrets_data.as_object() {
        map
    } else {
        anyhow::bail!("agent-sandbox: secretspec output was not a JSON object\n");
    };

    let mut lines = Vec::new();
    for b in filtered_bindings {
        let secret_name = &b.secret;
        let (domain, _port) = parse_host_port(&b.host);
        let domain = domain.to_lowercase();
        let header = &b.header;
        let prefix = b.prefix.unwrap_or_default();

        if let Some(secret_value) = secrets_map.get(secret_name) {
            let val_str = if let Some(s) = secret_value.as_str() {
                s.to_string()
            } else {
                secret_value.to_string()
            };
            lines.push(format!("{}\t{}\t{}{}", domain, header, prefix, val_str));
        } else {
            anyhow::bail!("agent-sandbox: secretspec output missing required secret '{}'\n", secret_name);
        }
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_secret_rule_matches() {
        let rule = SecretRule {
            host: "api.github.com:443".to_string(),
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            secret: "GITHUB_TOKEN".to_string(),
            header: "Authorization".to_string(),
            prefix: "Bearer ".to_string(),
        };

        // Exact match
        let mut hb = HostBinding {
            host: "api.github.com:443".to_string(),
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            secret: "GITHUB_TOKEN".to_string(),
            header: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        };
        assert!(rule.matches_host_binding(&hb));

        // Missing port in HostBinding -> mismatch
        hb.host = "api.github.com".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different method -> mismatch
        hb.host = "api.github.com:443".to_string();
        hb.method = "GET".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different path -> mismatch
        hb.method = "POST".to_string();
        hb.path = "/v1".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different secret -> mismatch
        hb.path = "/graphql".to_string();
        hb.secret = "OTHER_TOKEN".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different header -> mismatch
        hb.secret = "GITHUB_TOKEN".to_string();
        hb.header = "X-Api-Key".to_string();
        assert!(!rule.matches_host_binding(&hb));

        // Different prefix -> mismatch
        hb.header = "Authorization".to_string();
        hb.prefix = Some("Basic ".to_string());
        assert!(!rule.matches_host_binding(&hb));
    }

    #[test]
    fn test_get_requested_rules_parsing() {
        let content = r#"
```agent-sandbox
[network]
allow = ["github.com:443"]

[[network.rules]]
host = "api.github.com:443"
method = "POST"
path = "/graphql"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.rules]]
host = "registry.npmjs.org:443"
method = "GET"
path = "/*"
secret = "NPM_TOKEN"
```
"#;
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();

        let rules = get_requested_rules(tmp.path());
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].host, "api.github.com:443");
        assert_eq!(rules[0].method, "POST");
        assert_eq!(rules[0].path, "/graphql");
        assert_eq!(rules[0].secret, "GITHUB_TOKEN");
        assert_eq!(rules[0].header, "Authorization");
        assert_eq!(rules[0].prefix, "Bearer ");

        assert_eq!(rules[1].host, "registry.npmjs.org:443");
        assert_eq!(rules[1].method, "GET");
        assert_eq!(rules[1].path, "/*");
        assert_eq!(rules[1].secret, "NPM_TOKEN");
        assert_eq!(rules[1].header, "Authorization");
        assert_eq!(rules[1].prefix, "");
    }
}

