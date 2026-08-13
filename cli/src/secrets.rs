#![forbid(unsafe_code)]
use std::path::Path;
use std::process::Command;
use thiserror::Error;
use crate::agents::parse_host_port;

#[derive(Debug, Clone)]
pub struct RequestedBinding {
    pub domain: String,
    pub secret: String,
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
    pub secret: String,
    pub header: String,
    pub prefix: Option<String>,
}

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

pub fn get_requested_bindings(workspace: &Path) -> Vec<RequestedBinding> {
    let mut requested_bindings = Vec::new();
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
                                        let (domain, _) = parse_host_port(host);
                                        requested_bindings.push(RequestedBinding {
                                            domain: domain.to_lowercase(),
                                            secret: secret.to_string(),
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
    requested_bindings
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

pub fn resolve_secrets_logic(policy: &Path, config: &Path, file: &Path, workspace: &Path) -> anyhow::Result<()> {
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
        return Ok(());
    }

    let requested_bindings = get_requested_bindings(workspace);

    let (mut host_config, _toml_val) = match std::fs::read_to_string(config) {
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

    for req in requested_bindings {
        let req_domain = req.domain;
        let req_secret = req.secret;

        let mut authorized = false;
        let mut matched_host_binding = None;

        for hb in &host_config.bindings {
            let (hb_domain, _hb_port) = parse_host_port(&hb.host);
            let hb_domain = hb_domain.to_lowercase();
            let hb_secret = &hb.secret;

            if domain_match(&req_domain, &hb_domain) && hb_secret == &req_secret {
                authorized = true;
                matched_host_binding = Some(hb.clone());
                break;
            }
        }

        if !authorized {
            let mut err_msg = String::new();
            err_msg.push_str(&format!("agent-sandbox: AGENTS.md requests secret '{}' for host '{}',\n", req_secret, req_domain));
            err_msg.push_str(&format!("               but this secret binding is not authorized in {}.\n\n", config.display()));
            err_msg.push_str(&format!("               To authorize this secret binding, add the following block to {}:\n\n", config.display()));
            err_msg.push_str("               [[network.rules]]\n");
            err_msg.push_str(&format!("               host = \"{}\"\n", req_domain)); // Simplified host suggestion
            err_msg.push_str("               method = \"GET\"\n"); // Provide defaults as per plan error 7
            err_msg.push_str("               path = \"/\"\n");
            err_msg.push_str(&format!("               secret = \"{}\"\n", req_secret));
            err_msg.push_str("               header = \"Authorization\"\n");
            err_msg.push_str("               prefix = \"Bearer \"\n\n");
            err_msg.push_str("               Or remove 'secret' from the [[network.rules]] in AGENTS.md if untrusted.\n");
            anyhow::bail!("{}", err_msg);
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

    if filtered_bindings.is_empty() {
        return Ok(());
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
            println!("{}\t{}\t{}{}", domain, header, prefix, val_str);
        } else {
            anyhow::bail!("agent-sandbox: secretspec output missing required secret '{}'\n", secret_name);
        }
    }

    Ok(())
}
