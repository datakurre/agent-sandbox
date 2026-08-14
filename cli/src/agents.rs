#![forbid(unsafe_code)]

use agent_sandbox_proxy::policy::ProxyConfig;
use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag};
use std::collections::HashSet;
use std::net::{IpAddr, TcpListener, UdpSocket};
use thiserror::Error;
use toml::Value;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Message(String),
}

impl ConfigError {
    pub fn msg<T: std::fmt::Display>(m: T) -> Self {
        ConfigError::Message(m.to_string())
    }
}

pub const MAX_PORTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub name: String,
    pub bind: String,
    pub host: u16,
    pub container: u16,
    pub protocol: String,
}

impl Mapping {
    pub fn spec(&self) -> String {
        let bind = if self.bind.contains(':') {
            format!("[{}]", self.bind)
        } else {
            self.bind.clone()
        };
        format!("{}:{}:{}/{}", bind, self.host, self.container, self.protocol)
    }
}

pub fn iter_tagged_blocks(text: &str) -> Vec<String> {
    let parser = Parser::new(text);
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current_block = String::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref info))) => {
                let info_str = info.as_ref();
                if info_str.split_whitespace().any(|s| s == "agent-sandbox") {
                    in_block = true;
                    current_block.clear();
                }
            }
            Event::Text(ref text_ev) => {
                if in_block {
                    current_block.push_str(text_ev.as_ref());
                }
            }
            Event::End(Tag::CodeBlock(_)) => {
                if in_block {
                    blocks.push(current_block.clone());
                    in_block = false;
                }
            }
            _ => {}
        }
    }
    blocks
}

fn _port(name: &str, field: &str, value: &Value, allow_zero: bool) -> Result<u16, ConfigError> {
    let p = value.as_integer().ok_or_else(|| {
        ConfigError::msg(format!("ports.{}.{}: expected an integer", name, field))
    })?;
    let low = if allow_zero { 0 } else { 1 };
    if p < low || p > 65535 {
        return Err(ConfigError::msg(format!(
            "ports.{}.{}: {} is outside {}-65535",
            name, field, p, low
        )));
    }
    Ok(p as u16)
}

fn _bind(name: &str, value: &Value, allow_any_interface: bool) -> Result<String, ConfigError> {
    let s = value.as_str().ok_or_else(|| {
        ConfigError::msg(format!("ports.{}.bind: expected a string", name))
    })?;
    let literal = if s == "localhost" { "127.0.0.1" } else { s };
    let addr: IpAddr = literal.parse().map_err(|_| {
        ConfigError::msg(format!(
            "ports.{}.bind: {:?} is not an IP address literal",
            name, s
        ))
    })?;
    if !addr.is_loopback() && !allow_any_interface {
        return Err(ConfigError::msg(format!(
            "ports.{}.bind: {} is not a loopback address; pass --ports-any-interface to publish there",
            name, addr
        )));
    }
    Ok(addr.to_string())
}

fn _protocol(name: &str, value: &Value) -> Result<String, ConfigError> {
    let s = value.as_str().ok_or_else(|| {
        ConfigError::msg(format!("ports.{}.protocol: expected 'tcp' or 'udp'", name))
    })?;
    let lower = s.to_lowercase();
    if lower != "tcp" && lower != "udp" {
        return Err(ConfigError::msg(format!(
            "ports.{}.protocol: expected 'tcp' or 'udp', got {:?}",
            name, s
        )));
    }
    Ok(lower)
}

fn is_valid_name(n: &str) -> bool {
    if n.is_empty() || n.len() > 64 {
        return false;
    }
    let mut chars = n.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-' {
            return false;
        }
    }
    true
}

fn parse_entry(name: &str, value: &Value, allow_any_interface: bool) -> Result<Mapping, ConfigError> {
    if !is_valid_name(name) {
        return Err(ConfigError::msg(format!("ports.{:?}: name must match pattern", name)));
    }

    if let Some(table) = value.as_table() {
        let allowed_fields: HashSet<&str> = ["container", "host", "bind", "protocol"].iter().cloned().collect();
        let unknown: Vec<_> = table.keys().filter(|k| !allowed_fields.contains(k.as_str())).collect();
        if !unknown.is_empty() {
            return Err(ConfigError::msg(format!(
                "ports.{}: unknown field(s) {:?}",
                name, unknown
            )));
        }
        if !table.contains_key("container") {
            return Err(ConfigError::msg(format!("ports.{}: missing required field 'container'", name)));
        }
        let container = _port(name, "container", &table["container"], false)?;
        let host = if let Some(h) = table.get("host") {
            _port(name, "host", h, true)?
        } else {
            container
        };
        let bind = if let Some(b) = table.get("bind") {
            _bind(name, b, allow_any_interface)?
        } else {
            "127.0.0.1".to_string()
        };
        let protocol = if let Some(p) = table.get("protocol") {
            _protocol(name, p)?
        } else {
            "tcp".to_string()
        };
        Ok(Mapping {
            name: name.to_string(),
            bind,
            host,
            container,
            protocol,
        })
    } else {
        let container = _port(name, "container", value, false)?;
        Ok(Mapping {
            name: name.to_string(),
            bind: "127.0.0.1".to_string(),
            host: container,
            container,
            protocol: "tcp".to_string(),
        })
    }
}

pub fn parse_ports(text: &str, allow_any_interface: bool, max_ports: usize) -> Result<Vec<Mapping>, ConfigError> {
    let mut mappings = std::collections::HashMap::new();
    let blocks = iter_tagged_blocks(text);
    
    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;
        
        if let Some(ports) = block.get("ports") {
            let ports_table = ports.as_table().ok_or_else(|| {
                ConfigError::msg("[ports] must be a table")
            })?;
            
            for (name, value) in ports_table {
                if mappings.contains_key(name) {
                    return Err(ConfigError::msg(format!("ports.{}: declared more than once", name)));
                }
                let mapping = parse_entry(name, value, allow_any_interface)?;
                mappings.insert(name.clone(), mapping);
            }
        }
    }
    
    if mappings.len() > max_ports {
        return Err(ConfigError::msg(format!(
            "{} port mappings declared, limit is {}",
            mappings.len(),
            max_ports
        )));
    }
    
    Ok(mappings.into_values().collect())
}

pub fn allocate(mapping: Mapping) -> Result<Mapping, ConfigError> {
    if mapping.host != 0 {
        return Ok(mapping);
    }
    let bind_addr: IpAddr = mapping.bind.parse().map_err(|e| ConfigError::msg(format!("invalid bind: {}", e)))?;
    let host_port = if mapping.protocol == "udp" {
        let sock = UdpSocket::bind((bind_addr, 0)).map_err(|e| ConfigError::msg(e))?;
        sock.local_addr().map_err(|e| ConfigError::msg(e))?.port()
    } else {
        let listener = TcpListener::bind((bind_addr, 0)).map_err(|e| ConfigError::msg(e))?;
        listener.local_addr().map_err(|e| ConfigError::msg(e))?.port()
    };
    let mut m = mapping;
    m.host = host_port;
    Ok(m)
}

pub fn parse_mounts(text: &str) -> Result<Vec<String>, ConfigError> {
    let mut specs = Vec::new();
    let blocks = iter_tagged_blocks(text);
    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;
        if let Some(mounts) = block.get("mounts") {
            let mounts_table = mounts.as_table().ok_or_else(|| {
                ConfigError::msg("[mounts] must be a table")
            })?;
            for (src, value) in mounts_table {
                let (dest, opts) = if let Some(s) = value.as_str() {
                    (s.to_string(), String::new())
                } else if let Some(table) = value.as_table() {
                    let dest = table.get("destination")
                        .and_then(|d| d.as_str())
                        .ok_or_else(|| ConfigError::msg(format!("mounts.{}: missing required field 'destination' or not a string", src)))?
                        .to_string();
                    let mut opts = String::new();
                    if let Some(opts_val) = table.get("options") {
                        if let Some(s) = opts_val.as_str() {
                            opts = s.to_string();
                        } else if let Some(arr) = opts_val.as_array() {
                            let mut opt_strings = Vec::new();
                            for o in arr {
                                if let Some(s) = o.as_str() {
                                    opt_strings.push(s.to_string());
                                } else {
                                    return Err(ConfigError::msg(format!("mounts.{}.options: expected a string or list of strings", src)));
                                }
                            }
                            opts = opt_strings.join(",");
                        } else {
                            return Err(ConfigError::msg(format!("mounts.{}.options: expected a string or list of strings", src)));
                        }
                    }
                    let allowed: HashSet<&str> = ["destination", "options"].iter().cloned().collect();
                    let unknown: Vec<_> = table.keys().filter(|k| !allowed.contains(k.as_str())).collect();
                    if !unknown.is_empty() {
                        return Err(ConfigError::msg(format!("mounts.{}: unknown field(s) {:?}", src, unknown)));
                    }
                    (dest, opts)
                } else {
                    return Err(ConfigError::msg(format!("mounts.{}: expected a string or table", src)));
                };
                let mut spec = format!("{}:{}", src, dest);
                if !opts.is_empty() {
                    spec.push(':');
                    spec.push_str(&opts);
                }
                specs.push(spec);
            }
        }
    }
    Ok(specs)
}

fn is_valid_domain(mut d: &str) -> bool {
    if d.starts_with("*.") {
        d = &d[2..];
    }
    if d.is_empty() {
        return false;
    }
    let mut chars = d.chars().peekable();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut last = first;
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-' {
            return false;
        }
        last = c;
    }
    last.is_ascii_alphanumeric()
}

fn _proxy_domain(field: &str, value: &str) -> Result<(), ConfigError> {
    if !is_valid_domain(value) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} is not a valid domain name",
            field, value
        )));
    }
    Ok(())
}

pub(crate) fn is_ip_or_cidr(value: &str) -> bool {
    if let Some((ip_str, mask_str)) = value.split_once('/') {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if let Ok(mask) = mask_str.parse::<u8>() {
                return match ip {
                    IpAddr::V4(_) => mask <= 32,
                    IpAddr::V6(_) => mask <= 128,
                };
            }
        }
        false
    } else {
        value.parse::<IpAddr>().is_ok()
    }
}

fn _proxy_ip(field: &str, value: &str) -> Result<(), ConfigError> {
    if !is_ip_or_cidr(value) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} is not a valid IP address or network",
            field, value
        )));
    }
    Ok(())
}

fn _proxy_port(field: &str, value: &str) -> Result<(), ConfigError> {
    let parts: Vec<&str> = value.split('-').collect();
    let parse_err = || ConfigError::msg(format!("{}: {:?} is not a port or port range", field, value));
    let (start, end) = if parts.len() == 1 {
        let p: u32 = parts[0].parse().map_err(|_| parse_err())?;
        (p, p)
    } else if parts.len() == 2 {
        let p1: u32 = parts[0].parse().map_err(|_| parse_err())?;
        let p2: u32 = parts[1].parse().map_err(|_| parse_err())?;
        (p1, p2)
    } else {
        return Err(parse_err());
    };
    if start < 1 || start > 65535 || end < 1 || end > 65535 || start > end {
        return Err(ConfigError::msg(format!("{}: {:?} is out of range or start > end", field, value)));
    }
    Ok(())
}

fn _proxy_list<F>(field: &str, value: &Value, mut validate: F, prefix: &str) -> Result<Vec<String>, ConfigError>
where
    F: FnMut(&str, &str) -> Result<(), ConfigError>,
{
    let arr = value.as_array().ok_or_else(|| {
        ConfigError::msg(format!("{}{}", prefix, field))
    })?;
    let mut out = Vec::new();
    for item in arr {
        let s = item.as_str().ok_or_else(|| {
            ConfigError::msg(format!("{}{} elements must be strings", prefix, field))
        })?;
        validate(field, s)?;
        out.push(s.to_string());
    }
    Ok(out)
}

pub fn parse_host_port(s: &str) -> (String, Option<String>) {
    if let Some(pos) = s.rfind(':') {
        let left = &s[..pos];
        let right = &s[pos+1..];
        if right.chars().all(|c| c.is_ascii_digit()) || right == "*" || right.contains('-') {
            let host = if left.starts_with('[') && left.ends_with(']') {
                &left[1..left.len()-1]
            } else {
                left
            };
            return (host.to_string(), Some(right.to_string()));
        }
    }
    (s.to_string(), None)
}

#[derive(Default, Debug)]
pub struct ProxyPolicy {
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub secret_domains: Vec<String>,
    pub allow_signing: Vec<String>,
    pub allow_ips: Vec<String>,
    pub deny_ips: Vec<String>,
    pub allow_ports: Vec<String>,
    pub allow_l7: Vec<String>,
    pub default: Vec<String>,
}

pub fn parse_proxy(text: &str) -> Result<ProxyPolicy, ConfigError> {
    let mut policy = ProxyPolicy::default();
    policy.default = vec!["deny".to_string()];
    
    let blocks = iter_tagged_blocks(text);
    
    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;
        
        if let Some(table) = block.as_table() {
            let allowed_tables: HashSet<&str> = ["network", "ports", "mounts"].iter().cloned().collect();
            let unknown: Vec<_> = table.keys().filter(|k| !allowed_tables.contains(k.as_str())).collect();
            if !unknown.is_empty() {
                return Err(ConfigError::msg(format!("unknown top-level table(s): {:?}", unknown)));
            }
        }
        
        if let Some(network) = block.get("network") {
            let net_table = network.as_table().ok_or_else(|| ConfigError::msg("[network] must be a table"))?;
            
            let allowed_net: HashSet<&str> = ["allow", "rules"].iter().cloned().collect();
            let unknown: Vec<_> = net_table.keys().filter(|k| !allowed_net.contains(k.as_str())).collect();
            if let Some(first_unknown) = unknown.first() {
                return Err(ConfigError::msg(format!("[network]: unknown key '{}'. Valid keys under [network] are 'allow' and 'rules' ([[network.rules]]).", first_unknown)));
            }
            
            let mut allow_set = HashSet::new();
            let mut allow_has_wildcard = false;
            let mut rules_hosts_no_secret = HashSet::new();
            let mut rules_hosts_with_secret = HashSet::new();
            let mut has_non_secret_rule = false;
            
            if let Some(rules) = net_table.get("rules") {
                let rules_arr = rules.as_array().ok_or_else(|| ConfigError::msg("[network].rules must be an array of tables"))?;
                for (i, rule_val) in rules_arr.iter().enumerate() {
                    let rule = rule_val.as_table().ok_or_else(|| ConfigError::msg(format!("[[network.rules]][{}]: must be a table", i)))?;
                    
                    let allowed_rule_keys: HashSet<&str> = ["host", "method", "path", "secret", "header", "prefix"].iter().cloned().collect();
                    if let Some(unknown_key) = rule.keys().find(|k| !allowed_rule_keys.contains(k.as_str())) {
                        return Err(ConfigError::msg(format!("[[network.rules]][{}]: unknown field '{}'. Valid keys under [[network.rules]] are 'host', 'method', 'path', 'secret', 'header', and 'prefix'.", i, unknown_key)));
                    }
                    
                    let host_val = rule.get("host").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.rules]][{}]: missing required field 'host'. Example: host = \"registry.npmjs.org:443\".", i)))?;
                    let method = rule.get("method").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.rules]][{}]: missing required field 'method'. Specify an HTTP method (e.g. method = \"GET\", method = \"POST\", or method = \"*\").", i)))?;
                    let path = rule.get("path").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.rules]][{}]: missing required field 'path'. Example: path = \"/api/*\" or path = \"/\".", i)))?;
                    
                    if method != "*" && (!method.chars().all(|c| c.is_ascii_uppercase()) || method.is_empty()) {
                        return Err(ConfigError::msg(format!("[[network.rules]][{}].method: '{}' must be uppercase (e.g. method = \"GET\" or method = \"*\").", i, method)));
                    }
                    if !path.starts_with('/') {
                        return Err(ConfigError::msg(format!("[[network.rules]][{}].path: 'path' must start with '/'. Change to path = \"/{}\".", i, path.trim_start_matches('/'))));
                    }
                    
                    if rule.contains_key("secret") {
                        rules_hosts_with_secret.insert(host_val.to_string());
                    } else {
                        rules_hosts_no_secret.insert(host_val.to_string());
                        has_non_secret_rule = true;
                    }
                }
            }
            
            if let Some(allow) = net_table.get("allow") {
                let items = _proxy_list("allow", allow, |_, _| Ok(()), "[network].")?;
                for item in items {
                    if !allow_set.insert(item.clone()) {
                        return Err(ConfigError::msg(format!("[network].allow: duplicate entry '{}'. Remove the redundant entry.", item)));
                    }
                    if item == "*" || item.starts_with("*:") {
                        allow_has_wildcard = true;
                    }
                    if rules_hosts_no_secret.contains(&item) {
                        return Err(ConfigError::msg(format!("[network]: host '{}' is allowed broadly, making the non-secret [[network.rules]] ineffective. Remove the rule or add a secret.", item)));
                    }
                }
            }
            
            if allow_has_wildcard && has_non_secret_rule {
                return Err(ConfigError::msg("[network]: wildcard allow makes non-secret [[network.rules]] ineffective. Remove the rule or add a secret."));
            }
            
            if allow_has_wildcard {
                policy.default = vec!["allow".to_string()];
            }

            for item in allow_set {
                let (host_part, port_part) = parse_host_port(&item);
                if host_part != "*" {
                    if is_ip_or_cidr(&host_part) {
                        if !policy.allow_ips.contains(&host_part) {
                            policy.allow_ips.push(host_part.clone());
                        }
                    } else {
                        _proxy_domain("[network].allow", &host_part)?;
                        // One line per host, not one per port: the same host on
                        // two ports is two allow entries but one rule to read
                        // in `ctl proxy show`.
                        if !policy.allow_domains.contains(&host_part) {
                            policy.allow_domains.push(host_part.clone());
                        }
                    }
                }
                if let Some(port) = port_part {
                    _proxy_port("[network].allow", &port)?;
                    // An allow entry on the SSH port is also what authorizes
                    // the relay to reach that host, and -- because gpg has no
                    // destination of its own -- what enables signing at all.
                    // The relay refuses everything while allow_signing is
                    // empty, so this is the only way to turn it on.
                    if port == "22" && host_part != "*" && !policy.allow_signing.contains(&host_part) {
                        policy.allow_signing.push(host_part.clone());
                    }
                    policy.allow_ports.push(port);
                }
            }
            
            if let Some(rules) = net_table.get("rules") {
                let rules_arr = rules.as_array().unwrap();
                for (i, rule_val) in rules_arr.iter().enumerate() {
                    let rule = rule_val.as_table().unwrap();
                    let host_val = rule.get("host").and_then(|v| v.as_str()).unwrap();
                    let method = rule.get("method").and_then(|v| v.as_str()).unwrap();
                    let path = rule.get("path").and_then(|v| v.as_str()).unwrap();
                    
                    let (host_part, port_part) = parse_host_port(host_val);
                    
                    if host_part != "*" {
                        if is_ip_or_cidr(&host_part) {
                            if !policy.allow_ips.contains(&host_part) {
                                policy.allow_ips.push(host_part.clone());
                            }
                        } else {
                            _proxy_domain(&format!("[[network.rules]][{}].host", i), &host_part)?;
                            if !policy.allow_domains.contains(&host_part) {
                                policy.allow_domains.push(host_part.clone());
                            }
                        }
                    }
                    
                    if let Some(port) = port_part {
                        _proxy_port(&format!("[[network.rules]][{}].host", i), &port)?;
                        if !policy.allow_ports.contains(&port) {
                            policy.allow_ports.push(port.clone());
                        }
                    }
                    
                    policy.allow_l7.push(format!("{}\t{}\t{}", host_part, method, path));
                    
                    if let Some(secret) = rule.get("secret") {
                        if !secret.is_str() {
                            return Err(ConfigError::msg(format!("[[network.rules]][{}].secret: must be a string", i)));
                        }
                        if !policy.secret_domains.contains(&host_part) {
                            policy.secret_domains.push(host_part.clone());
                        }
                    }
                }
            }
        }
    }
    
    Ok(policy)
}

pub fn format_proxy_policy(policy: &ProxyPolicy, source: &str) -> String {
    let mut lines = vec![format!("# generated by agent-sandbox-parse-agents from {}", source)];
    
    for val in &policy.allow_domains { lines.push(format!("allow_domains {}", val)); }
    for val in &policy.deny_domains { lines.push(format!("deny_domains {}", val)); }
    for val in &policy.secret_domains { lines.push(format!("secret_domains {}", val)); }
    for val in &policy.allow_signing { lines.push(format!("allow_signing {}", val)); }
    for val in &policy.allow_ips { lines.push(format!("allow_ips {}", val)); }
    for val in &policy.deny_ips { lines.push(format!("deny_ips {}", val)); }
    for val in &policy.allow_ports { lines.push(format!("allow_ports {}", val)); }
    
    for val in &policy.allow_l7 { lines.push(format!("allow_l7\t{}", val)); }
    for val in &policy.default { lines.push(format!("default {}", val)); }

    lines.join("\n") + "\n"
}

/// The reverse of `format_proxy_policy`: renders a running sandbox's current
/// (possibly live-edited) policy back as an AGENTS.md `[network]` TOML block,
/// for `agent-sandbox ctl proxy export`.
///
/// Not fully round-trippable: `[network]` only supports `allow` (bare
/// host/IP entries) and `[[network.rules]]` (`allow_l7`), so `deny_domains`,
/// `deny_ips`, and a non-default `allow_ports` — all of which can only be
/// added live (via the TUI or `ctl proxy allow/deny`), never declared in
/// AGENTS.md — are emitted as a trailing advisory comment instead of being
/// silently dropped or invented as unsupported TOML keys. A `secret = true`
/// on an exported rule is a placeholder too: the policy file only records
/// that the domain takes a secret, not which one, so the real reference has
/// to be filled in by hand.
pub fn format_policy_as_network_toml(cfg: &ProxyConfig) -> String {
    let mut out = String::from("[network]\n");

    let mut allow_items: Vec<String> = cfg.allow_domains.clone();
    allow_items.extend(cfg.allow_ips.iter().map(|n| n.to_string()));
    if !allow_items.is_empty() {
        let quoted: Vec<String> = allow_items.iter().map(|s| format!("{:?}", s)).collect();
        out.push_str(&format!("allow = [{}]\n", quoted.join(", ")));
    }

    for r in &cfg.l7_rules {
        out.push('\n');
        out.push_str("[[network.rules]]\n");
        out.push_str(&format!("host = {:?}\n", r.domain));
        out.push_str(&format!("method = {:?}\n", r.method));
        out.push_str(&format!("path = {:?}\n", r.path_pattern));
        if cfg.secret_domains.iter().any(|d| d == &r.domain) {
            out.push_str("secret = true # placeholder -- fill in the real secret reference; the policy file doesn't retain it\n");
        }
    }

    let mut advisory: Vec<String> = Vec::new();
    for d in &cfg.deny_domains { advisory.push(format!("deny_domains {}", d)); }
    for ip in &cfg.deny_ips { advisory.push(format!("deny_ips {}", ip)); }
    if let Some(ranges) = &cfg.allow_ports {
        for r in ranges { advisory.push(format!("allow_ports {}", r)); }
    }
    if !advisory.is_empty() {
        out.push_str("\n# The following have no [network] TOML equivalent (it only supports 'allow'\n");
        out.push_str("# and 'rules') and were left out of the block above. Re-apply them after\n");
        out.push_str("# relaunching with `agent-sandbox ctl proxy allow`/`deny`:\n");
        for line in advisory {
            out.push_str(&format!("# {}\n", line));
        }
    }

    out
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use agent_sandbox_proxy::policy::parse_policy;

    #[test]
    fn exports_allow_entries_and_l7_rules_as_toml() {
        let cfg = parse_policy(
            "allow_domains github.com\n\
             allow_ips 10.0.0.0/8\n\
             secret_domains api.github.com\n\
             allow_l7\tapi.github.com\tGET\t/repos/*\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("[network]\n"), "{toml}");
        assert!(toml.contains("allow = [\"github.com\", \"10.0.0.0/8\"]"), "{toml}");
        assert!(toml.contains("[[network.rules]]"), "{toml}");
        assert!(toml.contains("host = \"api.github.com\""), "{toml}");
        assert!(toml.contains("method = \"GET\""), "{toml}");
        assert!(toml.contains("path = \"/repos/*\""), "{toml}");
        assert!(toml.contains("secret = true"), "{toml}");
    }

    #[test]
    fn exports_deny_and_ports_as_an_advisory_comment_not_toml_keys() {
        let cfg = parse_policy(
            "deny_domains evil.example.com\ndeny_ips 169.254.169.254/32\nallow_ports 8000-8100\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(!toml.contains("deny ="), "deny has no [network] TOML key: {toml}");
        assert!(toml.contains("# deny_domains evil.example.com"), "{toml}");
        assert!(toml.contains("# deny_ips 169.254.169.254/32"), "{toml}");
        assert!(toml.contains("# allow_ports 8000-8100"), "{toml}");
    }

    #[test]
    fn is_ip_or_cidr_distinguishes_ips_from_domains() {
        assert!(is_ip_or_cidr("10.0.0.0/8"));
        assert!(is_ip_or_cidr("169.254.169.254"));
        assert!(!is_ip_or_cidr("example.com"));
    }
}
