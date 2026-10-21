#![forbid(unsafe_code)]

use agent_sandbox_proxy::policy::ProxyConfig;
use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
        format!(
            "{}:{}:{}/{}",
            bind, self.host, self.container, self.protocol
        )
    }
}

impl ProxyPolicy {
    /// Merge another declarative policy, preserving the first occurrence of
    /// each rule. Profiles and AGENTS.md are intentionally additive: neither
    /// source can use merging to weaken the deny-by-default policy.
    pub fn merge(&mut self, other: ProxyPolicy) {
        fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
            for value in values {
                if !target.contains(&value) {
                    target.push(value);
                }
            }
        }

        extend_unique(&mut self.allow_host, other.allow_host);
        extend_unique(&mut self.secret_route, other.secret_route);
        extend_unique(&mut self.allow_signing, other.allow_signing);
        self.signing_enabled = self.signing_enabled || other.signing_enabled;
        extend_unique(&mut self.allow_ip, other.allow_ip);
        extend_unique(&mut self.allow_port, other.allow_port);
        extend_unique(&mut self.allow_route, other.allow_route);
        if self.default.is_empty() {
            self.default = other.default;
        }
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
    let s = value
        .as_str()
        .ok_or_else(|| ConfigError::msg(format!("ports.{}.bind: expected a string", name)))?;
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

fn parse_entry(
    name: &str,
    value: &Value,
    allow_any_interface: bool,
) -> Result<Mapping, ConfigError> {
    if !is_valid_name(name) {
        return Err(ConfigError::msg(format!(
            "ports.{:?}: name must match pattern",
            name
        )));
    }

    if let Some(table) = value.as_table() {
        let allowed_fields: HashSet<&str> = ["container", "host", "bind", "protocol"]
            .iter()
            .cloned()
            .collect();
        let unknown: Vec<_> = table
            .keys()
            .filter(|k| !allowed_fields.contains(k.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(ConfigError::msg(format!(
                "ports.{}: unknown field(s) {:?}",
                name, unknown
            )));
        }
        if !table.contains_key("container") {
            return Err(ConfigError::msg(format!(
                "ports.{}: missing required field 'container'",
                name
            )));
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

pub fn parse_ports(
    text: &str,
    allow_any_interface: bool,
    max_ports: usize,
) -> Result<Vec<Mapping>, ConfigError> {
    let mut mappings = std::collections::HashMap::new();
    let blocks = iter_tagged_blocks(text);

    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;

        if let Some(ports) = block.get("ports") {
            let ports_table = ports
                .as_table()
                .ok_or_else(|| ConfigError::msg("[ports] must be a table"))?;

            for (name, value) in ports_table {
                if mappings.contains_key(name) {
                    return Err(ConfigError::msg(format!(
                        "ports.{}: declared more than once",
                        name
                    )));
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
    let bind_addr: IpAddr = mapping
        .bind
        .parse()
        .map_err(|e| ConfigError::msg(format!("invalid bind: {}", e)))?;
    let host_port = if mapping.protocol == "udp" {
        let sock = UdpSocket::bind((bind_addr, 0)).map_err(ConfigError::msg)?;
        sock.local_addr().map_err(ConfigError::msg)?.port()
    } else {
        let listener = TcpListener::bind((bind_addr, 0)).map_err(ConfigError::msg)?;
        listener
            .local_addr()
            .map_err(ConfigError::msg)?
            .port()
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
            let mounts_table = mounts
                .as_table()
                .ok_or_else(|| ConfigError::msg("[mounts] must be a table"))?;
            for (src, value) in mounts_table {
                let (dest, opts) = if let Some(s) = value.as_str() {
                    (s.to_string(), String::new())
                } else if let Some(table) = value.as_table() {
                    let dest = table
                        .get("destination")
                        .and_then(|d| d.as_str())
                        .ok_or_else(|| {
                            ConfigError::msg(format!(
                                "mounts.{}: missing required field 'destination' or not a string",
                                src
                            ))
                        })?
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
                                    return Err(ConfigError::msg(format!(
                                        "mounts.{}.options: expected a string or list of strings",
                                        src
                                    )));
                                }
                            }
                            opts = opt_strings.join(",");
                        } else {
                            return Err(ConfigError::msg(format!(
                                "mounts.{}.options: expected a string or list of strings",
                                src
                            )));
                        }
                    }
                    let allowed: HashSet<&str> =
                        ["destination", "options"].iter().cloned().collect();
                    let unknown: Vec<_> = table
                        .keys()
                        .filter(|k| !allowed.contains(k.as_str()))
                        .collect();
                    if !unknown.is_empty() {
                        return Err(ConfigError::msg(format!(
                            "mounts.{}: unknown field(s) {:?}",
                            src, unknown
                        )));
                    }
                    (dest, opts)
                } else {
                    return Err(ConfigError::msg(format!(
                        "mounts.{}: expected a string or table",
                        src
                    )));
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

/// Validates a port spec: a port, a range, or a comma-separated list of both.
///
/// Delegated to the proxy's own parser rather than reimplemented, so what the
/// launcher accepts and what the proxy accepts cannot drift apart -- the
/// asymmetry this closes had the exit summary printing `host:22,443` back as
/// TOML that the launcher then refused on relaunch.
fn _proxy_port(field: &str, value: &str) -> Result<(), ConfigError> {
    // `split_list` drops empty elements, so an empty spec parses as "no ports"
    // rather than failing. Caught here, because `"github.com:"` would otherwise
    // compile to a line the proxy reads back as a literal domain.
    if value.trim().is_empty() || value.split(',').any(|p| p.trim().is_empty()) {
        return Err(ConfigError::msg(format!(
            "{}: {:?} has an empty port. Write a port, a range, or a comma-separated list of them.",
            field, value
        )));
    }
    agent_sandbox_proxy::policy::parse_csv_ports(value).map_err(|_| {
        ConfigError::msg(format!(
            "{}: {:?} is not a port, port range, or comma-separated list of them",
            field, value
        ))
    })?;
    Ok(())
}

/// Whether a port spec covers 22 -- including via a range, which is what
/// `is_allowed(host, 22)` will do at the proxy.
///
/// An `allowed_hosts` entry on the SSH port does double duty: it is also what
/// authorizes the relay to reach that host, so this is what decides whether
/// `git push`/`pull` work in a proxied session.
fn ports_include_ssh(spec: &str) -> bool {
    agent_sandbox_proxy::policy::parse_csv_ports(spec)
        .map(|ranges| ranges.iter().any(|r| r.contains(22)))
        .unwrap_or(false)
}

fn _proxy_list<F>(
    field: &str,
    value: &Value,
    mut validate: F,
    prefix: &str,
) -> Result<Vec<String>, ConfigError>
where
    F: FnMut(&str, &str) -> Result<(), ConfigError>,
{
    let arr = value
        .as_array()
        .ok_or_else(|| ConfigError::msg(format!("{}{}", prefix, field)))?;
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

/// Splits `host:ports` on the last colon, where `ports` may be a port, a
/// range, or a comma-separated list of both.
///
/// The right-hand side is recognised on the same terms as the proxy's
/// `policy::parse_target_with_ports`, deliberately: what the splitter accepts
/// and what the policy file accepts have to be the same set. `*` is recognised
/// here and rejected by `_proxy_port`, which is what produces the good error
/// message instead of "not a valid domain name".
pub fn parse_host_port(s: &str) -> (String, Option<String>) {
    if let Some(pos) = s.rfind(':') {
        let left = &s[..pos];
        let right = &s[pos + 1..];
        let looks_like_ports = !right.is_empty()
            && right
                .chars()
                .all(|c| c.is_ascii_digit() || c == ',' || c == '-');
        // An unbracketed IPv6 address is all colons and hex; splitting it here
        // would hand `_proxy_domain` a fragment and blame the domain.
        let is_unbracketed_ipv6 = left.contains(':') && !left.starts_with('[');
        if (looks_like_ports || right == "*") && !is_unbracketed_ipv6 {
            let host = if left.starts_with('[') && left.ends_with(']') {
                &left[1..left.len() - 1]
            } else {
                left
            };
            return (host.to_string(), Some(right.to_string()));
        }
    }
    (s.to_string(), None)
}

pub fn format_host_port(host: &str, port: Option<&str>) -> String {
    match port {
        Some(port) if host.contains(':') && !host.starts_with('[') => {
            format!("[{}]:{}", host, port)
        }
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    }
}

#[derive(Default, Debug)]
pub struct ProxyPolicy {
    pub allow_host: Vec<String>,
    /// `domain\tmethod\tpath` per rule that names a secret.  Route-scoped, not
    /// domain-scoped: the proxy injects only into requests matching one of
    /// these, so a secret-less rule elsewhere on the same host cannot collect
    /// the token.
    pub secret_route: Vec<String>,
    pub allow_signing: Vec<String>,
    /// Whether the GPG relay should be allowed to sign/authenticate at all,
    /// independent of any host. Never parsed from AGENTS.md TOML -- set
    /// directly by the launcher binary whenever `--gpg` wires up the relay.
    pub signing_enabled: bool,
    pub allow_ip: Vec<String>,
    pub allow_port: Vec<String>,
    pub allow_route: Vec<String>,
    pub default: Vec<String>,
}

/// The path of an `[[network.allowed_routes]]` rule that names none, or names
/// `""`: every path, so a rule can narrow a host by method alone.
pub const DEFAULT_ROUTE_PATH: &str = "/**";

pub fn route_path(path: Option<&str>) -> &str {
    match path {
        None | Some("") => DEFAULT_ROUTE_PATH,
        Some(path) => path,
    }
}

/// One HTTP route, validated but not yet compiled into policy lines.
struct RouteSpec {
    /// The `allowed_hosts` entry a short-form route was written as; `None` for
    /// a `[[network.allowed_routes]]` table.
    entry: Option<String>,
    /// `domain[:ports]`, as written.
    host: String,
    method: String,
    /// Already defaulted: `/**` when the rule names none.
    path: String,
    has_secret: bool,
}

fn parse_route_table(i: usize, rule_val: &Value) -> Result<RouteSpec, ConfigError> {
    let rule = rule_val.as_table().ok_or_else(|| {
        ConfigError::msg(format!(
            "[[network.allowed_routes]][{}]: must be a table",
            i
        ))
    })?;

    let allowed_rule_keys: HashSet<&str> = ["host", "method", "path", "secret", "header", "prefix"]
        .iter()
        .cloned()
        .collect();
    if let Some(unknown_key) = rule
        .keys()
        .find(|k| !allowed_rule_keys.contains(k.as_str()))
    {
        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}]: unknown field '{}'. Valid keys under [[network.allowed_routes]] are 'host', 'method', 'path', 'secret', 'header', and 'prefix'.", i, unknown_key)));
    }

    let host_val = rule.get("host").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}]: missing required field 'host'. Example: host = \"registry.npmjs.org:443\".", i)))?;
    let method = rule.get("method").and_then(|v| v.as_str()).ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}]: missing required field 'method'. Specify an HTTP method (e.g. method = \"GET\", method = \"POST\", or method = \"*\").", i)))?;
    let path = match rule.get("path") {
        None => DEFAULT_ROUTE_PATH,
        Some(v) => route_path(Some(v.as_str().ok_or_else(|| ConfigError::msg(format!("[[network.allowed_routes]][{}].path: must be a string. Example: path = \"/api/*\", or omit it to allow every path.", i)))?)),
    };

    if method != "*" && (!method.chars().all(|c| c.is_ascii_uppercase()) || method.is_empty()) {
        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}].method: '{}' must be uppercase (e.g. method = \"GET\" or method = \"*\").", i, method)));
    }
    if !path.starts_with('/') {
        return Err(ConfigError::msg(format!("[[network.allowed_routes]][{}].path: 'path' must start with '/'. Change to path = \"/{}\".", i, path.trim_start_matches('/'))));
    }
    if let Some(secret) = rule.get("secret") {
        if !secret.is_str() {
            return Err(ConfigError::msg(format!(
                "[[network.allowed_routes]][{}].secret: must be a string",
                i
            )));
        }
    }
    let ctx = format!("[[network.allowed_routes]][{}]", i);
    validate_route_host(&ctx, host_val)?;

    Ok(RouteSpec {
        entry: None,
        host: host_val.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        has_secret: rule.contains_key("secret"),
    })
}

/// The short form of a route, written straight into `allowed_hosts`:
/// `[METHODS ]DOMAIN[:PORTS][/PATH]`, such as `"GET,POST api.example.com:443/v1/**"`.
/// A method list without a path means every path, and a path without a method
/// list every method, as an `[[network.allowed_routes]]` table would have it.
///
/// `None` for a plain allow entry: anything without a method list or a path,
/// a CIDR block's `/` being a prefix length rather than a path.
fn parse_route_entry(i: usize, entry: &str) -> Option<Result<Vec<RouteSpec>, ConfigError>> {
    let trimmed = entry.trim();
    let (methods, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((methods, rest)) => (Some(methods), rest.trim_start()),
        None => (None, trimmed),
    };
    if methods.is_none() {
        // An address before the first `/` makes it a CIDR block, well-formed
        // or not; a malformed one is the plain path's to refuse, as before.
        let before_slash = rest.split('/').next().unwrap_or_default();
        let address = parse_host_port(before_slash).0;
        let address = address.trim_start_matches('[').trim_end_matches(']');
        if !rest.contains('/') || is_ip_or_cidr(&parse_host_port(rest).0) || is_ip_or_cidr(address)
        {
            return None;
        }
    }
    Some(route_entry_specs(i, entry, methods, rest))
}

fn route_entry_specs(
    i: usize,
    entry: &str,
    methods: Option<&str>,
    rest: &str,
) -> Result<Vec<RouteSpec>, ConfigError> {
    let ctx = format!("[network].allowed_hosts[{}] '{}'", i, entry);
    if rest.contains(char::is_whitespace) {
        return Err(ConfigError::msg(format!(
            "{}: unexpected space. A route is written METHODS DOMAIN[:PORTS][/PATH], with whitespace after the method list and none elsewhere (e.g. \"GET,POST api.example.com:443/v1/**\").",
            ctx
        )));
    }
    let (host, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, DEFAULT_ROUTE_PATH),
    };
    let (host_part, port_part) = parse_host_port(host);
    if host_part.is_empty() {
        return Err(ConfigError::msg(format!(
            "{}: missing domain. Example: \"GET api.example.com:443/v1/**\".",
            ctx
        )));
    }
    if host_part == "*" || is_ip_or_cidr(&host_part) {
        return Err(ConfigError::msg(format!(
            "{}: a route needs a domain name, not '{}'. Allow it without a method or path instead.",
            ctx, host_part
        )));
    }
    _proxy_domain(&ctx, &host_part)?;
    if let Some(port) = &port_part {
        _proxy_port(&ctx, port)?;
        if ports_include_ssh(port) {
            return Err(ConfigError::msg(format!(
                "{}: a route is HTTP, so it cannot cover port 22. Write \"{}:22\" as an entry of its own for SSH.",
                ctx, host_part
            )));
        }
    }

    let methods: Vec<&str> = match methods {
        None => vec!["*"],
        Some(list) => list.split(',').collect(),
    };
    let mut seen = HashSet::new();
    for method in &methods {
        let valid = *method == "*"
            || (!method.is_empty() && method.chars().all(|c| c.is_ascii_uppercase()));
        if !valid {
            return Err(ConfigError::msg(format!(
                "{}: method '{}' must be uppercase (e.g. GET, or * for every method), and methods are separated by commas alone.",
                ctx, method
            )));
        }
        if !seen.insert(*method) {
            return Err(ConfigError::msg(format!(
                "{}: method '{}' is listed twice.",
                ctx, method
            )));
        }
    }
    if methods.len() > 1 && methods.contains(&"*") {
        return Err(ConfigError::msg(format!(
            "{}: '*' already covers every method; list it alone.",
            ctx
        )));
    }

    Ok(methods
        .into_iter()
        .map(|method| RouteSpec {
            entry: Some(entry.to_string()),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            has_secret: false,
        })
        .collect())
}

/// The refusal for a host allowed outright beside secret-less routes on it,
/// naming every one of them so a single edit can resolve it.
fn broad_allow_conflict(item: &str, routes: &[&RouteSpec]) -> String {
    let has_table = routes.iter().any(|r| r.entry.is_none());
    let mut entries: Vec<String> = Vec::new();
    for entry in routes.iter().filter_map(|r| r.entry.as_deref()) {
        let quoted = format!("'{}'", entry);
        if !entries.contains(&quoted) {
            entries.push(quoted);
        }
    }
    let short = match entries.len() {
        0 => String::new(),
        1 => format!("the route {} in allowed_hosts", entries[0]),
        _ => format!("the routes {} in allowed_hosts", entries.join(", ")),
    };
    match (has_table, short.is_empty()) {
        (true, true) => format!("[network]: host '{}' is allowed broadly, making the non-secret [[network.allowed_routes]] ineffective. Remove the rule or add a secret.", item),
        (false, _) => format!("[network]: host '{}' is allowed broadly, making {} ineffective. Remove one of the two entries.", item, short),
        (true, false) => format!("[network]: host '{}' is allowed broadly, making the non-secret [[network.allowed_routes]] and {} ineffective. Remove the broad allow, or the rules.", item, short),
    }
}

/// The domain and port checks for a route's `host`, kept with the rest of a
/// route's validation so every rule is checked before any is compiled.
fn validate_route_host(ctx: &str, host: &str) -> Result<(), ConfigError> {
    let host_ctx = format!("{}.host", ctx);
    let (host_part, port_part) = parse_host_port(host);
    if host_part != "*" && !is_ip_or_cidr(&host_part) {
        _proxy_domain(&host_ctx, &host_part)?;
    }
    if let Some(port) = port_part {
        _proxy_port(&host_ctx, &port)?;
    }
    Ok(())
}

/// Compiles one validated route: its host becomes an allow entry like any
/// other, and the route itself an `allow_route` line (plus `secret_route` when
/// it injects).
fn add_route(policy: &mut ProxyPolicy, route: &RouteSpec) {
    let (host_part, port_part) = parse_host_port(&route.host);

    if host_part != "*" {
        let combined = format_host_port(&host_part, port_part.as_deref());
        if is_ip_or_cidr(&host_part) {
            if !policy.allow_ip.contains(&combined) {
                policy.allow_ip.push(combined);
            }
        } else if !policy.allow_host.contains(&combined) {
            policy.allow_host.push(combined);
        }
    }

    if let Some(port) = port_part {
        if host_part == "*" {
            // One line per element, as for allowed_hosts.
            for element in port.split(',') {
                let element = element.to_string();
                if !policy.allow_port.contains(&element) {
                    policy.allow_port.push(element);
                }
            }
        }
    }

    let line = format!("{}\t{}\t{}", host_part, route.method, route.path);
    if route.has_secret {
        // The route, not just the host: this is what the proxy matches a
        // request against before injecting.
        if !policy.secret_route.contains(&line) {
            policy.secret_route.push(line.clone());
        }
    }
    policy.allow_route.push(line);
}

pub fn parse_proxy(text: &str) -> Result<ProxyPolicy, ConfigError> {
    let mut policy = ProxyPolicy {
        default: vec!["deny".to_string()],
        ..Default::default()
    };

    let blocks = iter_tagged_blocks(text);

    for body in blocks {
        let block: Value = body.parse().map_err(|e| {
            ConfigError::msg(format!("malformed TOML in agent-sandbox block: {}", e))
        })?;

        if let Some(table) = block.as_table() {
            let allowed_tables: HashSet<&str> =
                ["network", "ports", "mounts"].iter().cloned().collect();
            let unknown: Vec<_> = table
                .keys()
                .filter(|k| !allowed_tables.contains(k.as_str()))
                .collect();
            if !unknown.is_empty() {
                return Err(ConfigError::msg(format!(
                    "unknown top-level table(s): {:?}",
                    unknown
                )));
            }
        }

        if let Some(network) = block.get("network") {
            let net_table = network
                .as_table()
                .ok_or_else(|| ConfigError::msg("[network] must be a table"))?;

            let allowed_net: HashSet<&str> =
                ["allowed_hosts", "allowed_routes"].iter().cloned().collect();
            let unknown: Vec<_> = net_table
                .keys()
                .filter(|k| !allowed_net.contains(k.as_str()))
                .collect();
            if let Some(first_unknown) = unknown.first() {
                return Err(ConfigError::msg(format!("[network]: unknown key '{}'. Valid keys under [network] are 'allowed_hosts' and 'allowed_routes' ([[network.allowed_routes]]).", first_unknown)));
            }

            let mut allow_set = HashSet::new();
            let mut allow_has_wildcard = false;

            let mut routes = Vec::new();
            if let Some(rules) = net_table.get("allowed_routes") {
                let rules_arr = rules.as_array().ok_or_else(|| {
                    ConfigError::msg("[network].allowed_routes must be an array of tables")
                })?;
                for (i, rule_val) in rules_arr.iter().enumerate() {
                    routes.push(parse_route_table(i, rule_val)?);
                }
            }

            // Routes written into allowed_hosts join the tables' routes before
            // any conflict check, so the order of the entries does not matter.
            let mut plain_items = Vec::new();
            if let Some(allow) = net_table.get("allowed_hosts") {
                let items = _proxy_list("allowed_hosts", allow, |_, _| Ok(()), "[network].")?;
                // Seeded with the tables, so a short-form route repeating one
                // is refused too.
                let mut seen_routes: HashSet<(String, String, String)> = routes
                    .iter()
                    .map(|r: &RouteSpec| (r.host.clone(), r.method.clone(), r.path.clone()))
                    .collect();
                for (i, item) in items.into_iter().enumerate() {
                    match parse_route_entry(i, &item) {
                        None => plain_items.push(item),
                        Some(specs) => {
                            for spec in specs? {
                                let key =
                                    (spec.host.clone(), spec.method.clone(), spec.path.clone());
                                if !seen_routes.insert(key) {
                                    return Err(ConfigError::msg(format!(
                                        "[network].allowed_hosts: duplicate entry '{}': its route {} {}{} is already listed, in allowed_hosts or as a [[network.allowed_routes]] table. Remove the redundant entry.",
                                        item, spec.method, spec.host, spec.path
                                    )));
                                }
                                routes.push(spec);
                            }
                        }
                    }
                }
            }

            let mut rules_hosts_no_secret: HashMap<&str, Vec<&RouteSpec>> = HashMap::new();
            for r in routes.iter().filter(|r| !r.has_secret) {
                rules_hosts_no_secret
                    .entry(r.host.as_str())
                    .or_default()
                    .push(r);
            }
            let has_non_secret_rule = !rules_hosts_no_secret.is_empty();

            for item in plain_items {
                if !allow_set.insert(item.clone()) {
                    return Err(ConfigError::msg(format!(
                        "[network].allowed_hosts: duplicate entry '{}'. Remove the redundant entry.",
                        item
                    )));
                }
                if item == "*" || item.starts_with("*:") {
                    allow_has_wildcard = true;
                }
                if let Some(conflicting) = rules_hosts_no_secret.get(item.as_str()) {
                    return Err(ConfigError::msg(broad_allow_conflict(&item, conflicting)));
                }
            }

            if allow_has_wildcard && has_non_secret_rule {
                if routes.iter().any(|r| !r.has_secret && r.entry.is_none()) {
                    return Err(ConfigError::msg("[network]: wildcard allow makes non-secret [[network.allowed_routes]] ineffective. Remove the rule or add a secret."));
                }
                return Err(ConfigError::msg("[network]: wildcard allow makes the routes in allowed_hosts ineffective. Remove the wildcard or the routes."));
            }

            if allow_has_wildcard {
                policy.default = vec!["allow".to_string()];
            }

            for item in allow_set {
                let (host_part, port_part) = parse_host_port(&item);
                if host_part != "*" {
                    let combined = format_host_port(&host_part, port_part.as_deref());
                    if is_ip_or_cidr(&host_part) {
                        if !policy.allow_ip.contains(&combined) {
                            policy.allow_ip.push(combined);
                        }
                    } else {
                        _proxy_domain("[network].allowed_hosts", &host_part)?;
                        // One line per entry, so `ctl policy show` and
                        // `rm allow` operate on the entry as it was written --
                        // including a comma-separated port list, which the
                        // proxy parses on one line. The proxy also unions the
                        // ports of every line sharing a pattern
                        // (`union_ports`), so two entries on one host are two
                        // lines and both are in force.
                        if !policy.allow_host.contains(&combined) {
                            policy.allow_host.push(combined);
                        }
                    }
                }
                if let Some(port) = port_part {
                    _proxy_port("[network].allowed_hosts", &port)?;
                    // An allow entry covering the SSH port is also what
                    // authorizes the relay to reach that host, so it is what
                    // makes `git push`/`pull` work in a proxied session. It
                    // says nothing about GPG signing, which `signing_enabled`
                    // gates on its own, host-agnostic.
                    if ports_include_ssh(&port)
                        && host_part != "*"
                        && !policy.allow_signing.contains(&host_part)
                    {
                        policy.allow_signing.push(host_part.clone());
                    }
                    if host_part == "*" {
                        // One line per element: the proxy's `allow_port` arm
                        // takes a single port or range, unlike the port field
                        // of a host target.
                        for element in port.split(',') {
                            let element = element.to_string();
                            if !policy.allow_port.contains(&element) {
                                policy.allow_port.push(element);
                            }
                        }
                    }
                }
            }

            for route in &routes {
                add_route(&mut policy, route);
            }
        }
    }

    Ok(policy)
}

/// Parse a host-owned policy file. Policy files are plain TOML rather than
/// Markdown, but otherwise use exactly the same declarative network syntax as
/// AGENTS.md.
pub fn parse_policy_file(text: &str) -> Result<ProxyPolicy, ConfigError> {
    let value: Value = text
        .parse()
        .map_err(|e| ConfigError::msg(format!("malformed TOML in policy file: {}", e)))?;
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::msg("policy file must contain a TOML table"))?;
    if let Some(unknown) = table.keys().find(|key| *key != "network") {
        return Err(ConfigError::msg(format!(
            "policy file: unknown top-level key '{}'; only [network] is supported",
            unknown
        )));
    }
    let network = table
        .get("network")
        .ok_or_else(|| ConfigError::msg("policy file must contain a [network] table"))?;
    if !network.is_table() {
        return Err(ConfigError::msg("[network] must be a table"));
    }

    // Reuse the single AGENTS.md validator rather than maintaining a second
    // parser for the policy file format.
    let wrapped = format!("```toml agent-sandbox\n{}\n```", text);
    parse_proxy(&wrapped)
}

pub fn format_proxy_policy(policy: &ProxyPolicy, source: &str) -> String {
    let mut lines = vec![format!(
        "# generated by agent-sandbox-parse-agents from {}",
        source
    )];

    for val in &policy.allow_host {
        lines.push(format!("allow_host {}", val));
    }
    for val in &policy.secret_route {
        lines.push(format!("secret_route\t{}", val));
    }
    for val in &policy.allow_signing {
        lines.push(format!("allow_signing {}", val));
    }
    if policy.signing_enabled {
        lines.push("signing_enabled true".to_string());
    }
    for val in &policy.allow_ip {
        lines.push(format!("allow_ip {}", val));
    }
    for val in &policy.allow_port {
        lines.push(format!("allow_port {}", val));
    }

    for val in &policy.allow_route {
        lines.push(format!("allow_route\t{}", val));
    }
    for val in &policy.default {
        lines.push(format!("default {}", val));
    }

    lines.join("\n") + "\n"
}

/// The reverse of `format_proxy_policy`: renders a running sandbox's current
/// (possibly live-edited) policy back as an AGENTS.md `[network]` TOML block,
/// for `agent-sandbox ctl policy export`.
///
/// Not fully round-trippable: `[network]` only supports `allowed_hosts` (bare
/// host/IP entries) and `[[network.allowed_routes]]` (`allow_route`), so a non-default
/// `allow_port` — which can only be added live, via the TUI or
/// `ctl policy allow`, never declared in AGENTS.md — is emitted as a trailing
/// advisory comment instead of being silently dropped or invented as an
/// unsupported TOML key.  `deny_ip` is omitted entirely: the baseline is
/// built-in, enforced whatever AGENTS.md says, and cannot be changed, so
/// round-tripping it would be noise.  A `secret = true` on an exported rule
/// is a placeholder too: the policy file records which *route* takes a
/// secret, never which one, so the reference has to be filled in by hand.
#[derive(Serialize)]
struct NetworkDocument {
    network: NetworkToml,
}

#[derive(Serialize)]
struct NetworkToml {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_hosts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_routes: Vec<RouteToml>,
}

#[derive(Serialize)]
struct RouteToml {
    host: String,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<bool>,
}

/// Return compiled policy lines that were added after the sandbox launched.
/// Exact line matching is intentional: policy files contain canonical lines,
/// and it prevents repeated live edits from producing duplicate output.
pub fn policy_delta_lines(
    active: &[String],
    base: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    active
        .iter()
        .filter(|line| !base.contains(*line) && !baseline.contains(*line))
        .filter(|line| seen.insert((*line).clone()))
        .cloned()
        .collect()
}

pub fn format_policy_lines_as_network_toml(lines: &[String]) -> Option<String> {
    let text = lines.join("\n") + "\n";
    let cfg = agent_sandbox_proxy::policy::parse_policy(&text).ok()?;
    Some(format_policy_as_network_toml(&cfg))
}

pub fn format_policy_as_network_toml(cfg: &ProxyConfig) -> String {
    // A route line carries no port: its ports are those of the allow line the
    // route's `host` compiled to. Fold that line back into the route, or a
    // re-import would give the route's domain the default ports instead of the
    // ones it had, and keep a redundant plain entry beside it.
    let mut folded_hosts: HashSet<usize> = HashSet::new();
    let mut folded_ips: HashSet<usize> = HashSet::new();
    let mut route_hosts: HashMap<&str, Option<String>> = HashMap::new();
    for rule in &cfg.l7_rules {
        let domain = rule.domain.as_str();
        if route_hosts.contains_key(domain) {
            continue;
        }
        let ip = domain.parse::<IpAddr>().ok();
        // An entry covering 22 also authorized the SSH relay, which a route
        // cannot carry: such a line stays a plain entry, unless the relay was
        // never authorized for this host, in which case it came from a route.
        let signs = cfg.allow_signing.iter().any(|h| h == domain);
        let foldable = |ports: &Option<Vec<agent_sandbox_proxy::policy::PortRange>>| {
            !signs || !ports.iter().flatten().any(|r| r.contains(22))
        };
        let lines: Vec<(usize, &Option<Vec<agent_sandbox_proxy::policy::PortRange>>)> = match ip {
            None => cfg
                .allow_host
                .iter()
                .enumerate()
                .filter(|(_, h)| h.target == domain && foldable(&h.ports))
                .map(|(i, h)| (i, &h.ports))
                .collect(),
            // An IP route names one address, so it folds only a host-length
            // network on it, not a wider block that happens to contain it.
            Some(ip) => cfg
                .allow_ip
                .iter()
                .enumerate()
                .filter(|(_, n)| {
                    n.target.addr() == ip
                        && n.target.prefix_len() == n.target.max_prefix_len()
                        && foldable(&n.ports)
                })
                .map(|(i, n)| (i, &n.ports))
                .collect(),
        };
        let folded = if ip.is_some() {
            &mut folded_ips
        } else {
            &mut folded_hosts
        };
        let ports: Option<Option<Vec<agent_sandbox_proxy::policy::PortRange>>> =
            if let Some((i, _)) = lines.iter().find(|(_, p)| p.is_none()) {
                // The default ports; any explicit line beside it stays a plain
                // entry of its own.
                folded.insert(*i);
                Some(None)
            } else if !lines.is_empty() {
                let mut ranges = Vec::new();
                for (i, p) in &lines {
                    folded.insert(*i);
                    ranges.extend(p.iter().flatten().copied());
                }
                Some(Some(ranges))
            } else {
                // No allow line of its own (`ctl policy allow --l7` writes
                // none): the route reaches what the rest of the policy allows
                // its domain, and nothing at all if that is nothing.
                let (allowed, ports) = match ip {
                    Some(ip) => cfg.check_ip(ip),
                    None => cfg.check_domain(domain),
                };
                allowed.then_some(ports)
            };
        let host = ports.map(|ports| match ports {
            None => domain.to_string(),
            Some(mut ranges) => {
                ranges.sort_by_key(|r| (r.start, r.end));
                ranges.dedup();
                let ranges: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
                format_host_port(domain, Some(&ranges.join(",")))
            }
        });
        route_hosts.insert(domain, host);
    }

    let mut allowed_hosts: Vec<String> = cfg
        .allow_host
        .iter()
        .enumerate()
        .filter(|(i, _)| !folded_hosts.contains(i))
        .map(|(_, r)| r.to_string())
        .chain(
            cfg.allow_ip
                .iter()
                .enumerate()
                .filter(|(i, _)| !folded_ips.contains(i))
                .map(|(_, n)| n.to_string()),
        )
        .collect();
    allowed_hosts.sort();
    allowed_hosts.dedup();

    let mut unreachable_routes: Vec<String> = Vec::new();
    let mut allowed_routes: Vec<RouteToml> = cfg
        .l7_rules
        .iter()
        .filter_map(|r| {
            let host = route_hosts.get(r.domain.as_str()).cloned().flatten();
            if host.is_none() {
                unreachable_routes.push(format!(
                    "allow_route {} {} {}",
                    r.domain, r.method, r.path_pattern
                ));
            }
            host.map(|host| (host, r))
        })
        .map(|(host, r)| RouteToml {
            host,
            method: r.method.clone(),
            path: r.path_pattern.clone(),
            // The compiled policy records that a route is secret, not
            // the host-side secret reference.
            secret: cfg
                .secret_routes
                .iter()
                .any(|s| {
                    s.domain == r.domain && s.method == r.method && s.path_pattern == r.path_pattern
                })
                .then_some(true),
        })
        .collect();
    allowed_routes.sort_by(|a, b| {
        (&a.host, &a.method, &a.path, &a.secret).cmp(&(&b.host, &b.method, &b.path, &b.secret))
    });
    allowed_routes.dedup_by(|a, b| {
        a.host == b.host && a.method == b.method && a.path == b.path && a.secret == b.secret
    });

    let mut out = toml::to_string_pretty(&NetworkDocument {
        network: NetworkToml {
            allowed_hosts,
            allowed_routes,
        },
    })
    .expect("network TOML serialization cannot fail");
    out.push('\n');

    let mut advisory: Vec<String> = Vec::new();
    if let Some(ranges) = &cfg.allow_port {
        if ranges.as_slice() != agent_sandbox_proxy::policy::DEFAULT_ALLOW_PORTS.as_slice() {
            for r in ranges {
                advisory.push(format!("allow_port {}", r));
            }
        }
    }
    // A route whose domain nothing allows reaches nothing live; as a table it
    // would allow its host on the default ports.
    advisory.extend(unreachable_routes);
    if !advisory.is_empty() {
        out.push_str(
            "\n# The following have no [network] TOML equivalent (it only supports 'allowed_hosts'\n",
        );
        out.push_str(
            "# and 'allowed_routes') and were left out of the block above. Re-apply them after\n",
        );
        out.push_str("# relaunching with `agent-sandbox ctl policy allow`:\n");
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
            "allow_host github.com\n\
             allow_host api.github.com:443\n\
             allow_ip 10.0.0.0/8\n\
             secret_route\tapi.github.com\tGET\t/repos/*\n\
             allow_route\tapi.github.com\tGET\t/repos/*\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("[network]\n"), "{toml}");
        assert!(
            toml.contains("allowed_hosts = [\n    \"10.0.0.0/8\",\n    \"github.com\",\n]"),
            "{toml}"
        );
        assert!(toml.contains("[[network.allowed_routes]]"), "{toml}");
        assert!(toml.contains("host = \"api.github.com:443\""), "{toml}");
        assert!(toml.contains("method = \"GET\""), "{toml}");
        assert!(toml.contains("path = \"/repos/*\""), "{toml}");
        assert!(toml.contains("secret = true"), "{toml}");
    }

    /// Compiles AGENTS.md, exports the result the way `ctl policy export`
    /// does, and compiles the export again.
    fn export_round_trip(agents_md: &str) -> (ProxyPolicy, String, ProxyPolicy) {
        let first = parse_proxy(agents_md).expect("the original must parse");
        let cfg = parse_policy(&format_proxy_policy(&first, "AGENTS.md")).unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        let second = parse_policy_file(&toml)
            .unwrap_or_else(|e| panic!("the export must re-import: {e}\n{toml}"));
        (first, toml, second)
    }

    fn sorted_lines(policy: &ProxyPolicy) -> Vec<String> {
        let mut lines: Vec<String> = format_proxy_policy(policy, "x")
            .lines()
            .skip(1)
            .map(str::to_string)
            .collect();
        lines.sort();
        lines.dedup();
        lines
    }

    #[test]
    fn an_exported_route_keeps_its_port() {
        let (first, toml, second) = export_round_trip(
            "```agent-sandbox\n[network]\n\
             allowed_hosts = [\"github.com:443\", \"GET,POST api.example.com:443/v1/**\"]\n\
             [[network.allowed_routes]]\nhost = \"*.example.org:8443,9443\"\nmethod = \"GET\"\n```\n",
        );
        assert!(toml.contains("host = \"api.example.com:443\""), "{toml}");
        assert!(
            toml.contains("host = \"*.example.org:8443,9443\""),
            "{toml}"
        );
        // Folded into the routes, not left beside them as a plain entry.
        assert!(
            toml.contains("allowed_hosts = [\"github.com:443\"]"),
            "{toml}"
        );
        assert_eq!(sorted_lines(&first), sorted_lines(&second), "{toml}");
    }

    #[test]
    fn an_exported_route_on_default_ports_stays_portless() {
        // A portless route host means the default ports; an explicit entry
        // for the same domain beside it is a plain entry of its own.
        let cfg = parse_policy(
            "allow_host api.example.com\n\
             allow_host api.example.com:8443\n\
             allow_route\tapi.example.com\tGET\t/v1/**\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("host = \"api.example.com\"\n"), "{toml}");
        assert!(
            toml.contains("allowed_hosts = [\"api.example.com:8443\"]"),
            "{toml}"
        );
        let second = parse_policy_file(&toml).expect("the export must re-import");
        let reparsed = parse_policy(&format_proxy_policy(&second, "x")).unwrap();
        // Whatever the original allowed, and no more: a portless line means
        // the default ports for the domain, explicit lines beside it included.
        for port in [22, 80, 443, 8443] {
            assert_eq!(
                reparsed.is_allowed("api.example.com", port),
                cfg.is_allowed("api.example.com", port),
                "{port}\n{toml}"
            );
        }
    }

    #[test]
    fn an_exported_route_beside_an_ssh_entry_keeps_the_relay_authorized() {
        let (first, toml, second) = export_round_trip(
            "```agent-sandbox\n[network]\n\
             allowed_hosts = [\"github.com:22\", \"GET github.com:443/x\"]\n```\n",
        );
        assert!(toml.contains("host = \"github.com:443\""), "{toml}");
        assert!(toml.contains("\"github.com:22\""), "{toml}");
        assert_eq!(second.allow_signing, vec!["github.com".to_string()]);
        assert_eq!(sorted_lines(&first), sorted_lines(&second), "{toml}");
    }

    #[test]
    fn an_exported_route_on_ssh_ports_without_the_relay_stays_a_route() {
        // A table route on :22 compiles no allow_signing, so its line is the
        // route's own and folds back into it.
        let (first, toml, second) = export_round_trip(
            "```agent-sandbox\n[[network.allowed_routes]]\n\
             host = \"git.example.com:22,443\"\nmethod = \"GET\"\n```\n",
        );
        assert!(toml.contains("host = \"git.example.com:22,443\""), "{toml}");
        assert!(second.allow_signing.is_empty(), "{toml}");
        assert_eq!(sorted_lines(&first), sorted_lines(&second), "{toml}");
    }

    #[test]
    fn an_exported_ip_route_keeps_its_port() {
        let (first, toml, second) = export_round_trip(
            "```agent-sandbox\n[[network.allowed_routes]]\n\
             host = \"10.1.2.3:8080\"\nmethod = \"GET\"\n```\n",
        );
        assert!(toml.contains("host = \"10.1.2.3:8080\""), "{toml}");
        assert!(!toml.contains("allowed_hosts = [\"10.1.2.3"), "{toml}");
        let live = parse_policy(&format_proxy_policy(&first, "x")).unwrap();
        let again = parse_policy(&format_proxy_policy(&second, "x")).unwrap();
        for port in [80, 443, 8080] {
            assert_eq!(
                again.is_allowed("10.1.2.3", port),
                live.is_allowed("10.1.2.3", port),
                "{port}\n{toml}"
            );
        }
    }

    #[test]
    fn an_exported_route_without_its_own_allow_line_takes_what_the_policy_allows() {
        // `ctl policy allow --l7` writes a route and nothing else.
        let cfg = parse_policy(
            "allow_host *.example.com:443\n\
             allow_route\tapi.example.com\tGET\t/v1/**\n\
             allow_route\tapi.example.org\tGET\t/v1/**\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        // Reached through the wildcard, on its ports and no others.
        assert!(toml.contains("host = \"api.example.com:443\""), "{toml}");
        // Reached by nothing live, so not offered as a table that would
        // allow it on the default ports.
        assert!(!toml.contains("host = \"api.example.org"), "{toml}");
        assert!(
            toml.contains("# allow_route api.example.org GET /v1/**"),
            "{toml}"
        );
        parse_policy_file(&toml).expect("the export must re-import");
    }

    #[test]
    fn exported_route_ports_are_sorted() {
        let cfg = parse_policy(
            "allow_host a.example:8443\n\
             allow_host a.example:443\n\
             allow_route\ta.example\tGET\t/\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("host = \"a.example:443,8443\""), "{toml}");
    }

    #[test]
    fn export_marks_only_the_rule_that_actually_carries_a_secret() {
        // Two rules on one host, one secret-bearing.  The marker used to be
        // per domain, so both rules came back marked -- which is exactly the
        // over-broad model this replaces.
        let cfg = parse_policy(
            "allow_host api.github.com\n\
             secret_route\tapi.github.com\tGET\t/user/repos\n\
             allow_route\tapi.github.com\tGET\t/user/repos\n\
             allow_route\tapi.github.com\tGET\t/zen\n",
        )
        .unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert_eq!(toml.matches("secret = true").count(), 1, "{toml}");
        let (before_zen, after_zen) = toml.split_once("/zen").expect("both rules exported");
        assert!(before_zen.contains("secret = true"), "{toml}");
        assert!(!after_zen.contains("secret = true"), "{toml}");
    }

    #[test]
    fn roundtrip_allow_with_ports() {
        let cfg = parse_policy("allow_host *.jyu.fi:443\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("allowed_hosts = [\"*.jyu.fi:443\"]"), "{toml}");
        assert!(!toml.contains("allow_port"), "{toml}");
    }

    #[test]
    fn delta_contains_only_live_rules_and_deduplicates_them() {
        let active = vec![
            "allow_host github.com".to_string(),
            "allow_host api.github.com".to_string(),
            "allow_host api.github.com".to_string(),
            "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
            "deny_ip 127.0.0.0/8".to_string(),
        ];
        let base = HashSet::from(["allow_host github.com".to_string()]);
        let baseline = HashSet::from(["deny_ip 127.0.0.0/8".to_string()]);

        assert_eq!(
            policy_delta_lines(&active, &base, &baseline),
            vec![
                "allow_host api.github.com".to_string(),
                "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
            ]
        );
    }

    #[test]
    fn formatted_policy_is_valid_toml() {
        let lines = vec![
            "allow_host github.com".to_string(),
            "allow_host api.github.com:443".to_string(),
            "allow_route\tapi.github.com\tGET\t/repos/*".to_string(),
        ];
        let output = format_policy_lines_as_network_toml(&lines).expect("policy should parse");
        let value: Value = output.parse().expect("formatted output should be TOML");
        assert!(value.get("network").is_some(), "{output}");
        assert!(output.contains("allowed_hosts"), "{output}");
        assert!(output.contains("[[network.allowed_routes]]"), "{output}");
    }

    #[test]
    fn exports_a_non_default_port_range_as_an_advisory_comment() {
        let cfg = parse_policy("allow_port 8000-8100\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(
            !toml.contains("deny ="),
            "deny has no [network] TOML key: {toml}"
        );
        assert!(toml.contains("# allow_port 8000-8100"), "{toml}");
    }

    #[test]
    fn export_omits_the_built_in_deny_baseline() {
        // Built-in denies are enforced whatever AGENTS.md says and cannot be
        // changed, so exporting them would only be noise the operator has to
        // delete before pasting.
        let cfg = parse_policy("allow_host github.com\ndeny_ip 169.254.169.254/32\n").unwrap();
        let toml = format_policy_as_network_toml(&cfg);
        assert!(!toml.contains("169.254"), "{toml}");
    }

    /// The link that was missing: `cli` writes the policy file and `proxy`
    /// reads it, but nothing exercised both halves, so `allow_signing` could
    /// be emitted by one and rejected as an unknown key by the other -- which
    /// made the proxy exit 2 on every sandbox whose AGENTS.md declared an SSH
    /// allow entry.  Any new key must round-trip through here.
    #[test]
    fn every_key_the_launcher_writes_is_a_key_the_proxy_parses() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"github.com:443\", \"github.com:22\", \"10.0.0.0/8:80\"]\n\
             \n\
             [[network.allowed_routes]]\n\
             host = \"api.github.com:443\"\n\
             method = \"GET\"\n\
             path = \"/user/repos\"\n\
             secret = \"GITHUB_TOKEN\"\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        let text = format_proxy_policy(&policy, "AGENTS.md");
        let cfg = parse_policy(&text).unwrap_or_else(|e| {
            panic!("the proxy rejected the launcher's own policy: {e}\n{text}")
        });

        assert_eq!(cfg.allow_signing, vec!["github.com".to_string()]);
        assert!(cfg
            .secret_routes
            .iter()
            .any(|r| r.domain == "api.github.com"));
        assert!(cfg.is_allowed("github.com", 443), "{text}");
        assert!(cfg.is_allowed("github.com", 22), "{text}");
        assert!(cfg.is_allowed("10.1.2.3", 80), "{text}");
    }

    #[test]
    fn a_route_without_a_path_allows_every_path_for_its_method() {
        for path_line in ["", "path = \"\"\n"] {
            let agents_md = format!(
                "```agent-sandbox\n\
                 [[network.allowed_routes]]\n\
                 host = \"registry.npmjs.org:443\"\n\
                 method = \"GET\"\n\
                 {path_line}\
                 ```\n"
            );
            let policy = parse_proxy(&agents_md).expect("AGENTS.md must parse");
            assert_eq!(
                policy.allow_route,
                vec!["registry.npmjs.org\tGET\t/**".to_string()],
                "{path_line:?}"
            );

            let text = format_proxy_policy(&policy, "AGENTS.md");
            let cfg = parse_policy(&text).unwrap_or_else(|e| {
                panic!("the proxy rejected the launcher's own policy: {e}\n{text}")
            });
            for path in ["/", "/pnpm", "/@scope/name/-/name-1.0.0.tgz"] {
                assert!(
                    cfg.is_l7_allowed("registry.npmjs.org", "GET", path),
                    "{path}"
                );
            }
            assert!(!cfg.is_l7_allowed("registry.npmjs.org", "PUT", "/pnpm"));
        }
    }

    #[test]
    fn a_route_path_that_is_not_a_string_is_refused() {
        let agents_md = "```agent-sandbox\n\
             [[network.allowed_routes]]\n\
             host = \"registry.npmjs.org:443\"\n\
             method = \"GET\"\n\
             path = 1\n\
             ```\n";
        let err = parse_proxy(agents_md).expect_err("path = 1 must not compile");
        assert!(err.to_string().contains("must be a string"), "{err}");
    }

    /// Pins what `allowed_routes` compiles to, across every host shape a
    /// route can take, so the parser can be restructured against it.
    #[test]
    fn allowed_routes_compile_to_these_policy_lines() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"github.com:22,443\", \"10.0.0.0/8:80\"]\n\
             [[network.allowed_routes]]\n\
             host = \"registry.npmjs.org:443\"\n\
             method = \"GET\"\n\
             path = \"/pnpm/**\"\n\
             [[network.allowed_routes]]\n\
             host = \"registry.npmjs.org:443\"\n\
             method = \"PUT\"\n\
             [[network.allowed_routes]]\n\
             host = \"api.example.com\"\n\
             method = \"POST\"\n\
             path = \"/v1/*\"\n\
             secret = \"TOKEN\"\n\
             header = \"X-Token\"\n\
             prefix = \"Bearer \"\n\
             [[network.allowed_routes]]\n\
             host = \"*:8080,8443\"\n\
             method = \"*\"\n\
             path = \"/x\"\n\
             [[network.allowed_routes]]\n\
             host = \"192.168.1.5:8000\"\n\
             method = \"GET\"\n\
             path = \"/\"\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        let sorted = |v: &[String]| {
            let mut v = v.to_vec();
            v.sort();
            v
        };
        let strings = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // Compiled from a HashSet, so only the set is meaningful.
        assert_eq!(
            sorted(&policy.allow_host),
            strings(&[
                "api.example.com",
                "github.com:22,443",
                "registry.npmjs.org:443"
            ])
        );
        assert_eq!(
            sorted(&policy.allow_ip),
            strings(&["10.0.0.0/8:80", "192.168.1.5:8000"])
        );
        assert_eq!(sorted(&policy.allow_port), strings(&["8080", "8443"]));
        assert_eq!(policy.allow_signing, strings(&["github.com"]));
        // In rule order.
        assert_eq!(
            policy.allow_route,
            strings(&[
                "registry.npmjs.org\tGET\t/pnpm/**",
                "registry.npmjs.org\tPUT\t/**",
                "api.example.com\tPOST\t/v1/*",
                "*\t*\t/x",
                "192.168.1.5\tGET\t/",
            ])
        );
        assert_eq!(
            policy.secret_route,
            strings(&["api.example.com\tPOST\t/v1/*"])
        );
        assert_eq!(policy.default, strings(&["deny"]));
    }

    #[test]
    fn each_invalid_allowed_routes_rule_is_refused_by_name() {
        let refused = |rule: &str| {
            let agents_md = format!("```agent-sandbox\n[network]\n{rule}```\n");
            parse_proxy(&agents_md).expect_err(rule).to_string()
        };
        let route = |fields: &str| format!("[[network.allowed_routes]]\n{fields}");
        let cases = [
            (
                "allowed_routes = [\"x\"]\n".to_string(),
                "[[network.allowed_routes]][0]: must be a table",
            ),
            (
                route("host = \"a.example\"\nmethod = \"GET\"\nverb = \"GET\"\n"),
                "[[network.allowed_routes]][0]: unknown field 'verb'.",
            ),
            (
                route("method = \"GET\"\n"),
                "[[network.allowed_routes]][0]: missing required field 'host'.",
            ),
            (
                route("host = \"a.example\"\n"),
                "[[network.allowed_routes]][0]: missing required field 'method'.",
            ),
            (
                route("host = \"a.example\"\nmethod = \"get\"\n"),
                "[[network.allowed_routes]][0].method: 'get' must be uppercase",
            ),
            (
                route("host = \"a.example\"\nmethod = \"GET\"\npath = \"api\"\n"),
                "[[network.allowed_routes]][0].path: 'path' must start with '/'. Change to path = \"/api\".",
            ),
            (
                route("host = \"a.example\"\nmethod = \"GET\"\nsecret = 1\n"),
                "[[network.allowed_routes]][0].secret: must be a string",
            ),
            (
                route("host = \"-bad-.example\"\nmethod = \"GET\"\n"),
                "[[network.allowed_routes]][0].host",
            ),
            (
                route("host = \"a.example:99999\"\nmethod = \"GET\"\n"),
                "[[network.allowed_routes]][0].host",
            ),
        ];
        for (rule, expected) in cases {
            let err = refused(&rule);
            assert!(
                err.contains(expected),
                "{rule}\n  expected: {expected}\n  got: {err}"
            );
        }
    }

    #[test]
    fn a_host_allowed_outright_refuses_a_non_secret_route_on_it() {
        let refused = |network: &str| {
            parse_proxy(&format!("```agent-sandbox\n[network]\n{network}```\n"))
                .expect_err(network)
                .to_string()
        };
        let route = "[[network.allowed_routes]]\nhost = \"a.example:443\"\nmethod = \"GET\"\n";

        let err = refused(&format!("allowed_hosts = [\"a.example:443\"]\n{route}"));
        assert!(
            err.contains("host 'a.example:443' is allowed broadly"),
            "{err}"
        );
        for wildcard in ["*", "*:443"] {
            let err = refused(&format!("allowed_hosts = [\"{wildcard}\"]\n{route}"));
            assert!(err.contains("wildcard allow makes non-secret"), "{err}");
        }

        // A secret rule is not narrowing anything, so it is not a conflict.
        let agents_md = format!(
            "```agent-sandbox\n[network]\nallowed_hosts = [\"a.example:443\"]\n\
             {route}secret = \"TOKEN\"\n```\n"
        );
        parse_proxy(&agents_md).expect("a secret route beside a broad allow");
    }

    #[test]
    fn routes_from_several_blocks_compile_in_order_and_dedupe() {
        let block = |path: &str| {
            format!(
                "```agent-sandbox\n[[network.allowed_routes]]\n\
                 host = \"a.example:443\"\nmethod = \"GET\"\npath = \"{path}\"\n\
                 secret = \"TOKEN\"\n```\n"
            )
        };
        let agents_md = format!(
            "{}\nprose\n\n{}\n{}",
            block("/one"),
            block("/two"),
            block("/one")
        );
        let policy = parse_proxy(&agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_host, vec!["a.example:443".to_string()]);
        // allow_route keeps one line per rule; secret_route one per route.
        assert_eq!(
            policy.allow_route,
            vec![
                "a.example\tGET\t/one".to_string(),
                "a.example\tGET\t/two".to_string(),
                "a.example\tGET\t/one".to_string(),
            ]
        );
        assert_eq!(
            policy.secret_route,
            vec![
                "a.example\tGET\t/one".to_string(),
                "a.example\tGET\t/two".to_string(),
            ]
        );
    }

    #[test]
    fn a_route_on_the_bare_wildcard_host_adds_no_allow_entry() {
        let agents_md = "```agent-sandbox\n[[network.allowed_routes]]\n\
             host = \"*\"\nmethod = \"GET\"\n```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert!(policy.allow_host.is_empty(), "{:?}", policy.allow_host);
        assert!(policy.allow_ip.is_empty(), "{:?}", policy.allow_ip);
        assert!(policy.allow_port.is_empty(), "{:?}", policy.allow_port);
        assert_eq!(policy.allow_route, vec!["*\tGET\t/**".to_string()]);
        assert_eq!(policy.default, vec!["deny".to_string()]);
    }

    fn network(body: &str) -> String {
        format!("```agent-sandbox\n[network]\n{body}```\n")
    }

    fn compiled(policy: &ProxyPolicy) -> [Vec<String>; 6] {
        let sorted = |v: &[String]| {
            let mut v = v.to_vec();
            v.sort();
            v
        };
        [
            sorted(&policy.allow_host),
            sorted(&policy.allow_ip),
            sorted(&policy.allow_port),
            sorted(&policy.allow_signing),
            policy.allow_route.clone(),
            policy.default.clone(),
        ]
    }

    #[test]
    fn a_route_written_into_allowed_hosts_is_the_table_it_stands_for() {
        let short = parse_proxy(&network(
            "allowed_hosts = [\n\
             \"POST *.example.com:443/foo/*\",\n\
             \"GET,POST *.example.com:80,443/foo/**\",\n\
             \"PUT api.example.org\",\n\
             \"api.example.net:8443/v2/**\",\n\
             ]\n",
        ))
        .expect("the short form must parse");
        let long = parse_proxy(&network(
            "[[network.allowed_routes]]\nhost = \"*.example.com:443\"\nmethod = \"POST\"\npath = \"/foo/*\"\n\
             [[network.allowed_routes]]\nhost = \"*.example.com:80,443\"\nmethod = \"GET\"\npath = \"/foo/**\"\n\
             [[network.allowed_routes]]\nhost = \"*.example.com:80,443\"\nmethod = \"POST\"\npath = \"/foo/**\"\n\
             [[network.allowed_routes]]\nhost = \"api.example.org\"\nmethod = \"PUT\"\n\
             [[network.allowed_routes]]\nhost = \"api.example.net:8443\"\nmethod = \"*\"\npath = \"/v2/**\"\n",
        ))
        .expect("the tables must parse");
        assert_eq!(compiled(&short), compiled(&long));
        assert_eq!(
            short.allow_route,
            vec![
                "*.example.com\tPOST\t/foo/*".to_string(),
                "*.example.com\tGET\t/foo/**".to_string(),
                "*.example.com\tPOST\t/foo/**".to_string(),
                "api.example.org\tPUT\t/**".to_string(),
                "api.example.net\t*\t/v2/**".to_string(),
            ]
        );
        assert!(short.secret_route.is_empty());
    }

    #[test]
    fn plain_allowed_hosts_entries_are_not_routes() {
        for entry in [
            "github.com",
            "github.com:22,443",
            "*.example.com:443",
            "10.0.0.0/8:80",
            "10.0.0.0/8",
            "fd00::/8",
            "[::1]:4000",
            "*",
            "*:443",
        ] {
            assert!(parse_route_entry(0, entry).is_none(), "{entry}");
            let policy = parse_proxy(&network(&format!("allowed_hosts = [\"{entry}\"]\n")))
                .unwrap_or_else(|e| panic!("{entry}: {e}"));
            assert!(policy.allow_route.is_empty(), "{entry}");
        }
    }

    #[test]
    fn an_invalid_route_in_allowed_hosts_is_refused_by_name() {
        let cases = [
            ("get a.example/x", "method 'get' must be uppercase"),
            ("GET, a.example/x", "methods are separated by commas alone"),
            ("GET,,POST a.example/x", "method '' must be uppercase"),
            ("GET,GET a.example/x", "method 'GET' is listed twice"),
            ("GET,* a.example/x", "'*' already covers every method"),
            ("GET a.example /x", "unexpected space"),
            ("GET :443/x", "missing domain"),
            ("GET /x", "missing domain"),
            ("GET 10.0.0.1/x", "needs a domain name, not '10.0.0.1'"),
            ("GET 10.0.0.0/8", "needs a domain name, not '10.0.0.0'"),
            ("GET *:443/x", "needs a domain name, not '*'"),
            ("GET a.example:22/x", "cannot cover port 22"),
            ("GET a.example:20-30", "cannot cover port 22"),
            ("GET a.example:99999/x", "is not a port"),
            ("GET -bad-.example/x", "is not a valid domain name"),
        ];
        for (entry, expected) in cases {
            let err = parse_proxy(&network(&format!(
                "allowed_hosts = [\"ok.example:443\", \"{entry}\"]\n"
            )))
            .expect_err(entry)
            .to_string();
            assert!(
                err.contains(&format!("[network].allowed_hosts[1] '{entry}'")),
                "{entry}: the entry is named: {err}"
            );
            assert!(
                err.contains(expected),
                "{entry}\n  expected: {expected}\n  got: {err}"
            );
        }
    }

    #[test]
    fn a_malformed_address_keeps_the_plain_entry_error() {
        // No method list, so these were never routes: a bad address is
        // refused as before, not told to drop a method it does not have.
        for entry in ["10.0.0.0/33", "fd00::/8:80", "10.0.0.1:80/x"] {
            assert!(parse_route_entry(0, entry).is_none(), "{entry}");
            let err = parse_proxy(&network(&format!("allowed_hosts = [\"{entry}\"]\n")))
                .expect_err(entry)
                .to_string();
            assert!(err.contains("is not a valid domain name"), "{entry}: {err}");
        }
    }

    #[test]
    fn whitespace_after_the_method_list_is_any_run_of_it() {
        for entry in [
            "GET a.example/x",
            "GET\ta.example/x",
            "GET   a.example/x",
            " GET a.example/x ",
        ] {
            let policy = parse_proxy(&network(&format!("allowed_hosts = [\"{entry}\"]\n")))
                .unwrap_or_else(|e| panic!("{entry:?}: {e}"));
            assert_eq!(
                policy.allow_route,
                vec!["a.example\tGET\t/x".to_string()],
                "{entry:?}"
            );
        }
    }

    #[test]
    fn a_short_form_route_repeating_a_table_is_refused() {
        let err = parse_proxy(&network(
            "allowed_hosts = [\"GET a.example:443/x\"]\n\
             [[network.allowed_routes]]\nhost = \"a.example:443\"\nmethod = \"GET\"\npath = \"/x\"\n",
        ))
        .expect_err("the same route twice")
        .to_string();
        assert!(
            err.contains("duplicate entry 'GET a.example:443/x'"),
            "{err}"
        );
        assert!(
            err.contains("as a [[network.allowed_routes]] table"),
            "{err}"
        );
    }

    #[test]
    fn a_broad_allow_conflict_names_every_route_it_defeats() {
        let err = parse_proxy(&network(
            "allowed_hosts = [\"a.example:443\", \"GET a.example:443/x\", \"PUT a.example:443/y\"]\n\
             [[network.allowed_routes]]\nhost = \"a.example:443\"\nmethod = \"POST\"\n",
        ))
        .expect_err("a broad allow beside routes")
        .to_string();
        assert!(
            err.contains(
                "making the non-secret [[network.allowed_routes]] and the routes \
                 'GET a.example:443/x', 'PUT a.example:443/y' in allowed_hosts ineffective"
            ),
            "{err}"
        );
    }

    #[test]
    fn a_route_listed_twice_in_allowed_hosts_is_refused() {
        let err = parse_proxy(&network(
            "allowed_hosts = [\"GET a.example:443/x\", \"POST,GET a.example:443/x\"]\n",
        ))
        .expect_err("GET is listed by both entries")
        .to_string();
        assert!(
            err.contains("duplicate entry 'POST,GET a.example:443/x'"),
            "{err}"
        );
    }

    #[test]
    fn a_broad_allow_beside_a_route_in_allowed_hosts_is_refused_either_way_round() {
        for entries in [
            "\"a.example:443\", \"GET a.example:443/x\"",
            "\"GET a.example:443/x\", \"a.example:443\"",
        ] {
            let err = parse_proxy(&network(&format!("allowed_hosts = [{entries}]\n")))
                .expect_err(entries)
                .to_string();
            assert!(
                err.contains(
                    "host 'a.example:443' is allowed broadly, making the route 'GET a.example:443/x' in allowed_hosts ineffective"
                ),
                "{err}"
            );
        }
        let err = parse_proxy(&network("allowed_hosts = [\"*\", \"GET a.example/x\"]\n"))
            .expect_err("a wildcard beside a route")
            .to_string();
        assert!(
            err.contains("wildcard allow makes the routes in allowed_hosts ineffective"),
            "{err}"
        );
    }

    #[test]
    fn a_policy_file_takes_routes_in_allowed_hosts_too() {
        let policy =
            parse_policy_file("[network]\nallowed_hosts = [\"GET api.example.com:443/v1/**\"]\n")
                .expect("policy files share the parser");
        assert_eq!(policy.allow_host, vec!["api.example.com:443".to_string()]);
        assert_eq!(
            policy.allow_route,
            vec!["api.example.com\tGET\t/v1/**".to_string()]
        );
    }

    #[test]
    fn the_first_invalid_route_is_the_one_named() {
        // Every check on a rule, its host included, runs before the next rule
        // is looked at, so the error points at the earliest mistake.
        let agents_md = "```agent-sandbox\n\
             [[network.allowed_routes]]\n\
             host = \"-bad-.example\"\n\
             method = \"GET\"\n\
             [[network.allowed_routes]]\n\
             host = \"a.example\"\n\
             method = \"GET\"\n\
             secret = 1\n\
             ```\n";
        let err = parse_proxy(agents_md).expect_err("both rules are invalid");
        assert!(
            err.to_string()
                .contains("[[network.allowed_routes]][0].host"),
            "{err}"
        );
    }

    #[test]
    fn csv_ports_compile_to_one_line_and_still_authorize_the_relay() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"github.com:22,443\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_host, vec!["github.com:22,443".to_string()]);
        assert_eq!(policy.allow_signing, vec!["github.com".to_string()]);

        let text = format_proxy_policy(&policy, "AGENTS.md");
        let cfg = parse_policy(&text).unwrap_or_else(|e| {
            panic!("the proxy rejected the launcher's own policy: {e}\n{text}")
        });
        assert!(cfg.is_allowed("github.com", 22), "{text}");
        assert!(cfg.is_allowed("github.com", 443), "{text}");
        assert!(!cfg.is_allowed("github.com", 8443), "{text}");
    }

    #[test]
    fn a_range_covering_22_authorizes_the_relay_too() {
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"git.example.com:20-30\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_signing, vec!["git.example.com".to_string()]);
    }

    #[test]
    fn a_wildcard_with_csv_ports_becomes_one_allow_port_line_each() {
        // The proxy's allow_port arm takes a single port or range, so a list
        // has to be split before it is written.
        let agents_md = "```agent-sandbox\n\
             [network]\n\
             allowed_hosts = [\"*:80,443\"]\n\
             ```\n";
        let policy = parse_proxy(agents_md).expect("AGENTS.md must parse");
        assert_eq!(policy.allow_port, vec!["80".to_string(), "443".to_string()]);

        let text = format_proxy_policy(&policy, "AGENTS.md");
        assert!(text.contains("allow_port 80\n"), "{text}");
        assert!(text.contains("allow_port 443\n"), "{text}");
        parse_policy(&text)
            .unwrap_or_else(|e| panic!("the proxy rejected a split allow_port: {e}\n{text}"));
    }

    #[test]
    fn the_exit_summary_round_trips_csv_ports() {
        // `ctl policy allow github.com:22,443` writes one line, and the exit
        // summary renders every live rule back as [network] TOML. That TOML
        // has to be something AGENTS.md accepts, or the advice it prints is
        // advice that does not work.
        let cfg = parse_policy("allow_host github.com:22,443\ndefault deny\n").expect("policy");
        let toml = format_policy_as_network_toml(&cfg);
        assert!(toml.contains("github.com:22,443"), "{toml}");

        let fenced = format!("```toml agent-sandbox\n{}```\n", toml);
        let policy = parse_proxy(&fenced).unwrap_or_else(|e| {
            panic!("AGENTS.md rejected the exit summary's own TOML: {e}\n{toml}")
        });
        assert_eq!(policy.allow_signing, vec!["github.com".to_string()]);
    }

    #[test]
    fn a_port_spec_has_to_name_at_least_one_port() {
        // `split_list` drops empty elements, so without an explicit check
        // "github.com:" compiles to a line the proxy reads as a literal domain.
        for bad in ["github.com:", "github.com:22,", "github.com:,443"] {
            let agents_md = format!(
                "```agent-sandbox\n[network]\nallowed_hosts = [\"{}\"]\n```\n",
                bad
            );
            assert!(
                parse_proxy(&agents_md).is_err(),
                "'{}' should not compile",
                bad
            );
        }
    }

    #[test]
    fn is_ip_or_cidr_distinguishes_ips_from_domains() {
        assert!(is_ip_or_cidr("10.0.0.0/8"));
        assert!(is_ip_or_cidr("169.254.169.254"));
        assert!(!is_ip_or_cidr("example.com"));
    }

    #[test]
    fn parses_plain_policy_files_with_network_vocabulary() {
        let policy = parse_policy_file(
            "[network]\nallowed_hosts = [\"github.com:443\"]\n\n[[network.allowed_routes]]\nhost = \"api.github.com:443\"\nmethod = \"GET\"\npath = \"/user/repos\"\n",
        )
        .unwrap();
        assert_eq!(
            policy.allow_host,
            vec!["github.com:443", "api.github.com:443"]
        );
        assert_eq!(policy.allow_route, vec!["api.github.com\tGET\t/user/repos"]);
    }

    #[test]
    fn bracketed_ipv6_policy_targets_round_trip_to_proxy_syntax() {
        let policy = parse_policy_file(
            "[network]\nallowed_hosts = [\"[::1]:4000\"]\n",
        )
        .unwrap();
        assert_eq!(policy.allow_ip, vec!["[::1]:4000"]);
        let text = format_proxy_policy(&policy, "policy");
        agent_sandbox_proxy::policy::parse_policy(&text)
            .expect("bracketed IPv6 policy must reach the proxy");
    }

    #[test]
    fn merging_policy_files_is_additive_and_deduplicates_rules() {
        let mut first =
            parse_policy_file("[network]\nallowed_hosts = [\"github.com:443\"]\n").unwrap();
        let second = parse_policy_file(
            "[network]\nallowed_hosts = [\"github.com:443\", \"pypi.org:443\"]\n",
        )
        .unwrap();
        first.merge(second);
        assert_eq!(first.allow_host, vec!["github.com:443", "pypi.org:443"]);
    }
}
