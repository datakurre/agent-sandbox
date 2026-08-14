use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;
use crate::secret::SecretBindings;

/// A single port, or an inclusive range (`8000-8100`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

pub const DEFAULT_ALLOW_PORTS: [PortRange; 3] = [
    PortRange { start: 80, end: 80 },
    PortRange {
        start: 443,
        end: 443,
    },
    PortRange { start: 22, end: 22 },
];

#[derive(Debug, Clone)]
pub struct L7Rule {
    pub domain: String,
    pub method: String,
    pub path_pattern: String,
}

#[derive(Debug)]
pub struct ProxyConfig {
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub secret_domains: Vec<String>,
    pub allow_ips: Vec<IpNet>,
    pub deny_ips: Vec<IpNet>,
    pub default_allow: bool,
    pub default_ask: bool,
    pub ask_timeout: Duration,
    pub allow_ports: Option<Vec<PortRange>>,
    pub l7_rules: Vec<L7Rule>,
}

impl ProxyConfig {
    pub fn new(
        allow_domains: Vec<String>,
        deny_domains: Vec<String>,
        secret_domains: Vec<String>,
        allow_ips: Vec<IpNet>,
        deny_ips: Vec<IpNet>,
        allow_ports_override: Option<Vec<PortRange>>,
        default_override: Option<bool>,
        ask_override: Option<bool>,
        ask_timeout: Duration,
        l7_rules: Vec<L7Rule>,
    ) -> ProxyConfig {
        let default_allow = default_override.unwrap_or(false);
        let default_ask = ask_override.unwrap_or(false);
        let allow_ports = match allow_ports_override {
            Some(v) => Some(v),
            None if default_allow => None,
            None => Some(DEFAULT_ALLOW_PORTS.to_vec()),
        };
        ProxyConfig {
            allow_domains,
            deny_domains,
            secret_domains,
            allow_ips,
            deny_ips,
            default_allow,
            default_ask,
            ask_timeout,
            allow_ports,
            l7_rules,
        }
    }

    pub fn has_l7_rules(&self, host: &str) -> bool {
        self.l7_rules.iter().any(|r| domain_match(host, &r.domain))
    }

    pub fn is_l7_allowed(&self, host: &str, method: &str, path: &str) -> bool {
        let matching_rules: Vec<_> = self.l7_rules.iter()
            .filter(|r| domain_match(host, &r.domain))
            .collect();
        if matching_rules.is_empty() {
            return true;
        }
        matching_rules.iter().any(|r| {
            (r.method == method || r.method == "*") && crate::l7::glob_match(path, &r.path_pattern)
        })
    }

    /// Human-readable explanation for why an L7 request is denied.  Returns an
    /// empty string when the request is actually allowed, but callers should
    /// only invoke this after `is_l7_allowed` has already returned false.
    pub fn why_l7_denied(&self, host: &str, method: &str, path: &str) -> String {
        let matching_rules: Vec<_> = self.l7_rules.iter()
            .filter(|r| domain_match(host, &r.domain))
            .collect();
        if matching_rules.is_empty() {
            return format!("no L7 allow rules for domain {:?}", host);
        }
        let method_matches: Vec<_> = matching_rules.iter()
            .filter(|r| r.method == method || r.method == "*")
            .collect();
        if method_matches.is_empty() {
            let methods: Vec<_> = matching_rules.iter().map(|r| r.method.as_str()).collect();
            return format!(
                "domain {:?} has L7 rules but none allow method {:?}; configured methods: {}",
                host, method, methods.join(", ")
            );
        }
        let patterns: Vec<_> = method_matches.iter().map(|r| r.path_pattern.as_str()).collect();
        format!(
            "domain {:?} allows method {:?} but path {:?} does not match any configured pattern; configured patterns: {}",
            host, method, path, patterns.join(", ")
        )
    }

    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        for d in &self.allow_domains {
            out.push(format!("allow_domains {}", d));
        }
        for d in &self.deny_domains {
            out.push(format!("deny_domains {}", d));
        }
        for d in &self.secret_domains {
            out.push(format!("secret_domains {}", d));
        }
        for n in &self.allow_ips {
            out.push(format!("allow_ips {}", n));
        }
        for n in &self.deny_ips {
            out.push(format!("deny_ips {}", n));
        }
        if let Some(ranges) = &self.allow_ports {
            for r in ranges {
                out.push(format!("allow_ports {}", r));
            }
        }
        for r in &self.l7_rules {
            out.push(format!("allow_l7\t{}\t{}\t{}", r.domain, r.method, r.path_pattern));
        }
        out.push(format!(
            "default {}",
            if self.default_ask {
                "ask"
            } else if self.default_allow {
                "allow"
            } else {
                "deny"
            }
        ));
        out
    }
}

pub fn split_list(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
}

pub fn parse_csv(s: &str) -> Vec<String> {
    split_list(s).map(|s| s.to_ascii_lowercase()).collect()
}

pub fn parse_net(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    match s.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(ip)),
        Err(e) => Err(format!(
            "{:?} is not an IP address or CIDR block: {}",
            s, e
        )),
    }
}

pub fn parse_csv_ips(s: &str) -> Result<Vec<IpNet>, String> {
    split_list(s).map(parse_net).collect()
}

pub fn parse_port_range(s: &str) -> Result<PortRange, String> {
    let (start, end) = match s.split_once('-') {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    let parse_one = |p: &str| -> Result<u16, String> {
        p.parse::<u16>()
            .ok()
            .filter(|&n| n != 0)
            .ok_or_else(|| format!("{:?} is not a port in 1-65535", p))
    };
    let start = parse_one(start)?;
    let end = parse_one(end)?;
    if start > end {
        return Err(format!("{:?} has start > end", s));
    }
    Ok(PortRange { start, end })
}

pub fn parse_csv_ports(s: &str) -> Result<Vec<PortRange>, String> {
    split_list(s).map(parse_port_range).collect()
}

pub fn parse_policy(text: &str, ask_timeout: Duration) -> Result<ProxyConfig, String> {
    let mut allow_domains = Vec::new();
    let mut deny_domains = Vec::new();
    let mut secret_domains = Vec::new();
    let mut allow_ips = Vec::new();
    let mut deny_ips = Vec::new();
    let mut allow_ports_override: Option<Vec<PortRange>> = None;
    let mut default_override = None;
    let mut ask_override = None;
    let mut l7_rules = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = i + 1;
        let (key, rest_of_line) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{}: {:?} is not KEY VALUE", lineno, line))?;
        let value = rest_of_line.trim();
        if value.is_empty() {
            return Err(format!("{}: {} has no value", lineno, key));
        }

        // allow_l7 is intentionally tab-separated (domain<TAB>method<TAB>path),
        // so it is exempt from the "no whitespace in values" rule that guards
        // every other key against the old space-separated encoding.
        if key != "allow_l7" && value.chars().any(char::is_whitespace) {
            return Err(format!("{}: {}: {:?} contains whitespace", lineno, key, value));
        }

        match key {
            "allow_domains" => allow_domains.push(value.to_ascii_lowercase()),
            "deny_domains" => deny_domains.push(value.to_ascii_lowercase()),
            "secret_domains" => secret_domains.push(value.to_ascii_lowercase()),
            "allow_ips" => allow_ips
                .push(parse_net(value).map_err(|e| format!("{}: allow_ips: {}", lineno, e))?),
            "deny_ips" => deny_ips
                .push(parse_net(value).map_err(|e| format!("{}: deny_ips: {}", lineno, e))?),
            "allow_ports" => {
                let r = parse_port_range(value)
                    .map_err(|e| format!("{}: allow_ports: {}", lineno, e))?;
                allow_ports_override.get_or_insert_with(Vec::new).push(r);
            }
            "allow_l7" => {
                let parts: Vec<&str> = value.splitn(3, '\t').collect();
                if parts.len() != 3 {
                    return Err(format!("{}: allow_l7 expects 3 tab-separated fields", lineno));
                }
                l7_rules.push(L7Rule {
                    domain: parts[0].to_lowercase(),
                    method: parts[1].to_string(),
                    path_pattern: parts[2].to_string(),
                });
            }
            "default" => match value {
                "allow" | "deny" | "ask" => {
                    default_override = Some(value != "deny");
                    ask_override = Some(value == "ask");
                }
                _ => return Err(format!("{}: default: expected 'allow', 'deny' or 'ask', got {:?}", lineno, value)),
            },
            other => return Err(format!("{}: unknown key {:?}", lineno, other)),
        }
    }

    Ok(ProxyConfig::new(
        allow_domains,
        deny_domains,
        secret_domains,
        allow_ips,
        deny_ips,
        allow_ports_override,
        default_override,
        ask_override,
        ask_timeout,
        l7_rules,
    ))
}

pub fn load_policy(path: &str, ask_timeout: Duration) -> Result<ProxyConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {}", path, e))?;
    parse_policy(&text, ask_timeout).map_err(|e| format!("{}:{}", path, e))
}

pub fn fold_ipv6(ip: std::net::Ipv6Addr) -> IpAddr {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    let seg = ip.segments();
    if seg[0..6] == [0, 0, 0, 0, 0, 0] && (seg[6] != 0 || seg[7] > 1) {
        let o = ip.octets();
        return IpAddr::V4(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    IpAddr::V6(ip)
}

pub fn normalize_host(host: &str) -> Option<String> {
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => Some(format!("[{}]", fold_ipv6(ip))),
            Err(_) => None,
        };
    }
    if let Ok(IpAddr::V6(ip)) = host.parse::<IpAddr>() {
        return Some(fold_ipv6(ip).to_string());
    }
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }

    if host.starts_with('.') {
        return None;
    }
    let stripped = host.strip_suffix('.').unwrap_or(host);
    if stripped.is_empty() || stripped.contains("..") {
        return None;
    }
    if !stripped
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return None;
    }
    Some(stripped.to_string())
}

pub fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

pub fn overlap_candidates(pattern: &str) -> [String; 2] {
    match pattern.strip_prefix("*.") {
        Some(base) => [base.to_string(), format!("sample.{}", base)],
        None => [pattern.to_string(), pattern.to_string()],
    }
}

pub fn patterns_overlap(a: &str, b: &str) -> bool {
    let [a0, a1] = overlap_candidates(a);
    let [b0, b1] = overlap_candidates(b);
    domain_match(&a0, b) || domain_match(&a1, b) || domain_match(&b0, a) || domain_match(&b1, a)
}

pub fn has_backed_secret_domains(config: &ProxyConfig, secrets: &SecretBindings) -> bool {
    config.secret_domains.iter().any(|policy_pattern| {
        secrets
            .entries()
            .iter()
            .any(|binding| patterns_overlap(policy_pattern, &binding.domain))
    })
}

impl ProxyConfig {
    pub fn is_allowed_domain(&self, domain: &str) -> bool {
        let mut best_len: i32 = -1;
        let mut allowed = self.default_allow;

        for p in &self.allow_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                allowed = true;
            }
        }

        for p in &self.deny_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                allowed = false;
            }
        }

        allowed
    }

    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut allowed = self.default_allow;

        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = true;
            }
        }

        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                allowed = false;
            }
        }

        allowed
    }

    pub fn is_denied_address(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut denied = false;

        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = true;
            }
        }

        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) >= best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = false;
            }
        }

        denied
    }

    pub fn is_allowed_target(&self, host: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        match host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.is_allowed_ip(ip),
            Err(_) => self.is_allowed_domain(&host),
        }
    }

    pub fn is_allowed_port(&self, port: u16) -> bool {
        self.allow_ports
            .as_ref()
            .map_or(true, |ranges| ranges.iter().any(|r| r.contains(port)))
    }

    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        self.is_allowed_target(host) && self.is_allowed_port(port)
    }

    pub fn is_secret_domain(&self, host: &str) -> bool {
        let host = match normalize_host(host) {
            Some(h) => h,
            None => return false,
        };
        if host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().is_ok() {
            return false;
        }
        self.secret_domains
            .iter()
            .any(|pattern| domain_match(&host, pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_reads_allow_l7_rules() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text, Duration::from_secs(300)).expect("parse should succeed");
        assert_eq!(cfg.l7_rules.len(), 1);
        assert_eq!(cfg.l7_rules[0].domain, "repo.kopla.jyu.fi");
        assert_eq!(cfg.l7_rules[0].method, "GET");
        assert_eq!(cfg.l7_rules[0].path_pattern, "/api/pypi/pypi");
        assert!(cfg.is_l7_allowed("repo.kopla.jyu.fi", "GET", "/api/pypi/pypi"));
        assert!(!cfg.is_l7_allowed("repo.kopla.jyu.fi", "POST", "/api/pypi/pypi"));
    }

    #[test]
    fn parse_policy_rejects_whitespace_in_other_values() {
        let text = "allow_ips 10.0.0.0/8 192.168.0.0/16\n";
        let err = parse_policy(text, Duration::from_secs(300)).unwrap_err();
        assert!(err.contains("whitespace"), "unexpected error: {err}");
    }

    #[test]
    fn why_l7_denied_explains_no_rules_for_domain() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text, Duration::from_secs(300)).expect("parse should succeed");
        let reason = cfg.why_l7_denied("other.example.com", "GET", "/");
        assert!(reason.contains("no L7 allow rules for domain"), "{reason}");
        assert!(reason.contains("other.example.com"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_method_mismatch() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text, Duration::from_secs(300)).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "POST", "/api/pypi/pypi");
        assert!(reason.contains("none allow method"), "{reason}");
        assert!(reason.contains("POST"), "{reason}");
        assert!(reason.contains("GET"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_path_mismatch() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text, Duration::from_secs(300)).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "GET", "/packages/wheel.whl");
        assert!(reason.contains("path"), "{reason}");
        assert!(reason.contains("/packages/wheel.whl"), "{reason}");
        assert!(reason.contains("/api/pypi/pypi"), "{reason}");
    }
}
