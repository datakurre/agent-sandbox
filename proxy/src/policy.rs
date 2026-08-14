use ipnet::IpNet;
use std::net::IpAddr;
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
        l7_rules: Vec<L7Rule>,
    ) -> ProxyConfig {
        let default_allow = default_override.unwrap_or(false);
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
            if self.default_allow { "allow" } else { "deny" }
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

pub fn parse_policy(text: &str) -> Result<ProxyConfig, String> {
    let mut allow_domains = Vec::new();
    let mut deny_domains = Vec::new();
    let mut secret_domains = Vec::new();
    let mut allow_ips = Vec::new();
    let mut deny_ips = Vec::new();
    let mut allow_ports_override: Option<Vec<PortRange>> = None;
    let mut default_override = None;
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
                "allow" | "deny" => default_override = Some(value == "allow"),
                "ask" => return Err(format!(
                    "{}: default: 'ask' is no longer supported; use 'allow' or 'deny', and watch denied requests live via `agent-sandbox ctl tui`",
                    lineno
                )),
                _ => return Err(format!("{}: default: expected 'allow' or 'deny', got {:?}", lineno, value)),
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
        l7_rules,
    ))
}

pub fn load_policy(path: &str) -> Result<ProxyConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {}", path, e))?;
    parse_policy(&text).map_err(|e| format!("{}:{}", path, e))
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

    /// Explains why `is_allowed_domain` returned false for `domain`. Mirrors
    /// its longest-match-wins loop exactly, tracking which pattern actually
    /// decided the verdict rather than just the outcome, so the explanation
    /// can never name a pattern other than the real one. Callers must only
    /// invoke this once denial is already confirmed.
    fn why_domain_denied(&self, domain: &str) -> String {
        let mut best_len: i32 = -1;
        let mut winner: Option<(&str, bool)> = None;
        for p in &self.allow_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                winner = Some((p.as_str(), false));
            }
        }
        for p in &self.deny_domains {
            if domain_match(domain, p) && p.len() as i32 > best_len {
                best_len = p.len() as i32;
                winner = Some((p.as_str(), true));
            }
        }
        match winner {
            Some((pattern, true)) => format!("matches deny_domains {:?}", pattern),
            Some((pattern, false)) => format!("matches allow_domains {:?}", pattern),
            None => format!("no allow_domains rule matches {:?}; default is deny", domain),
        }
    }

    /// Explains why `is_allowed_ip` returned false for `ip`. Same mirroring
    /// approach as `why_domain_denied`.
    fn why_ip_denied(&self, ip: IpAddr) -> String {
        let mut best_prefix: i32 = -1;
        let mut winner: Option<(&IpNet, bool)> = None;
        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some((net, false));
            }
        }
        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some((net, true));
            }
        }
        match winner {
            Some((net, true)) => format!("matches deny_ips {}", net),
            Some((net, false)) => format!("matches allow_ips {}", net),
            None => format!("no allow_ips rule matches {}; default is deny", ip),
        }
    }

    /// Explains why `is_allowed_target` returned false for `host`. Dispatches
    /// to the domain or IP explanation exactly like `is_allowed_target` picks
    /// between `is_allowed_domain`/`is_allowed_ip`.
    pub fn why_target_denied(&self, host: &str) -> String {
        let normalized = match normalize_host(host) {
            Some(h) => h,
            None => return format!("{:?} is not a valid host", host),
        };
        match normalized.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.why_ip_denied(ip),
            Err(_) => self.why_domain_denied(&normalized),
        }
    }

    /// Explains why `is_allowed_port` returned false for `port`.
    pub fn why_port_denied(&self, port: u16) -> String {
        match &self.allow_ports {
            Some(ranges) => {
                let list: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
                format!("port {} is not in allow_ports (configured: {})", port, list.join(", "))
            }
            None => format!("port {} is not allowed", port),
        }
    }

    /// Explains why `is_denied_address` returned true for a *resolved*
    /// address. Distinct algorithm from `why_ip_denied`/`is_allowed_ip`: a
    /// `deny_ips` entry wins on a strictly greater prefix, but an `allow_ips`
    /// entry of *equal or greater* specificity overrides it (see
    /// `is_denied_address`'s own comment for why the tie-break is
    /// asymmetric). Mirrors that exact algorithm so the explanation can't
    /// disagree with the real decision.
    pub fn why_address_denied(&self, ip: IpAddr) -> String {
        let mut best_prefix: i32 = -1;
        let mut winner: Option<&IpNet> = None;
        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = Some(net);
            }
        }
        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) >= best_prefix {
                best_prefix = net.prefix_len() as i32;
                winner = None;
            }
        }
        match winner {
            Some(net) => format!("resolved address {} matches deny_ips {}", ip, net),
            None => format!("resolved address {} has no matching deny_ips rule", ip),
        }
    }

    /// Full explanation for a pre-resolution deny (host or port, whichever is
    /// responsible), for `is_allowed(host, port)` returning false. Callers
    /// must only invoke this once denial is already confirmed.
    pub fn why_denied(&self, host: &str, port: u16) -> String {
        if !self.is_allowed_port(port) {
            self.why_port_denied(port)
        } else {
            self.why_target_denied(host)
        }
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
        let cfg = parse_policy(text).expect("parse should succeed");
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
        let err = parse_policy(text).unwrap_err();
        assert!(err.contains("whitespace"), "unexpected error: {err}");
    }

    #[test]
    fn why_l7_denied_explains_no_rules_for_domain() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("other.example.com", "GET", "/");
        assert!(reason.contains("no L7 allow rules for domain"), "{reason}");
        assert!(reason.contains("other.example.com"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_method_mismatch() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "POST", "/api/pypi/pypi");
        assert!(reason.contains("none allow method"), "{reason}");
        assert!(reason.contains("POST"), "{reason}");
        assert!(reason.contains("GET"), "{reason}");
    }

    #[test]
    fn why_l7_denied_explains_path_mismatch() {
        let text = "default deny\nallow_l7\trepo.kopla.jyu.fi\tGET\t/api/pypi/pypi\n";
        let cfg = parse_policy(text).expect("parse should succeed");
        let reason = cfg.why_l7_denied("repo.kopla.jyu.fi", "GET", "/packages/wheel.whl");
        assert!(reason.contains("path"), "{reason}");
        assert!(reason.contains("/packages/wheel.whl"), "{reason}");
        assert!(reason.contains("/api/pypi/pypi"), "{reason}");
    }

    #[test]
    fn default_ask_line_produces_an_actionable_error() {
        let err = parse_policy("default ask\n").unwrap_err();
        assert!(err.contains("no longer supported"), "{err}");
        assert!(err.contains("ctl tui"), "{err}");
    }

    #[test]
    fn why_target_denied_names_the_winning_deny_domains_pattern() {
        let cfg = parse_policy("allow_domains *.example.com\ndeny_domains internal.example.com\n").unwrap();
        assert!(!cfg.is_allowed_target("internal.example.com"));
        let reason = cfg.why_target_denied("internal.example.com");
        assert!(reason.contains("deny_domains"), "{reason}");
        assert!(reason.contains("internal.example.com"), "{reason}");
    }

    #[test]
    fn why_target_denied_explains_the_implicit_default_deny() {
        let cfg = parse_policy("allow_domains github.com\n").unwrap();
        assert!(!cfg.is_allowed_target("evil.example.com"));
        let reason = cfg.why_target_denied("evil.example.com");
        assert!(reason.contains("no allow_domains rule matches"), "{reason}");
        assert!(reason.contains("default is deny"), "{reason}");
    }

    #[test]
    fn why_target_denied_names_the_winning_deny_ips_pattern() {
        let cfg = parse_policy("allow_ips 10.0.0.0/8\ndeny_ips 10.5.0.0/16\n").unwrap();
        let ip: IpAddr = "10.5.1.1".parse().unwrap();
        assert!(!cfg.is_allowed_target("10.5.1.1"));
        let reason = cfg.why_target_denied("10.5.1.1");
        assert!(reason.contains("deny_ips"), "{reason}");
        assert!(reason.contains(&ip.to_string()) || reason.contains("10.5.0.0/16"), "{reason}");
    }

    #[test]
    fn why_port_denied_lists_the_configured_ranges() {
        let cfg = parse_policy("allow_domains github.com\nallow_ports 443\n").unwrap();
        assert!(!cfg.is_allowed_port(8443));
        let reason = cfg.why_port_denied(8443);
        assert!(reason.contains("8443"), "{reason}");
        assert!(reason.contains("443"), "{reason}");
    }

    #[test]
    fn why_address_denied_names_the_matching_baseline_range() {
        let cfg = parse_policy("allow_domains github.com\ndeny_ips 169.254.0.0/16\n").unwrap();
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(cfg.is_denied_address(ip));
        let reason = cfg.why_address_denied(ip);
        assert!(reason.contains("deny_ips"), "{reason}");
        assert!(reason.contains("169.254.0.0/16"), "{reason}");
    }

    #[test]
    fn why_denied_prioritizes_the_port_reason_over_the_domain_reason() {
        let cfg = parse_policy("allow_domains github.com\nallow_ports 443\n").unwrap();
        assert!(cfg.is_allowed_target("github.com"));
        assert!(!cfg.is_allowed("github.com", 8443));
        let reason = cfg.why_denied("github.com", 8443);
        assert!(reason.contains("port"), "{reason}");
    }
}
