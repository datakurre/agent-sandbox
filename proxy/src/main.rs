#![forbid(unsafe_code)]

//! Forward proxy for the agent-sandbox sidecar.
//!
//! Usage: agent-sandbox-proxy ALLOW_DOMAINS DENY_DOMAINS ALLOW_IPS DENY_IPS [LOG_PATH]
//!
//! The four policy arguments are comma-separated; an empty LOG_PATH (or none)
//! disables connection metering.

use ipnet::IpNet;
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Read timeout on proxied sockets.  This is only a liveness tick so a blocked
/// read can be retried, *not* an idle cap: a stream that goes quiet for longer
/// (a streaming completion waiting on the model, a slow git server) must not be
/// severed.  See `pump`.
const IO_TICK: Duration = Duration::from_secs(300);
/// A client that opens a connection and never sends a request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TTL: Duration = Duration::from_secs(60);
/// How long after process start the resolve/connect paths keep retrying.  The
/// sidecar's network is not always up the instant the proxy binds, so early
/// connections absorb the race; steady-state connections must not pay for it.
const STARTUP_GRACE: Duration = Duration::from_secs(10);
const BUF_SIZE: usize = 64 * 1024;
const HEAD_MAX: usize = 8192;
const DNS_CACHE_MAX: usize = 512;

// ── Policy ──────────────────────────────────────────────────────────────────

struct ProxyConfig {
    allow_domains: Vec<String>,
    deny_domains: Vec<String>,
    allow_ips: Vec<IpNet>,
    deny_ips: Vec<IpNet>,
    default_allow: bool,
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_csv_ips(s: &str) -> Vec<IpNet> {
    s.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect()
}

/// Both arguments must already be lowercase.
fn domain_match(domain: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&pattern[1..]),
        None => domain == pattern,
    }
}

impl ProxyConfig {
    /// More specific wins: the longest matching pattern decides.  On an exact
    /// tie between an allow and a deny rule, allow wins.
    fn is_allowed_domain(&self, domain: &str) -> bool {
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

    /// More specific wins: the longest matching CIDR prefix decides.
    fn is_allowed_ip(&self, ip: IpAddr) -> bool {
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

    /// Whether an address is explicitly denied.
    ///
    /// Deliberately *not* `!is_allowed_ip(ip)`: this runs on the addresses a
    /// hostname resolved to, after the name itself already passed policy, so
    /// the deny-by-default fallback must not apply — under an allow list of
    /// domains no address would ever be listed and every connection would be
    /// rejected.  Only an explicit `deny_ips` match counts, and a
    /// more-specific `allow_ips` rule still overrides it.
    fn is_denied_address(&self, ip: IpAddr) -> bool {
        let mut best_prefix: i32 = -1;
        let mut denied = false;

        for net in &self.deny_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = true;
            }
        }

        for net in &self.allow_ips {
            if net.contains(&ip) && (net.prefix_len() as i32) > best_prefix {
                best_prefix = net.prefix_len() as i32;
                denied = false;
            }
        }

        denied
    }

    /// `host` is the literal target from the request line, already lowercased.
    fn is_allowed(&self, host: &str) -> bool {
        match host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            Ok(ip) => self.is_allowed_ip(ip),
            Err(_) => self.is_allowed_domain(host),
        }
    }
}

// ── Name resolution ─────────────────────────────────────────────────────────

/// Agents reconnect to the same handful of hosts constantly, so a short-TTL
/// cache removes a resolver round trip from most connections.
struct Resolver {
    cache: Mutex<HashMap<String, (Vec<SocketAddr>, Instant)>>,
}

impl Resolver {
    fn new() -> Self {
        Resolver {
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn resolve(&self, host: &str, port: u16, retry_until: Instant) -> Vec<SocketAddr> {
        let key = format!("{}:{}", host, port);

        if let Ok(cache) = self.cache.lock() {
            if let Some((addrs, cached_at)) = cache.get(&key) {
                if cached_at.elapsed() < DNS_TTL {
                    return addrs.clone();
                }
            }
        }

        let mut addrs: Vec<SocketAddr> = Vec::new();
        loop {
            if let Ok(found) = key.to_socket_addrs() {
                addrs = found.collect();
                if !addrs.is_empty() {
                    break;
                }
            }
            if Instant::now() >= retry_until {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !addrs.is_empty() {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= DNS_CACHE_MAX {
                    cache.clear();
                }
                cache.insert(key, (addrs.clone(), Instant::now()));
            }
        }
        addrs
    }
}

// ── Metering ────────────────────────────────────────────────────────────────

/// One JSON line per finished connection, consumed by the launcher to render
/// the `--meter-network` summary.  Cheap enough to leave on: a few hundred
/// bytes per connection, versus the full-payload packet capture it replaces.
struct MetricsLog {
    file: Mutex<File>,
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

impl MetricsLog {
    fn open(path: &str) -> Option<Arc<MetricsLog>> {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Some(Arc::new(MetricsLog {
                file: Mutex::new(f),
            })),
            Err(e) => {
                eprintln!("proxy: cannot open metrics log {}: {}", path, e);
                None
            }
        }
    }

    fn record(&self, host: &str, port: u16, verdict: &str, err: Option<&str>, up: u64, down: u64, ms: u128) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut line = format!(
            "{{\"ts\":{},\"host\":\"{}\",\"port\":{},\"verdict\":\"{}\",\"up\":{},\"down\":{},\"ms\":{}",
            ts,
            json_escape(host),
            port,
            verdict,
            up,
            down,
            ms
        );
        if let Some(e) = err {
            line.push_str(&format!(",\"err\":\"{}\"", e));
        }
        line.push_str("}\n");

        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

// ── Connection handling ─────────────────────────────────────────────────────

struct Shared {
    config: ProxyConfig,
    resolver: Resolver,
    metrics: Option<Arc<MetricsLog>>,
    /// Instant until which the resolve/connect paths keep retrying.
    startup_until: Instant,
}

impl Shared {
    fn record(&self, host: &str, port: u16, verdict: &str, err: Option<&str>, up: u64, down: u64, ms: u128) {
        if let Some(m) = &self.metrics {
            m.record(host, port, verdict, err, up, down, ms);
        }
    }
}

/// Copy `src` into `dst` until either side is done, returning the byte count.
///
/// A read timeout means "nothing to say yet", not "hang up" — treating it as
/// fatal severs long-lived idle streams.  On a real end-of-stream the write
/// half of `dst` is shut down so the peer observes EOF immediately, rather
/// than the connection lingering until the opposite direction times out.
fn pump(mut src: TcpStream, mut dst: TcpStream) -> u64 {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
    total
}

/// Read until the end of the HTTP request head.  A request line can be split
/// across TCP segments, so a single `read` is not enough to parse against.
fn read_head(sock: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    loop {
        if n == buf.len() {
            return Some(n);
        }
        match sock.read(&mut buf[n..]) {
            Ok(0) => return if n > 0 { Some(n) } else { None },
            Ok(k) => {
                // Rescan only the new bytes plus the 3-byte overlap.
                let scan_from = n.saturating_sub(3);
                n += k;
                if buf[scan_from..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(n);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return if n > 0 { Some(n) } else { None },
        }
    }
}

fn connect_any(addrs: &[SocketAddr], retry_until: Instant) -> Option<TcpStream> {
    loop {
        for addr in addrs {
            if let Ok(s) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
                return Some(s);
            }
        }
        if Instant::now() >= retry_until {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn handle_client(mut client_sock: TcpStream, shared: Arc<Shared>) {
    let started = Instant::now();
    let _ = client_sock.set_nodelay(true);
    let _ = client_sock.set_read_timeout(Some(HEAD_TIMEOUT));

    let mut req_buf = [0u8; HEAD_MAX];
    let n = match read_head(&mut client_sock, &mut req_buf) {
        Some(n) => n,
        None => return,
    };

    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        let _ = client_sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    let method = parts[0];
    let mut url = parts[1];

    let host;
    let port: u16;

    if method == "CONNECT" {
        if let Some((h, p)) = url.rsplit_once(':') {
            host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(443);
        } else {
            host = url.to_ascii_lowercase();
            port = 443;
        }
    } else {
        if let Some(idx) = url.find("://") {
            url = &url[idx + 3..];
        }
        let url_no_path = url.split('/').next().unwrap_or("");
        if let Some((h, p)) = url_no_path.rsplit_once(':') {
            host = h.to_ascii_lowercase();
            port = p.parse().unwrap_or(80);
        } else {
            host = url_no_path.to_ascii_lowercase();
            port = 80;
        }
    }

    if host.is_empty() {
        let _ = client_sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }

    if !shared.config.is_allowed(&host) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{}", host, port);
        shared.record(&host, port, "deny", None, 0, 0, started.elapsed().as_millis());
        return;
    }

    let addrs = shared.resolver.resolve(&host, port, shared.startup_until);
    if addrs.is_empty() {
        let _ = client_sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        eprintln!("proxy: dns failure {}:{}", host, port);
        shared.record(&host, port, "error", Some("dns"), 0, 0, started.elapsed().as_millis());
        return;
    }

    // The policy check above ran on the name.  Re-check what it actually
    // resolves to, so a denied address cannot be reached via an allowed (or
    // merely unlisted) hostname.
    if let Some(bad) = addrs.iter().find(|a| shared.config.is_denied_address(a.ip())) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        eprintln!("proxy: deny {}:{} (resolves to denied address {})", host, port, bad.ip());
        shared.record(&host, port, "deny", Some("address"), 0, 0, started.elapsed().as_millis());
        return;
    }

    let mut remote_sock = match connect_any(&addrs, shared.startup_until) {
        Some(s) => s,
        None => {
            let _ = client_sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            eprintln!("proxy: connect failure {}:{}", host, port);
            shared.record(&host, port, "error", Some("connect"), 0, 0, started.elapsed().as_millis());
            return;
        }
    };

    // Without this both directions pay a Nagle/delayed-ACK stall on every
    // request/response turn: TLS handshakes, HTTP/2 frames, git negotiation.
    let _ = remote_sock.set_nodelay(true);
    let _ = remote_sock.set_read_timeout(Some(IO_TICK));
    let _ = client_sock.set_read_timeout(Some(IO_TICK));

    // Bytes forwarded before the pumps take over, so they still show up in the
    // metered "sent" total.
    let mut head_up: u64 = 0;

    if method == "CONNECT" {
        if client_sock
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        // Forward any data that arrived alongside the CONNECT head.
        if let Some(pos) = req_buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            let extra = &req_buf[pos + 4..n];
            if !extra.is_empty() {
                if remote_sock.write_all(extra).is_err() {
                    return;
                }
                head_up += extra.len() as u64;
            }
        }
    } else {
        if remote_sock.write_all(&req_buf[..n]).is_err() {
            return;
        }
        head_up += n as u64;
    }

    let (client_read, remote_write) = match (client_sock.try_clone(), remote_sock.try_clone()) {
        (Ok(c), Ok(r)) => (c, r),
        _ => {
            eprintln!("proxy: cannot duplicate sockets for {}:{}", host, port);
            shared.record(&host, port, "error", Some("fd"), 0, 0, started.elapsed().as_millis());
            return;
        }
    };

    // One direction inline: two threads per connection instead of three.
    let upstream = thread::spawn(move || pump(client_read, remote_write));
    let down = pump(remote_sock, client_sock);
    let up = head_up + upstream.join().unwrap_or(0);

    shared.record(&host, port, "allow", None, up, down, started.elapsed().as_millis());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");

    let allow_domains = parse_csv(arg(1));
    let deny_domains = parse_csv(arg(2));
    let allow_ips = parse_csv_ips(arg(3));
    let deny_ips = parse_csv_ips(arg(4));
    let log_path = arg(5);

    // An allow list makes the policy deny-by-default; deny lists alone leave it
    // allow-by-default.
    let default_allow = allow_domains.is_empty() && allow_ips.is_empty();

    let metrics = if log_path.is_empty() {
        None
    } else {
        MetricsLog::open(log_path)
    };

    let shared = Arc::new(Shared {
        config: ProxyConfig {
            allow_domains,
            deny_domains,
            allow_ips,
            deny_ips,
            default_allow,
        },
        resolver: Resolver::new(),
        metrics,
        startup_until: Instant::now() + STARTUP_GRACE,
    });

    let listener = match TcpListener::bind("0.0.0.0:8888") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("proxy: cannot bind 0.0.0.0:8888: {}", e);
            std::process::exit(1);
        }
    };

    if let Ok(mut f) = File::create("/sidecar_shared/ready") {
        let _ = f.write_all(b"ready\n");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let shared = Arc::clone(&shared);
                // The pump buffers live on the heap, so these threads need very
                // little stack; the default 8 MiB reservation each adds up.
                let spawned = thread::Builder::new()
                    .stack_size(256 * 1024)
                    .spawn(move || handle_client(client, shared));
                if spawned.is_err() {
                    eprintln!("proxy: cannot spawn handler thread");
                }
            }
            Err(_) => {
                // Transient accept errors (fd pressure) must not busy-spin.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allow_d: &str, deny_d: &str, allow_i: &str, deny_i: &str) -> ProxyConfig {
        let allow_domains = parse_csv(allow_d);
        let allow_ips = parse_csv_ips(allow_i);
        let default_allow = allow_domains.is_empty() && allow_ips.is_empty();
        ProxyConfig {
            allow_domains,
            deny_domains: parse_csv(deny_d),
            allow_ips,
            deny_ips: parse_csv_ips(deny_i),
            default_allow,
        }
    }

    #[test]
    fn exact_domain_does_not_match_subdomains() {
        assert!(domain_match("github.com", "github.com"));
        assert!(!domain_match("status.github.com", "github.com"));
    }

    #[test]
    fn wildcard_matches_base_and_subdomains() {
        assert!(domain_match("github.com", "*.github.com"));
        assert!(domain_match("api.github.com", "*.github.com"));
        assert!(!domain_match("notgithub.com", "*.github.com"));
    }

    #[test]
    fn allow_list_makes_policy_deny_by_default() {
        let c = cfg("github.com", "", "", "");
        assert!(c.is_allowed("github.com"));
        assert!(!c.is_allowed("example.com"));
    }

    #[test]
    fn deny_list_alone_leaves_policy_allow_by_default() {
        let c = cfg("", "example.com", "", "");
        assert!(c.is_allowed("github.com"));
        assert!(!c.is_allowed("example.com"));
    }

    #[test]
    fn more_specific_domain_wins() {
        let c = cfg("api.github.com", "*.github.com", "", "");
        assert!(c.is_allowed("api.github.com"));
        assert!(!c.is_allowed("gist.github.com"));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let c = cfg("api.github.com", "", "", "");
        assert!(c.is_allowed("API.GitHub.com".to_ascii_lowercase().as_str()));
    }

    #[test]
    fn longer_cidr_prefix_wins() {
        let c = cfg("", "", "10.0.0.0/8", "10.1.0.0/24");
        assert!(c.is_allowed("10.2.0.1"));
        assert!(!c.is_allowed("10.1.0.5"));
    }

    #[test]
    fn bracketed_ipv6_literal_is_matched_as_an_address() {
        let c = cfg("", "", "", "::1/128");
        assert!(!c.is_allowed("[::1]"));
    }

    #[test]
    fn resolved_address_check_ignores_the_deny_by_default_fallback() {
        // An allow list of domains and no allow_ips: every resolved address is
        // unlisted, and must still be reachable.
        let c = cfg("github.com", "", "", "");
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn resolved_address_check_honours_explicit_deny_ips() {
        let c = cfg("internal.example.com", "", "", "169.254.0.0/16");
        assert!(c.is_denied_address("169.254.169.254".parse().unwrap()));
        assert!(!c.is_denied_address("140.82.121.4".parse().unwrap()));
    }

    #[test]
    fn more_specific_allow_ip_overrides_a_denied_range() {
        let c = cfg("", "", "10.1.0.0/24", "10.0.0.0/8");
        assert!(!c.is_denied_address("10.1.0.5".parse().unwrap()));
        assert!(c.is_denied_address("10.2.0.5".parse().unwrap()));
    }

    #[test]
    fn json_escaping_covers_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }
}
