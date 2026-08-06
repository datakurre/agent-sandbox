#![forbid(unsafe_code)]

use ipnet::IpNet;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone)]
struct ProxyConfig {
    allow_domains: Vec<String>,
    deny_domains: Vec<String>,
    allow_ips: Vec<IpNet>,
    deny_ips: Vec<IpNet>,
    default_allow: bool,
}

fn parse_csv(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').map(|s| s.to_string()).collect()
    }
}

fn parse_csv_ips(s: &str) -> Vec<IpNet> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',')
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect()
    }
}

fn domain_match(domain: &str, pattern: &str) -> bool {
    if let Some(stripped) = pattern.strip_prefix("*.") {
        domain == stripped || domain.ends_with(pattern.trim_start_matches('*'))
    } else {
        domain == pattern
    }
}

impl ProxyConfig {
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

    fn is_allowed(&self, host: &str) -> bool {
        match host.parse::<IpAddr>() {
            Ok(ip) => self.is_allowed_ip(ip),
            Err(_) => self.is_allowed_domain(host),
        }
    }
}

fn pump(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; 8192];
    let _ = src.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = dst.set_read_timeout(Some(Duration::from_secs(60)));
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn handle_client(mut client_sock: TcpStream, config: Arc<ProxyConfig>) {
    let mut req_buf = [0u8; 8192];
    let n = match client_sock.read(&mut req_buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        return;
    }

    let method = parts[0];
    let mut url = parts[1];

    let host;
    let port: u16;

    if method == "CONNECT" {
        let hp: Vec<&str> = url.split(':').collect();
        if hp.len() != 2 {
            return;
        }
        host = hp[0].to_string();
        port = hp[1].parse().unwrap_or(443);
    } else {
        if let Some(idx) = url.find("://") {
            url = &url[idx + 3..];
        }
        let url_no_path = url.split('/').next().unwrap_or("");
        if let Some(idx) = url_no_path.find(':') {
            host = url_no_path[..idx].to_string();
            port = url_no_path[idx + 1..].parse().unwrap_or(80);
        } else {
            host = url_no_path.to_string();
            port = 80;
        }
    }

    if !config.is_allowed(&host) {
        let _ = client_sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        return;
    }

    let mut remote_sock = match std::net::TcpStream::connect_timeout(
        &format!("{}:{}", host, port)
            .parse::<std::net::SocketAddr>()
            .unwrap_or_else(|_| {
                // If parsing fails (e.g., domain name), fallback to normal connect
                // Note: Rust's ToSocketAddrs resolves domains automatically.
                // We'll just pass the string formatted host:port
                return std::net::SocketAddr::from(([0, 0, 0, 0], 0));
            }),
        Duration::from_secs(10),
    ) {
        Ok(s) => s,
        Err(_) => {
            // For domains, we just use TcpStream::connect
            match std::net::TcpStream::connect(format!("{}:{}", host, port)) {
                Ok(s) => {
                    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    s
                }
                Err(_) => return,
            }
        }
    };

    if method == "CONNECT" {
        if client_sock
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
    } else {
        if remote_sock.write_all(&req_buf[..n]).is_err() {
            return;
        }
    }

    let client_sock_clone = client_sock.try_clone().unwrap();
    let remote_sock_clone = remote_sock.try_clone().unwrap();

    let t1 = thread::spawn(move || pump(client_sock, remote_sock));
    let t2 = thread::spawn(move || pump(remote_sock_clone, client_sock_clone));

    let _ = t1.join();
    let _ = t2.join();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let allow_domains = args.get(1).map(|s| parse_csv(s)).unwrap_or_default();
    let deny_domains = args.get(2).map(|s| parse_csv(s)).unwrap_or_default();
    let allow_ips = args.get(3).map(|s| parse_csv_ips(s)).unwrap_or_default();
    let deny_ips = args.get(4).map(|s| parse_csv_ips(s)).unwrap_or_default();

    let default_allow = allow_domains.is_empty() && allow_ips.is_empty();

    let config = Arc::new(ProxyConfig {
        allow_domains,
        deny_domains,
        allow_ips,
        deny_ips,
        default_allow,
    });

    let listener = TcpListener::bind("0.0.0.0:8888").unwrap();

    if let Ok(mut f) = File::create("/sidecar_shared/ready") {
        let _ = f.write_all(b"ready\n");
    }

    for stream in listener.incoming() {
        if let Ok(client) = stream {
            let config_clone = Arc::clone(&config);
            thread::spawn(move || handle_client(client, config_clone));
        }
    }
}
