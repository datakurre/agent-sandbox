#![forbid(unsafe_code)]

use anyhow::Result;
use chrono::{Local, TimeZone};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyRecord {
    pub id: Option<String>,
    pub ev: Option<String>,
    pub ts: f64,
    pub host: String,
    pub port: u16,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub ms: Option<f64>,
    pub verdict: Option<String>,
    pub err: Option<String>,
}

fn format_human(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1048576 {
        let v = (bytes as f64 / 1024.0 * 10.0).round() / 10.0;
        format!("{} KiB", v)
    } else if bytes < 1073741824 {
        let v = (bytes as f64 / 1048576.0 * 10.0).round() / 10.0;
        format!("{} MiB", v)
    } else {
        let v = (bytes as f64 / 1073741824.0 * 10.0).round() / 10.0;
        format!("{} GiB", v)
    }
}

fn format_dur(secs: f64) -> String {
    if secs < 60.0 {
        format!("{}s", secs.floor() as u64)
    } else if secs < 3600.0 {
        format!("{}m {}s", (secs / 60.0).floor() as u64, (secs % 60.0).floor() as u64)
    } else {
        format!("{}h {}m", (secs / 3600.0).floor() as u64, ((secs % 3600.0) / 60.0).floor() as u64)
    }
}

fn format_ms(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{}ms", ms)
    } else {
        format_dur((ms / 1000.0).floor())
    }
}

fn pad(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count < n {
        format!("{}{}", s, " ".repeat(n - chars_count))
    } else {
        s.to_string()
    }
}

fn lpad(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count < n {
        format!("{}{}", " ".repeat(n - chars_count), s)
    } else {
        s.to_string()
    }
}

fn clip(s: &str, n: usize) -> String {
    let chars_count = s.chars().count();
    if chars_count > n {
        let clipped: String = s.chars().take(n - 1).collect();
        format!("{}…", clipped)
    } else {
        s.to_string()
    }
}

pub fn process_stream<R: BufRead>(reader: R) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let record: ProxyRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let t = match Local.timestamp_opt(record.ts as i64, 0) {
            chrono::LocalResult::Single(dt) => dt.format("%H:%M:%S").to_string(),
            _ => "--:--:--".to_string(),
        };

        let ev = record.ev.as_deref().unwrap_or("close");
        if ev == "open" {
            let host_port = format!("{}:{}", record.host, record.port);
            println!("{}  open   {}", t, clip(&host_port, 40));
        } else {
            let verdict = record.verdict.as_deref().unwrap_or("?");
            let host_port = format!("{}:{}", record.host, record.port);
            
            let up_str = format_human(record.up.unwrap_or(0));
            let down_str = format_human(record.down.unwrap_or(0));
            let ms_str = format_ms(record.ms.unwrap_or(0.0));

            let out_str = format!("{}  {} {}{}{}{}{}",
                t,
                pad(verdict, 6),
                pad(&clip(&host_port, 40), 40),
                lpad(&up_str, 11),
                lpad(&down_str, 11),
                lpad(&ms_str, 9),
                if let Some(err) = &record.err { format!("  ({})", err) } else { "".to_string() }
            );
            println!("{}", out_str);
        }
    }
    Ok(())
}

pub fn process_summary(records: Vec<ProxyRecord>) {
    if records.is_empty() {
        println!("\n=== Network Summary ===");
        println!("(no connections recorded)");
        return;
    }

    let mut closed_ids = HashSet::new();
    for r in &records {
        let ev = r.ev.as_deref().unwrap_or("close");
        if ev == "close" {
            if let Some(id) = &r.id {
                closed_ids.insert(id.clone());
            }
        }
    }

    let all: Vec<&ProxyRecord> = records.iter().filter(|r| r.ev.as_deref().unwrap_or("close") == "close").collect();
    let live: Vec<&ProxyRecord> = records.iter().filter(|r| {
        r.ev.as_deref().unwrap_or("close") == "open" && r.id.as_ref().map_or(false, |id| !closed_ids.contains(id))
    }).collect();

    let mut ok = Vec::new();
    let mut den = Vec::new();
    let mut fail = Vec::new();

    for r in &all {
        let verdict = r.verdict.as_deref().unwrap_or("?");
        if verdict == "allow" {
            ok.push(*r);
        } else if verdict == "deny" {
            den.push(*r);
        } else if verdict == "error" {
            fail.push(*r);
        }
    }

    let mut den_map: HashMap<String, usize> = HashMap::new();
    for r in &den {
        *den_map.entry(r.host.clone()).or_insert(0) += 1;
    }
    let mut den_list: Vec<(String, usize)> = den_map.into_iter().collect();
    den_list.sort_by(|a, b| b.1.cmp(&a.1));

    let mut fail_map: HashMap<(String, String), usize> = HashMap::new();
    for r in &fail {
        let err = r.err.clone().unwrap_or_else(|| "?".to_string());
        *fail_map.entry((r.host.clone(), err)).or_insert(0) += 1;
    }
    let mut fail_list: Vec<((String, String), usize)> = fail_map.into_iter().collect();
    fail_list.sort_by(|a, b| b.1.cmp(&a.1));

    struct HostStats {
        conns: usize,
        up: u64,
        down: u64,
    }
    let mut hosts_map: HashMap<String, HostStats> = HashMap::new();
    for r in &ok {
        let entry = hosts_map.entry(r.host.clone()).or_insert(HostStats { conns: 0, up: 0, down: 0 });
        entry.conns += 1;
        entry.up += r.up.unwrap_or(0);
        entry.down += r.down.unwrap_or(0);
    }
    let mut hosts_list: Vec<(String, HostStats)> = hosts_map.into_iter().collect();
    hosts_list.sort_by(|a, b| (b.1.up + b.1.down).cmp(&(a.1.up + a.1.down)));

    let shown = if hosts_list.len() > 15 { &hosts_list[0..15] } else { &hosts_list[..] };
    let rest = if hosts_list.len() > 15 { &hosts_list[15..] } else { &[] };

    let mut w0 = 20;
    for (h, _) in shown { w0 = w0.max(h.chars().count()); }
    for (h, _) in &den_list { w0 = w0.max(h.chars().count()); }
    for ((h, _), _) in &fail_list { w0 = w0.max(h.chars().count()); }
    for r in &live { w0 = w0.max(format!("{}:{}", r.host, r.port).chars().count()); }

    let w = if w0 > 40 { 40 } else { w0 };

    let mut min_ts = f64::MAX;
    let mut max_ts = f64::MIN;
    for r in &records {
        if r.ts < min_ts { min_ts = r.ts; }
        if r.ts > max_ts { max_ts = r.ts; }
    }
    let span = if max_ts >= min_ts { max_ts - min_ts } else { 0.0 };

    let tup: u64 = ok.iter().map(|r| r.up.unwrap_or(0)).sum();
    let tdown: u64 = ok.iter().map(|r| r.down.unwrap_or(0)).sum();

    println!(""); 

    let mut header = format!("=== Network Summary ===  {} · {} connection{}", 
        format_dur(span), all.len(), if all.len() == 1 { "" } else { "s" });
    if !ok.is_empty() {
        header.push_str(&format!(" · {} in / {} out", format_human(tdown), format_human(tup)));
    }
    if !live.is_empty() {
        header.push_str(&format!(" · {} in flight", live.len()));
    }
    println!("{}", header);

    if !shown.is_empty() {
        println!("");
        println!("  {}{}{}{}", pad("HOST", w), lpad("CONNS", 7), lpad("SENT", 11), lpad("RECV", 11));
        for (h, stats) in shown {
            println!("  {}{}{}{}", 
                pad(&clip(h, w), w), 
                lpad(&stats.conns.to_string(), 7),
                lpad(&format_human(stats.up), 11),
                lpad(&format_human(stats.down), 11)
            );
        }
        if !rest.is_empty() {
            let rest_conns: usize = rest.iter().map(|(_, s)| s.conns).sum();
            let rest_up: u64 = rest.iter().map(|(_, s)| s.up).sum();
            let rest_down: u64 = rest.iter().map(|(_, s)| s.down).sum();
            println!("  {}{}{}{}", 
                pad(&clip(&format!("… and {} more hosts", rest.len()), w), w),
                lpad(&rest_conns.to_string(), 7),
                lpad(&format_human(rest_up), 11),
                lpad(&format_human(rest_down), 11)
            );
        }
    }

    if !den_list.is_empty() {
        println!("");
        println!("  ── denied {}", "─".repeat(w + 19));
        for (h, conns) in &den_list {
            println!("  {}{}", pad(&clip(h, w), w), lpad(&conns.to_string(), 7));
        }
    }

    if !fail_list.is_empty() {
        println!("");
        println!("  ── failed {}", "─".repeat(w + 19));
        for ((h, err), conns) in &fail_list {
            println!("  {}{}  ({})", pad(&clip(h, w), w), lpad(&conns.to_string(), 7), err);
        }
    }

    if !live.is_empty() {
        println!("");
        println!("  ── still open {}", "─".repeat(w + 15));
        let mut sorted_live = live.clone();
        sorted_live.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(Ordering::Equal));
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        for r in sorted_live {
            let hp = format!("{}:{}", r.host, r.port);
            let dur_secs = (now.floor() - r.ts).max(0.0);
            println!("  {}{}", pad(&clip(&hp, w), w), lpad(&format_dur(dur_secs), 9));
        }
    }

    if ok.is_empty() && !fail_list.is_empty() && live.is_empty() {
        println!("");
        println!("  Nothing got through. The sidecar could not reach the network;");
        println!("  see the proxy log:  podman logs <sidecar>");
    }

    println!("");
}
