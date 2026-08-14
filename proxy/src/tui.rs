use agent_sandbox_proxy::policy_io::{install_policy, load_policy_lines};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState},
    Terminal,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env, fs,
    io::{self, BufRead, Seek, SeekFrom},
    net::IpAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Drop guard ensuring terminal state (raw mode & alternate screen) is restored
/// even if a panic or early return occurs.
struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A row from `pending.jsonl` — only ever written while the policy's
/// `default` is `ask` (see `Shared::wait_for_ask`/`wait_for_l7_ask` in
/// `main.rs`).
#[derive(Deserialize, Debug, Clone)]
struct LogEvent {
    ev: Option<String>,
    id: Option<String>,
    ts: Option<u64>,
    host: Option<String>,
    port: Option<u16>,
    method: Option<String>,
}

/// A line from `connections.jsonl`. Distinct schema from `LogEvent`: no `id`
/// on the lines this TUI cares about (an outright, id-less deny — see the
/// doc comment on `MetricsLog` in `main.rs`).
#[derive(Deserialize, Debug, Clone)]
struct ConnEvent {
    ev: Option<String>,
    verdict: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    err: Option<String>,
    ts: Option<u64>,
    method: Option<String>,
}

/// A denied host/port, deduplicated across repeats so a retrying agent
/// doesn't spam the list with one row per attempt.
#[derive(Debug, Clone)]
struct DeniedEntry {
    host: String,
    port: u16,
    reason: Option<String>,
    method: Option<String>,
    count: u32,
    last_seen: u64,
}

/// `connections.jsonl` has no size cap, so the in-memory denied set doesn't
/// either unless bounded here.
const MAX_DENIED_ROWS: usize = 200;

enum DisplayRow {
    Pending(LogEvent),
    Denied(DeniedEntry),
}

impl DisplayRow {
    fn state_label(&self) -> &'static str {
        match self {
            DisplayRow::Pending(_) => "PEND",
            DisplayRow::Denied(_) => "DENY",
        }
    }

    fn host(&self) -> Option<&str> {
        match self {
            DisplayRow::Pending(r) => r.host.as_deref(),
            DisplayRow::Denied(d) => Some(d.host.as_str()),
        }
    }

    fn port(&self) -> u16 {
        match self {
            DisplayRow::Pending(r) => r.port.unwrap_or(0),
            DisplayRow::Denied(d) => d.port,
        }
    }

    fn method(&self) -> Option<&str> {
        match self {
            DisplayRow::Pending(r) => r.method.as_deref(),
            DisplayRow::Denied(d) => d.method.as_deref(),
        }
    }

    fn info_cell(&self) -> String {
        match self {
            DisplayRow::Pending(_) => String::new(),
            DisplayRow::Denied(d) => {
                let age = now_secs().saturating_sub(d.last_seen);
                let reason = d.reason.as_deref().unwrap_or("denied");
                if d.count > 1 {
                    format!("{} (×{}, {}s ago)", reason, d.count, age)
                } else {
                    format!("{} ({}s ago)", reason, age)
                }
            }
        }
    }
}

/// Whether `h` (allow HTTP route) makes sense for this row: only once a real
/// HTTP method is known. A domain-level ask (or an outright deny before any
/// L7 check ran) carries `"CONNECT"` or no method at all, and a rule built
/// from either can never match a real request.
fn h_available(method: Option<&str>) -> bool {
    matches!(method, Some(m) if m != "CONNECT")
}

/// Whether `A`/`D` (allow/deny IP) makes sense for this row's host: it must
/// actually parse as an IP or CIDR. Most rows carry a domain name instead.
fn ip_available(host: &str) -> bool {
    match host.split_once('/') {
        Some((ip, mask)) => ip.parse::<IpAddr>().is_ok() && mask.parse::<u8>().is_ok(),
        None => host.parse::<IpAddr>().is_ok(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum StatusKind {
    Success,
    Info,
    Error,
}

impl StatusKind {
    fn color(self) -> Color {
        match self {
            StatusKind::Success => Color::Green,
            StatusKind::Info => Color::Yellow,
            StatusKind::Error => Color::Red,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: agent-sandbox-tui <sandbox_name> <policy_dir> <shared_dir>");
        std::process::exit(1);
    }
    let sandbox_name = &args[1];
    let sidecar_policy = &args[2];
    let sidecar_shared = &args[3];
    let pending_log = format!("{}/pending.jsonl", sidecar_shared);
    let connections_log = format!("{}/connections.jsonl", sidecar_shared);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _cleanup = TerminalCleanup;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut pending_reqs: HashMap<String, LogEvent> = HashMap::new();
    let mut denied_reqs: HashMap<(String, u16), DeniedEntry> = HashMap::new();
    let mut selected_idx = 0;
    let mut table_state = TableState::default();
    let mut status_msg = String::new();
    let mut status_kind = StatusKind::Info;
    let mut status_until: Option<Instant> = None;

    let mut pending_file = None;
    let mut pending_pos = 0;
    let mut conn_file = None;
    let mut conn_pos = 0;

    loop {
        if let Some(until) = status_until {
            if Instant::now() >= until {
                status_msg.clear();
                status_until = None;
            }
        }

        if pending_file.is_none() {
            if let Ok(f) = fs::File::open(&pending_log) {
                pending_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = pending_file {
            let _ = reader.seek(SeekFrom::Start(pending_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 { break; }
                if !line.ends_with('\n') {
                    // Incomplete line written mid-frame; rewind so we re-read next loop
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<LogEvent>(&line) {
                    if let Some(id) = ev.id.clone() {
                        if ev.ev.as_deref() == Some("pending") {
                            pending_reqs.insert(id, ev);
                        } else if ev.ev.as_deref() == Some("resolved") {
                            pending_reqs.remove(&id);
                        }
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                pending_pos = pos;
            }
        }

        if conn_file.is_none() {
            if let Ok(f) = fs::File::open(&connections_log) {
                conn_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = conn_file {
            let _ = reader.seek(SeekFrom::Start(conn_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 { break; }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<ConnEvent>(&line) {
                    // An outright deny before any tunnel opened: no `ev`/`id`
                    // on the line (see the doc comment on `MetricsLog` in
                    // main.rs). Ask-mode pendings and open/close events are
                    // filtered out by requiring `ev` to be absent.
                    if ev.ev.is_none() && ev.verdict.as_deref() == Some("deny") {
                        if let (Some(host), Some(port)) = (ev.host.clone(), ev.port) {
                            let ts = ev.ts.unwrap_or_else(now_secs);
                            let key = (host.clone(), port);
                            let is_new = !denied_reqs.contains_key(&key);
                            let entry = denied_reqs.entry(key).or_insert_with(|| DeniedEntry {
                                host,
                                port,
                                reason: None,
                                method: None,
                                count: 0,
                                last_seen: ts,
                            });
                            entry.count += 1;
                            entry.last_seen = ts;
                            if ev.err.is_some() { entry.reason = ev.err.clone(); }
                            if ev.method.is_some() { entry.method = ev.method.clone(); }
                            if is_new && denied_reqs.len() > MAX_DENIED_ROWS {
                                if let Some(oldest) = denied_reqs
                                    .iter()
                                    .min_by_key(|(_, v)| v.last_seen)
                                    .map(|(k, _)| k.clone())
                                {
                                    denied_reqs.remove(&oldest);
                                }
                            }
                        }
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                conn_pos = pos;
            }
        }

        let mut pending_list: Vec<LogEvent> = pending_reqs.values().cloned().collect();
        pending_list.sort_by_key(|r| r.ts.unwrap_or(0));
        let pending_count = pending_list.len();

        let mut denied_list: Vec<DeniedEntry> = denied_reqs.values().cloned().collect();
        denied_list.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        let denied_count = denied_list.len();

        // Pending rows always come first and are never interleaved with
        // denies: a pending ask is time-boxed by `ask_timeout` and must stay
        // visually prominent, so a burst of repeated denies can't push it
        // off-screen.
        let row_list: Vec<DisplayRow> = pending_list
            .into_iter()
            .map(DisplayRow::Pending)
            .chain(denied_list.into_iter().map(DisplayRow::Denied))
            .collect();

        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(4),
                    Constraint::Length(1),
                ])
                .split(size);

            let title = Paragraph::new(format!(" Agent Sandbox TUI — {} ", sandbox_name))
                .style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray).fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let selected_style = Style::default().add_modifier(Modifier::REVERSED);
            let normal_style = Style::default();

            if row_list.is_empty() {
                let p = Paragraph::new("No pending or recently denied requests. Waiting for sandbox egress...")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL).title("Requests (0)"));
                f.render_widget(p, chunks[1]);
                selected_idx = 0;
                table_state.select(None);
            } else {
                if selected_idx >= row_list.len() {
                    selected_idx = row_list.len().saturating_sub(1);
                }
                table_state.select(Some(selected_idx));

                let rows = row_list.iter().enumerate().map(|(i, row)| {
                    let host = row.host().unwrap_or("unknown");
                    let port = row.port();
                    let method = row.method().unwrap_or("");
                    let style = if i == selected_idx { selected_style } else { normal_style };

                    let state_style = match row {
                        DisplayRow::Pending(_) => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        DisplayRow::Denied(_) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    };
                    let method_style = match method {
                        "GET" | "POST" | "PUT" | "DELETE" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        "CONNECT" => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        _ => Style::default().fg(Color::White),
                    };

                    Row::new(vec![
                        ratatui::text::Span::styled(row.state_label(), state_style),
                        ratatui::text::Span::styled(method.to_string(), method_style),
                        ratatui::text::Span::raw(host.to_string()),
                        ratatui::text::Span::raw(port.to_string()),
                        ratatui::text::Span::raw(row.info_cell()),
                    ]).style(style)
                });

                let table = Table::new(
                    rows,
                    [
                        Constraint::Length(6),
                        Constraint::Length(9),
                        Constraint::Percentage(40),
                        Constraint::Length(7),
                        Constraint::Percentage(35),
                    ],
                )
                .header(
                    Row::new(vec!["State", "Method", "Destination Host/IP", "Port", "Info"])
                        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                )
                .block(Block::default().borders(Borders::ALL).title(format!(
                    "Requests ({} pending, {} denied)",
                    pending_count, denied_count
                )));
                f.render_stateful_widget(table, chunks[1], &mut table_state);
            }

            let instructions = Paragraph::new(
                "↑/↓ select   [a] Allow domain   [h] Allow HTTP route   [d] Deny domain\n\
                 [A] Allow IP  [D] Deny IP  ·  PEND=awaiting decision, DENY=already rejected   [q]/[Esc] Quit",
            )
            .block(Block::default().borders(Borders::ALL).title("Keybindings"));
            f.render_widget(instructions, chunks[2]);

            if !status_msg.is_empty() {
                let status = Paragraph::new(status_msg.as_str())
                    .style(Style::default().fg(status_kind.color()).add_modifier(Modifier::BOLD));
                f.render_widget(status, chunks[3]);
            } else {
                f.render_widget(Paragraph::new(""), chunks[3]);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up => {
                        selected_idx = selected_idx.saturating_sub(1);
                    }
                    KeyCode::Down => {
                        selected_idx = (selected_idx + 1).min(row_list.len().saturating_sub(1));
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Char('h') => {
                        if !row_list.is_empty() && selected_idx < row_list.len() {
                            let row = &row_list[selected_idx];
                            if let Some(host) = row.host().map(|h| h.to_string()) {
                                let method = row.method().map(|m| m.to_string());

                                let mut guard_msg: Option<String> = None;
                                let mut detail = String::new();
                                let mut policy = load_policy_lines(sidecar_policy);

                                match key.code {
                                    KeyCode::Char('a') => {
                                        detail = format!("allow_domains {}", host);
                                        policy.push(detail.clone());
                                    }
                                    KeyCode::Char('d') => {
                                        detail = format!("deny_domains {}", host);
                                        policy.push(detail.clone());
                                    }
                                    KeyCode::Char('A') | KeyCode::Char('D') => {
                                        if !ip_available(&host) {
                                            guard_msg = Some(format!(
                                                "'{}' is not an IP — use 'a'/'d' to allow/deny the domain instead",
                                                host
                                            ));
                                        } else if key.code == KeyCode::Char('A') {
                                            detail = format!("allow_ips {}", host);
                                            policy.push(detail.clone());
                                        } else {
                                            detail = format!("deny_ips {}", host);
                                            policy.push(detail.clone());
                                        }
                                    }
                                    KeyCode::Char('h') => {
                                        if !h_available(method.as_deref()) {
                                            guard_msg = Some(
                                                "No HTTP method known yet for this row — allow the domain first with 'a'; 'h' becomes available once a real request is seen"
                                                    .to_string(),
                                            );
                                        } else {
                                            let m = method.unwrap();
                                            detail = format!("allow_l7 {} {}", host, m);
                                            policy.push(format!("allow_l7\t{}\t{}\t/*", host, m));
                                        }
                                    }
                                    _ => {}
                                }

                                if let Some(msg) = guard_msg {
                                    status_msg = msg;
                                    status_kind = StatusKind::Info;
                                    status_until = Some(Instant::now() + Duration::from_secs(4));
                                } else if let Err(e) = install_policy(sidecar_policy, &policy) {
                                    status_msg = format!("Error: {}", e);
                                    status_kind = StatusKind::Error;
                                    status_until = None;
                                } else {
                                    status_msg = format!("Added: {}", detail);
                                    status_kind = StatusKind::Success;
                                    status_until = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
