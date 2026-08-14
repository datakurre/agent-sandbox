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
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
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

/// A line from `connections.jsonl`. Denials can be id-less when rejected before
/// a tunnel opens, or `close` events when an L7 request is rejected after MITM.
#[derive(Deserialize, Debug, Clone)]
struct ConnEvent {
    ev: Option<String>,
    id: Option<String>,
    verdict: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    pub err: Option<String>,
    pub up: Option<u64>,
    pub down: Option<u64>,
    pub ms: Option<u128>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    ts: Option<u64>,
}

fn is_denied_event(ev: &ConnEvent) -> bool {
    ev.verdict.as_deref() == Some("deny") && (ev.ev.is_none() || ev.ev.as_deref() == Some("close"))
}

fn is_connection_event(ev: &ConnEvent) -> bool {
    ev.ev.as_deref() != Some("policy") && ev.host.is_some() && ev.port.is_some()
}

/// Correlate open/close events while retaining id-less terminal events.
fn ingest_connection_event(connections: &mut Vec<ConnEvent>, event: ConnEvent) {
    if !is_connection_event(&event) {
        return;
    }

    if let Some(id) = event.id.as_deref() {
        if let Some(existing) = connections
            .iter_mut()
            .find(|entry| entry.id.as_deref() == Some(id))
        {
            *existing = event;
        } else {
            connections.push(event);
        }
    } else {
        connections.push(event);
    }

    if connections.len() > MAX_CONNECTION_ROWS {
        if let Some(oldest) = connections
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.ts.unwrap_or(0))
            .map(|(index, _)| index)
        {
            connections.remove(oldest);
        }
    }
}

#[derive(Deserialize, Debug)]
struct DetailEvent {
    host: String,
    port: u16,
    reason: String,
    request: String,
}

/// A denied host/port, deduplicated across repeats so a retrying agent
/// doesn't spam the list with one row per attempt.
#[derive(Debug, Clone)]
struct DeniedEntry {
    host: String,
    port: u16,
    reason: Option<String>,
    method: Option<String>,
    detail: Option<String>,
    count: u32,
    last_seen: u64,
}

impl DeniedEntry {
    fn info_cell(&self) -> String {
        let age = now_secs().saturating_sub(self.last_seen);
        let reason = self.reason.as_deref().unwrap_or("denied");
        if self.count > 1 {
            format!("{} (×{}, {}s ago)", reason, self.count, age)
        } else {
            format!("{} ({}s ago)", reason, age)
        }
    }
}

/// `connections.jsonl` has no size cap, so the in-memory denied set doesn't
/// either unless bounded here.
const MAX_DENIED_ROWS: usize = 200;
const MAX_CONNECTION_ROWS: usize = 200;
const MAX_DETAIL_BYTES_PER_ROW: usize = 16 * 1024;

/// Whether `h` (allow HTTP route) makes sense for this row: only once a real
/// HTTP method is known. A domain/IP-level deny before any L7 check ran
/// carries `"CONNECT"` or no method at all, and a rule built from either can
/// never match a real request.
fn h_available(method: Option<&str>) -> bool {
    matches!(method, Some(m) if m != "CONNECT")
}

/// Whether `A` (allow IP) makes sense for this row's host: it must actually
/// parse as an IP or CIDR. Most rows carry a domain name instead.
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

/// The two screens this dashboard flips between: the live denied-request
/// feed (default), and a read/remove view of the policy actually in force.
#[derive(Clone, Copy, PartialEq)]
enum View {
    Requests,
    Connections,
    Rules,
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
    let connections_log = format!("{}/connections.jsonl", sidecar_shared);
    let details_log = format!("{}/denied-requests.jsonl", sidecar_shared);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _cleanup = TerminalCleanup;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut denied_reqs: HashMap<(String, u16), DeniedEntry> = HashMap::new();
    let mut connections: Vec<ConnEvent> = Vec::new();
    let mut view = View::Requests;
    let mut selected_idx = 0;
    let mut table_state = TableState::default();
    let mut connections_selected_idx = 0;
    let mut connections_table_state = TableState::default();
    let mut rules_selected_idx = 0;
    let mut rules_table_state = TableState::default();
    let mut status_msg = String::new();
    let mut status_kind = StatusKind::Info;
    let mut status_until: Option<Instant> = None;

    let mut conn_file = None;
    let mut conn_pos = 0;
    let mut details_file = None;
    let mut details_pos = 0;
    let mut show_detail = false;
    let mut detail_scroll = 0;

    loop {
        if let Some(until) = status_until {
            if Instant::now() >= until {
                status_msg.clear();
                status_until = None;
            }
        }

        if conn_file.is_none() {
            if let Ok(f) = fs::File::open(&connections_log) {
                conn_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = conn_file {
            if let Ok(meta) = reader.get_ref().metadata() {
                if meta.len() < conn_pos {
                    conn_pos = 0;
                }
            }
            let _ = reader.seek(SeekFrom::Start(conn_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<ConnEvent>(&line) {
                    ingest_connection_event(&mut connections, ev.clone());
                    // Include pre-tunnel denials and L7 denials emitted as a
                    // terminal close event. Allowed close events remain out.
                    if is_denied_event(&ev) {
                        if let (Some(host), Some(port)) = (ev.host.clone(), ev.port) {
                            let ts = ev.ts.unwrap_or_else(now_secs);
                            let key = (host.clone(), port);
                            let is_new = !denied_reqs.contains_key(&key);
                            let entry = denied_reqs.entry(key).or_insert_with(|| DeniedEntry {
                                host,
                                port,
                                reason: None,
                                method: None,
                                detail: None,
                                count: 0,
                                last_seen: ts,
                            });
                            entry.count += 1;
                            entry.last_seen = ts;
                            if ev.err.is_some() {
                                entry.reason = ev.err.clone();
                            }
                            if ev.method.is_some() {
                                entry.method = ev.method.clone();
                            }
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

        if details_file.is_none() {
            if let Ok(f) = fs::File::open(&details_log) {
                details_file = Some(io::BufReader::new(f));
            }
        }
        if let Some(ref mut reader) = details_file {
            if let Ok(meta) = reader.get_ref().metadata() {
                if meta.len() < details_pos {
                    details_pos = 0;
                }
            }
            let _ = reader.seek(SeekFrom::Start(details_pos));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    let _ = reader.seek(SeekFrom::Current(-(line.len() as i64)));
                    break;
                }
                if let Ok(ev) = serde_json::from_str::<DetailEvent>(&line) {
                    if let Some(entry) = denied_reqs.get_mut(&(ev.host, ev.port)) {
                        entry.detail = Some(format!(
                            "Reason: {}\n\n{}",
                            ev.reason,
                            ev.request
                                .chars()
                                .take(MAX_DETAIL_BYTES_PER_ROW)
                                .collect::<String>()
                        ));
                        entry.reason = Some(ev.reason.clone());
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                details_pos = pos;
            }
        }

        let mut denied_list: Vec<DeniedEntry> = denied_reqs.values().cloned().collect();
        denied_list.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        let mut connections_list = connections.clone();
        connections_list.sort_by_key(|entry| std::cmp::Reverse(entry.ts.unwrap_or(0)));

        // Only loaded while the Rules view is active — cheap either way (a
        // small file, and this loop already re-reads connections.jsonl at
        // ~10Hz), but no point parsing it every frame when it's not shown.
        let (policy_lines, base_lines, baseline_lines): (
            Vec<String>,
            HashSet<String>,
            HashSet<String>,
        ) = if view == View::Rules {
            let lines = load_policy_lines(sidecar_policy);
            let base = fs::read_to_string(format!("{}/policy.base", sidecar_policy))
                .map(|s| s.lines().map(|l| l.to_string()).collect())
                .unwrap_or_default();
            let baseline = fs::read_to_string(format!("{}/policy.baseline", sidecar_policy))
                .map(|s| s.lines().map(|l| l.to_string()).collect())
                .unwrap_or_default();
            (lines, base, baseline)
        } else {
            (Vec::new(), HashSet::new(), HashSet::new())
        };

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

            match view {
                View::Requests => {
                    if show_detail {
                        let mut text = denied_list.get(selected_idx)
                            .and_then(|d| d.detail.clone())
                            .unwrap_or_else(|| "No detailed request is available for this denial yet.".to_string());
                        if let Some(row) = denied_list.get(selected_idx) {
                            if row.method.as_deref() == Some("CONNECT") {
                                text.push_str(&format!(
                                    "\n\nThe inner HTTPS request is unavailable because CONNECT was denied before TLS.\nTo inspect it, temporarily add:\n\n[[network.rules]]\nhost = \"{}:{}\"\nmethod = \"GET\"\npath = \"/noop\"\n\nThis permits the CONNECT/MITM stage; the placeholder path remains denied. Replace it with the required path after retrying.",
                                    row.host, row.port
                                ));
                            }
                        }
                        let detail = Paragraph::new(text)
                            .wrap(Wrap { trim: false })
                            .scroll((detail_scroll, 0))
                            .block(Block::default().borders(Borders::ALL).title("Denied Request Details (redacted)"));
                        f.render_widget(detail, chunks[1]);
                    } else if denied_list.is_empty() {
                        let p = Paragraph::new("No denied requests yet. Waiting for sandbox egress...")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Denied Requests (0)"));
                        f.render_widget(p, chunks[1]);
                        selected_idx = 0;
                        table_state.select(None);
                    } else {
                        if selected_idx >= denied_list.len() {
                            selected_idx = denied_list.len().saturating_sub(1);
                        }
                        table_state.select(Some(selected_idx));

                        let rows = denied_list.iter().enumerate().map(|(i, d)| {
                            let method = d.method.as_deref().unwrap_or("");
                            let style = if i == selected_idx { selected_style } else { normal_style };
                            let method_style = match method {
                                "GET" | "POST" | "PUT" | "DELETE" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                "CONNECT" => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                                _ => Style::default().fg(Color::White),
                            };
                            Row::new(vec![
                                ratatui::text::Span::styled(method.to_string(), method_style),
                                ratatui::text::Span::raw(d.host.clone()),
                                ratatui::text::Span::raw(d.port.to_string()),
                                ratatui::text::Span::raw(d.info_cell()),
                            ]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [
                                Constraint::Length(9),
                                Constraint::Percentage(40),
                                Constraint::Length(7),
                                Constraint::Percentage(44),
                            ],
                        )
                        .header(
                            Row::new(vec!["Method", "Destination Host/IP", "Port", "Info"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Denied Requests ({})", denied_list.len())));
                        f.render_stateful_widget(table, chunks[1], &mut table_state);
                    }
                }
                View::Connections => {
                    if connections_list.is_empty() {
                        let p = Paragraph::new("No connections yet. Waiting for sandbox egress...")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Connections (0)"));
                        f.render_widget(p, chunks[1]);
                        connections_selected_idx = 0;
                        connections_table_state.select(None);
                    } else {
                        if connections_selected_idx >= connections_list.len() {
                            connections_selected_idx = connections_list.len().saturating_sub(1);
                        }
                        connections_table_state.select(Some(connections_selected_idx));

                        let rows = connections_list.iter().enumerate().map(|(i, ev)| {
                            let method = ev.method.as_deref().unwrap_or("");
                            let state = if ev.ev.as_deref() == Some("open") {
                                "OPEN".to_string()
                            } else {
                                ev.verdict.as_deref().unwrap_or("?").to_ascii_uppercase()
                            };
                            let target = match (&ev.host, ev.path.as_deref()) {
                                (Some(host), Some(path)) => format!("{}:{}{}", host, ev.port.unwrap_or(0), path),
                                (Some(host), None) => format!("{}:{}", host, ev.port.unwrap_or(0)),
                                _ => "?".to_string(),
                            };
                            let mut info = Vec::new();
                            if let Some(status) = ev.status { info.push(format!("HTTP {}", status)); }
                            if let Some(err) = &ev.err { info.push(err.clone()); }
                            if ev.ev.as_deref() != Some("open") {
                                info.push(format!("up {} / down {} / {}ms", ev.up.unwrap_or(0), ev.down.unwrap_or(0), ev.ms.unwrap_or(0)));
                            }
                            let style = if i == connections_selected_idx { selected_style } else { normal_style };
                            let state_style = match state.as_str() {
                                "ALLOW" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                "DENY" | "ERROR" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                                "OPEN" => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                                _ => Style::default().fg(Color::Yellow),
                            };
                            Row::new(vec![
                                ratatui::text::Span::styled(state, state_style),
                                ratatui::text::Span::raw(method.to_string()),
                                ratatui::text::Span::raw(target),
                                ratatui::text::Span::raw(info.join(", ")),
                            ]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [Constraint::Length(8), Constraint::Length(9), Constraint::Percentage(38), Constraint::Percentage(42)],
                        )
                        .header(
                            Row::new(vec!["State", "Method", "Destination", "Info"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Connections ({})", connections_list.len())));
                        f.render_stateful_widget(table, chunks[1], &mut connections_table_state);
                    }
                }
                View::Rules => {
                    if policy_lines.is_empty() {
                        let p = Paragraph::new("No policy rules yet.")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().borders(Borders::ALL).title("Rules (0)"));
                        f.render_widget(p, chunks[1]);
                        rules_selected_idx = 0;
                        rules_table_state.select(None);
                    } else {
                        if rules_selected_idx >= policy_lines.len() {
                            rules_selected_idx = policy_lines.len().saturating_sub(1);
                        }
                        rules_table_state.select(Some(rules_selected_idx));

                        let rows = policy_lines.iter().enumerate().map(|(i, line)| {
                            let style = if i == rules_selected_idx { selected_style } else { normal_style };
                            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line.as_str(), ""));
                            let display_value = if key == "allow_l7" {
                                value.trim().replace('\t', " ")
                            } else {
                                value.trim().to_string()
                            };
                            let source = if baseline_lines.contains(line) {
                                "built-in"
                            } else if base_lines.contains(line) {
                                "AGENTS.md"
                            } else {
                                "live"
                            };
                            Row::new(vec![key.to_string(), display_value, source.to_string()]).style(style)
                        });

                        let table = Table::new(
                            rows,
                            [Constraint::Length(15), Constraint::Percentage(60), Constraint::Length(12)],
                        )
                        .header(
                            Row::new(vec!["Key", "Value", "Source"])
                                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
                        )
                        .block(Block::default().borders(Borders::ALL).title(format!("Rules ({})", policy_lines.len())));
                        f.render_stateful_widget(table, chunks[1], &mut rules_table_state);
                    }
                }
            }

            let legend_text = match view {
                View::Requests if show_detail => "↑/↓ scroll   [d]/[Esc] Back   [q] Quit",
                View::Requests => "↑/↓ select   [d] Details   [a] Allow domain   [h] Allow HTTP route   [A] Allow IP\n[v] Connections view   [r] Rules view   [c] Clear   [q]/[Esc] Quit",
                View::Connections => "↑/↓ select   [v] Denied requests   [r] Rules view   [q]/[Esc] Quit",
                View::Rules => "↑/↓ select   [x] Remove rule (blocked for built-in/AGENTS.md rules)\n[r] Requests view   [q]/[Esc] Quit",
            };
            let instructions = Paragraph::new(legend_text)
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
                    KeyCode::Char('q') => break,
                    KeyCode::Esc if show_detail => {
                        show_detail = false;
                        detail_scroll = 0;
                    }
                    KeyCode::Esc => break,
                    KeyCode::Up => match view {
                        View::Requests if show_detail => {
                            detail_scroll = detail_scroll.saturating_sub(1)
                        }
                        View::Requests => selected_idx = selected_idx.saturating_sub(1),
                        View::Connections => {
                            connections_selected_idx = connections_selected_idx.saturating_sub(1)
                        }
                        View::Rules => rules_selected_idx = rules_selected_idx.saturating_sub(1),
                    },
                    KeyCode::Down => match view {
                        View::Requests if show_detail => {
                            detail_scroll = detail_scroll.saturating_add(1)
                        }
                        View::Requests => {
                            selected_idx =
                                (selected_idx + 1).min(denied_list.len().saturating_sub(1));
                        }
                        View::Connections => {
                            connections_selected_idx = (connections_selected_idx + 1)
                                .min(connections_list.len().saturating_sub(1));
                        }
                        View::Rules => {
                            rules_selected_idx =
                                (rules_selected_idx + 1).min(policy_lines.len().saturating_sub(1));
                        }
                    },
                    KeyCode::Char('r') => {
                        view = match view {
                            View::Rules => View::Requests,
                            _ => View::Rules,
                        };
                    }
                    KeyCode::Char('v') if !show_detail => {
                        view = match view {
                            View::Requests => View::Connections,
                            View::Connections => View::Requests,
                            View::Rules => View::Connections,
                        };
                    }
                    KeyCode::Char('c') if view == View::Requests => {
                        denied_reqs.clear();
                        denied_list.clear();
                        selected_idx = 0;
                    }
                    KeyCode::Char('d') if view == View::Requests && !denied_list.is_empty() => {
                        show_detail = !show_detail;
                        detail_scroll = 0;
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char('h')
                        if view == View::Requests && !show_detail =>
                    {
                        if !denied_list.is_empty() && selected_idx < denied_list.len() {
                            let row = &denied_list[selected_idx];
                            let host = row.host.clone();
                            let method = row.method.clone();

                            let mut guard_msg: Option<String> = None;
                            let mut detail = String::new();
                            let mut policy = load_policy_lines(sidecar_policy);

                            match key.code {
                                KeyCode::Char('a') => {
                                    detail = format!("allow_domains {}", host);
                                    policy.push(detail.clone());
                                }
                                KeyCode::Char('A') => {
                                    if !ip_available(&host) {
                                        guard_msg = Some(format!(
                                            "'{}' is not an IP — use 'a' to allow the domain instead",
                                            host
                                        ));
                                    } else {
                                        detail = format!("allow_ips {}", host);
                                        policy.push(detail.clone());
                                    }
                                }
                                KeyCode::Char('h') => {
                                    if !h_available(method.as_deref()) {
                                        guard_msg = Some(
                                            "No HTTP method known yet for this row — allow the domain first with 'a'; 'h' becomes available once a real request is seen"
                                                .to_string(),
                                        );
                                    } else if !base_lines.iter().any(|l| l.starts_with("allow_l7\t")) {
                                        // An L7 rule means the proxy terminates TLS for
                                        // that host, and the session CA is bound into the
                                        // sandbox only when the launch policy already had
                                        // one.  Adding the first one here cannot work.
                                        guard_msg = Some(format!(
                                            "This sandbox launched with no L7 rule, so it does not trust the proxy's session CA — TLS to {} would fail. Declare the rule in AGENTS.md and relaunch.",
                                            host
                                        ));
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
                    KeyCode::Char('x') if view == View::Rules => {
                        if let Some(line) = policy_lines.get(rules_selected_idx) {
                            if base_lines.contains(line) {
                                let label = if baseline_lines.contains(line) {
                                    "built-in"
                                } else {
                                    "AGENTS.md's baseline"
                                };
                                status_msg = format!(
                                    "'{}' comes from {} policy and can't be removed here — edit AGENTS.md and relaunch, or `agent-sandbox ctl proxy reset` first",
                                    line, label
                                );
                                status_kind = StatusKind::Info;
                                status_until = Some(Instant::now() + Duration::from_secs(5));
                            } else {
                                let mut lines = policy_lines.clone();
                                lines.remove(rules_selected_idx);
                                if let Err(e) = install_policy(sidecar_policy, &lines) {
                                    status_msg = format!("Error: {}", e);
                                    status_kind = StatusKind::Error;
                                    status_until = None;
                                } else {
                                    status_msg = format!("Removed: {}", line);
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

#[cfg(test)]
mod tests {
    use super::{ingest_connection_event, is_denied_event, ConnEvent};

    fn event(ev: Option<&str>, verdict: Option<&str>) -> ConnEvent {
        ConnEvent {
            ev: ev.map(str::to_string),
            id: None,
            verdict: verdict.map(str::to_string),
            host: None,
            port: None,
            err: None,
            up: None,
            down: None,
            ms: None,
            method: None,
            path: None,
            status: None,
            ts: None,
        }
    }

    #[test]
    fn includes_l7_denial_close_events() {
        assert!(is_denied_event(&event(Some("close"), Some("deny"))));
        assert!(is_denied_event(&event(None, Some("deny"))));
        assert!(!is_denied_event(&event(Some("close"), Some("allow"))));
        assert!(!is_denied_event(&event(Some("open"), Some("deny"))));
    }

    fn connection(ev: &str, id: Option<&str>, ts: u64) -> ConnEvent {
        ConnEvent {
            ev: Some(ev.to_string()),
            id: id.map(str::to_string),
            verdict: if ev == "close" {
                Some("allow".to_string())
            } else {
                None
            },
            host: Some("example.com".to_string()),
            port: Some(443),
            err: None,
            up: Some(10),
            down: Some(20),
            ms: Some(5),
            method: None,
            path: None,
            status: None,
            ts: Some(ts),
        }
    }

    #[test]
    fn correlates_open_and_close_events() {
        let mut connections = Vec::new();
        ingest_connection_event(&mut connections, connection("open", Some("1"), 1));
        ingest_connection_event(&mut connections, connection("close", Some("1"), 2));

        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].ev.as_deref(), Some("close"));
        assert_eq!(connections[0].id.as_deref(), Some("1"));
    }

    #[test]
    fn retains_idless_terminal_events() {
        let mut connections = Vec::new();
        ingest_connection_event(&mut connections, connection("close", None, 1));

        assert_eq!(connections.len(), 1);
        assert!(connections[0].id.is_none());
    }
}
