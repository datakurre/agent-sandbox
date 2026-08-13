pub mod policy;
mod l7;
mod secret;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, BufRead, Seek, SeekFrom},
    time::Duration,
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

#[derive(Deserialize, Debug, Clone)]
struct LogEvent {
    ev: Option<String>,
    id: Option<String>,
    ts: Option<u64>,
    host: Option<String>,
    port: Option<u16>,
    method: Option<String>,
}

fn load_policy_lines(policy_dir: &str) -> Vec<String> {
    let policy_path = format!("{}/policy", policy_dir);
    if let Ok(content) = fs::read_to_string(&policy_path) {
        content.lines().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    }
}

fn install_policy(policy_dir: &str, entries: &[String]) -> Result<(), String> {
    let policy_path = format!("{}/policy", policy_dir);
    let new_path = format!("{}/.policy.new", policy_dir);
    
    let content = entries.join("\n") + "\n";
    if let Err(e) = policy::parse_policy(&content, Duration::from_secs(300)) {
        return Err(e);
    }
    
    if let Err(e) = fs::write(&new_path, &content) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    if let Err(e) = fs::rename(&new_path, &policy_path) {
        let _ = fs::remove_file(&new_path);
        return Err(e.to_string());
    }
    Ok(())
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

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _cleanup = TerminalCleanup;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut pending_reqs = HashMap::new();
    let mut resolved_reqs = HashSet::new();
    let mut selected_idx = 0;
    let mut status_msg = String::new();
    let mut file_pos = 0;
    
    let mut file = None;

    loop {
        if file.is_none() {
            if let Ok(f) = fs::File::open(&pending_log) {
                file = Some(io::BufReader::new(f));
            }
        }
        
        if let Some(ref mut reader) = file {
            let _ = reader.seek(SeekFrom::Start(file_pos));
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
                            resolved_reqs.insert(id);
                        }
                    }
                }
                line.clear();
            }
            if let Ok(pos) = reader.stream_position() {
                file_pos = pos;
            }
        }

        let mut req_list: Vec<_> = pending_reqs.values().cloned().collect();
        req_list.sort_by_key(|r| r.ts.unwrap_or(0));

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

            let title = Paragraph::new(format!(" Agent Sandbox Ask-Mode TUI — {} ", sandbox_name))
                .style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray).fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let selected_style = Style::default().add_modifier(Modifier::REVERSED);
            let normal_style = Style::default();

            if req_list.is_empty() {
                let p = Paragraph::new("No pending network requests. Waiting for sandbox egress...")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL).title("Pending Requests (0)"));
                f.render_widget(p, chunks[1]);
                selected_idx = 0;
            } else {
                if selected_idx >= req_list.len() {
                    selected_idx = req_list.len().saturating_sub(1);
                }
                let rows = req_list.iter().enumerate().map(|(i, req)| {
                    let host = req.host.as_deref().unwrap_or("unknown");
                    let port = req.port.unwrap_or(0);
                    let method = req.method.as_deref().unwrap_or("");
                    let style = if i == selected_idx { selected_style } else { normal_style };
                    
                    let method_style = match method {
                        "GET" | "POST" | "PUT" | "DELETE" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                        "CONNECT" => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        _ => Style::default().fg(Color::White),
                    };

                    Row::new(vec![
                        ratatui::text::Span::styled(method.to_string(), method_style),
                        ratatui::text::Span::raw(host.to_string()),
                        ratatui::text::Span::raw(port.to_string()),
                    ]).style(style)
                });
                
                let table = Table::new(rows, [Constraint::Length(10), Constraint::Percentage(65), Constraint::Length(10)])
                    .header(Row::new(vec!["Method", "Destination Host/IP", "Port"]).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)))
                    .block(Block::default().borders(Borders::ALL).title(format!("Pending Requests ({})", req_list.len())));
                f.render_widget(table, chunks[1]);
            }

            let instructions = Paragraph::new("[a] Allow domain  [h] Allow HTTP route (domain+method)  [d] Deny domain\n[A] Allow IP      [D] Deny IP                             [q] Quit")
                .block(Block::default().borders(Borders::ALL).title("Keybindings"));
            f.render_widget(instructions, chunks[2]);

            if !status_msg.is_empty() {
                let status = Paragraph::new(status_msg.as_str())
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
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
                        selected_idx = (selected_idx + 1).min(req_list.len().saturating_sub(1));
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Char('h') => {
                        if !req_list.is_empty() && selected_idx < req_list.len() {
                            let req = &req_list[selected_idx];
                            if let Some(ref host) = req.host {
                                let mut policy = load_policy_lines(sidecar_policy);
                                match key.code {
                                    KeyCode::Char('a') => policy.push(format!("allow_domains {}", host)),
                                    KeyCode::Char('d') => policy.push(format!("deny_domains {}", host)),
                                    KeyCode::Char('A') => policy.push(format!("allow_ips {}", host)),
                                    KeyCode::Char('D') => policy.push(format!("deny_ips {}", host)),
                                    KeyCode::Char('h') => {
                                        if let Some(ref method) = req.method {
                                            policy.push(format!("allow_l7\t{}\t{}\t/*", host, method));
                                        }
                                    }
                                    _ => {}
                                }
                                if let Err(e) = install_policy(sidecar_policy, &policy) {
                                    status_msg = format!("Error: {}", e);
                                } else {
                                    status_msg.clear();
                                    std::thread::sleep(Duration::from_millis(100));
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
