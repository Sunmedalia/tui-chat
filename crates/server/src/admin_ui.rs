use std::{io, path::Path, time::Duration};

use anyhow::{Result, anyhow};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
};
use uuid::Uuid;

use crate::control::{AdminRequest, AdminSnapshot, request};

const TAB_TITLES: [&str; 5] = ["Dashboard", "Users", "Sessions", "Conversations", "Audit"];

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(stdout))?,
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
        let _ = disable_raw_mode();
    }
}

pub async fn run(socket: &Path) -> Result<()> {
    let mut snapshot = load_snapshot(socket).await?;
    let mut terminal = TerminalGuard::enter()?;
    let mut tab = 0_usize;
    let mut selected = 0_usize;
    let mut status = "Tab 切换页面 · F5 刷新 · Delete 管理在线会话 · Ctrl-C 退出".to_owned();
    let mut confirm_kick: Option<Uuid> = None;

    loop {
        terminal.terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(4),
                    Constraint::Length(1),
                ])
                .split(frame.area());
            frame.render_widget(
                Tabs::new(
                    TAB_TITLES
                        .iter()
                        .copied()
                        .map(Line::from)
                        .collect::<Vec<_>>(),
                )
                .select(tab)
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(
                    Block::default()
                        .title("tui-chat 管理")
                        .borders(Borders::ALL),
                ),
                areas[0],
            );
            let rows = rows_for(&snapshot, tab);
            let items: Vec<_> = rows
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    let style = if index == selected {
                        Style::default().fg(Color::Black).bg(Color::Cyan)
                    } else {
                        Style::default()
                    };
                    ListItem::new(row.as_str()).style(style)
                })
                .collect();
            frame.render_widget(
                List::new(items).block(Block::default().borders(Borders::ALL)),
                areas[1],
            );
            frame.render_widget(Paragraph::new(status.as_str()), areas[2]);
        })?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            break;
        }
        if confirm_kick.is_some() {
            match key.code {
                KeyCode::Enter => {
                    let Some(session_id) = confirm_kick.take() else {
                        continue;
                    };
                    let response =
                        request(socket, &AdminRequest::KickSession { session_id }).await?;
                    status = response.message;
                    snapshot = load_snapshot(socket).await?;
                    selected = selected.min(snapshot.sessions.len().saturating_sub(1));
                }
                KeyCode::Esc => {
                    confirm_kick = None;
                    status = "已取消".to_owned();
                }
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Tab => {
                tab = (tab + 1) % TAB_TITLES.len();
                selected = 0;
            }
            KeyCode::BackTab => {
                tab = (tab + TAB_TITLES.len() - 1) % TAB_TITLES.len();
                selected = 0;
            }
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => {
                selected = (selected + 1).min(rows_for(&snapshot, tab).len().saturating_sub(1));
            }
            KeyCode::F(5) => {
                snapshot = load_snapshot(socket).await?;
                status = "已刷新".to_owned();
            }
            KeyCode::Delete if tab == 2 => {
                if let Some(session) = snapshot.sessions.get(selected) {
                    confirm_kick = Some(session.session_id);
                    status = format!(
                        "按 Enter 踢下线 {} / {}，Esc 取消",
                        session.username, session.device_id
                    );
                }
            }
            KeyCode::Esc => break,
            _ => {}
        }
    }
    Ok(())
}

async fn load_snapshot(socket: &Path) -> Result<AdminSnapshot> {
    let response = request(socket, &AdminRequest::Snapshot).await?;
    if !response.ok {
        return Err(anyhow!(response.message));
    }
    response
        .snapshot
        .ok_or_else(|| anyhow!("admin server returned no snapshot"))
}

fn rows_for(snapshot: &AdminSnapshot, tab: usize) -> Vec<String> {
    match tab {
        0 => vec![
            format!("用户：{}", snapshot.users.len()),
            format!("在线会话：{}", snapshot.sessions.len()),
            format!("聊天会话：{}", snapshot.conversations.len()),
            format!("最近审计事件：{}", snapshot.audit.len()),
        ],
        1 => snapshot
            .users
            .iter()
            .map(|user| {
                format!(
                    "{}  {}  active={} pending={} password_change={}",
                    user.username,
                    user.state,
                    user.active_devices,
                    user.pending_devices,
                    user.password_change_required
                )
            })
            .collect(),
        2 => snapshot
            .sessions
            .iter()
            .map(|session| {
                format!(
                    "{}  {}  {}  {}  pending={}",
                    session.session_id,
                    session.username,
                    session.device_id,
                    session.source_ip,
                    session.pending
                )
            })
            .collect(),
        3 => snapshot
            .conversations
            .iter()
            .map(|conversation| {
                format!(
                    "{} ↔ {}  messages={} envelopes={} bytes={} undelivered={}",
                    conversation.first_username,
                    conversation.second_username,
                    conversation.logical_messages,
                    conversation.envelopes,
                    conversation.ciphertext_bytes,
                    conversation.undelivered_envelopes
                )
            })
            .collect(),
        _ => snapshot
            .audit
            .iter()
            .map(|event| {
                format!(
                    "{}  {}  {}  {}  {}",
                    event.occurred_at_ms, event.category, event.actor, event.action, event.result
                )
            })
            .collect(),
    }
}
