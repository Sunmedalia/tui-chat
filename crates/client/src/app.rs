use std::{
    borrow::Cow,
    collections::HashMap,
    io,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use crossterm::{
    event::{
        DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
        EnableFocusChange, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
        KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Wrap,
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tui_chat_crypto::{
    EncryptedOlm, OlmMachine, PairingChannel, PairingState, PreKeyMaterial, safety_code,
    verify_device_bundle, verify_prekey,
};
use tui_chat_protocol::{
    conversation_id, decode_frame, encode_frame, frame,
    v1::{self, EncryptedEnvelope, SendEnvelopes, SyncRequest, UserBundle, frame::Body},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::editor::EditorState;
use crate::network::RawConnection;
use crate::{
    local::{
        ChatMessage, Contact, LocalStore, MESSAGE_PAGE_SIZE, MessageStatus, RuntimeProfile,
        TransferContact, VaultSession,
    },
    network::RpcClient,
};

#[derive(Debug, Serialize, Deserialize)]
struct WirePayload {
    version: u8,
    kind: String,
    message_id: String,
    sender_username: String,
    sender_account_id: String,
    peer_account_id: String,
    sent_at_ms: i64,
    text: String,
    related_message_id: Option<String>,
    #[serde(default)]
    related_message_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct BootstrapTransfer {
    master_secret: [u8; 32],
    contacts: Vec<TransferContact>,
}

#[derive(Serialize, Deserialize)]
struct HistoryTransfer {
    messages: Vec<ChatMessage>,
}

enum PairingRole {
    Approver,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    Conversations,
    Messages,
    Composer,
}

impl FocusPane {
    fn next(self) -> Self {
        match self {
            Self::Conversations => Self::Messages,
            Self::Messages => Self::Composer,
            Self::Composer => Self::Conversations,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Conversations => Self::Composer,
            Self::Messages => Self::Conversations,
            Self::Composer => Self::Messages,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DragTarget {
    Conversations,
    Messages,
}

#[derive(Default)]
struct CompletionState {
    candidates: Vec<String>,
    selected: usize,
}

impl CompletionState {
    fn is_open(&self) -> bool {
        !self.candidates.is_empty()
    }

    fn cycle(&mut self, direction: isize) {
        if self.candidates.is_empty() {
            return;
        }
        self.selected = (self.selected as isize + direction)
            .rem_euclid(self.candidates.len() as isize) as usize;
    }

    fn selected(&self) -> Option<&str> {
        self.candidates.get(self.selected).map(String::as_str)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct UiLayout {
    area: Rect,
    conversations: Rect,
    messages: Rect,
    composer: Rect,
    status: Rect,
    narrow: bool,
}

struct TerminalSession {
    terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
    mouse_enabled: bool,
}

struct InputTask(tokio::task::JoinHandle<()>);

impl Drop for InputTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn_terminal_input() -> (
    mpsc::UnboundedReceiver<std::result::Result<Event, String>>,
    watch::Receiver<bool>,
    InputTask,
) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (exit_tx, exit_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut stream = EventStream::new();
        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Key(key))
                    if key.kind == KeyEventKind::Press
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c' | 'q')) =>
                {
                    let _ = exit_tx.send(true);
                    break;
                }
                Ok(event) => {
                    if event_tx.send(Ok(event)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = event_tx.send(Err(error.to_string()));
                    break;
                }
            }
        }
    });
    (event_rx, exit_rx, InputTask(task))
}

impl TerminalSession {
    fn enter(mouse_enabled: bool) -> Result<Self> {
        enable_raw_mode()?;
        let mut session = Self {
            terminal: None,
            mouse_enabled,
        };
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableFocusChange
        )?;
        if mouse_enabled {
            execute!(stdout, EnableMouseCapture)?;
        }
        session.terminal = Some(Terminal::new(CrosstermBackend::new(stdout))?);
        Ok(session)
    }

    fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        self.terminal
            .as_mut()
            .expect("terminal session is initialized")
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.as_mut() {
            if self.mouse_enabled {
                let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
            }
            let _ = execute!(
                terminal.backend_mut(),
                DisableFocusChange,
                DisableBracketedPaste,
                LeaveAlternateScreen
            );
            let _ = terminal.show_cursor();
        } else {
            let mut stdout = io::stdout();
            if self.mouse_enabled {
                let _ = execute!(stdout, DisableMouseCapture);
            }
            let _ = execute!(
                stdout,
                DisableFocusChange,
                DisableBracketedPaste,
                LeaveAlternateScreen
            );
        }
        let _ = disable_raw_mode();
    }
}

impl UiLayout {
    fn calculate(area: Rect, focus: FocusPane, editor_lines: usize) -> Self {
        let composer_height = (editor_lines as u16 + 2).clamp(3, 7);
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(4),
                Constraint::Length(composer_height),
                Constraint::Length(1),
            ])
            .split(area);
        let narrow = area.width < 72;
        let (conversations, messages) = if narrow {
            if focus == FocusPane::Conversations {
                (outer[0], Rect::default())
            } else {
                (Rect::default(), outer[0])
            }
        } else {
            let main = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(outer[0]);
            (main[0], main[1])
        };
        Self {
            area,
            conversations,
            messages,
            composer: outer[1],
            status: outer[2],
            narrow,
        }
    }
}

struct PairingSession {
    pairing_id: String,
    peer_device_id: String,
    pending_device: v1::DeviceBundle,
    channel: PairingChannel,
    role: PairingRole,
    our_confirmed: bool,
    peer_confirmed: bool,
}

pub struct App {
    store: LocalStore,
    vault: VaultSession,
    pub profile: RuntimeProfile,
    rpc: RpcClient,
    events: mpsc::Receiver<v1::Frame>,
    contacts: Vec<Contact>,
    selected: Option<usize>,
    messages: Vec<ChatMessage>,
    editor: EditorState,
    focus: FocusPane,
    completion: CompletionState,
    help_visible: bool,
    redraw_requested: bool,
    contact_scroll: usize,
    message_scroll: usize,
    new_messages_below: usize,
    history_exhausted: bool,
    persisted_draft: String,
    layout: UiLayout,
    dragging: Option<DragTarget>,
    mouse_enabled: bool,
    terminal_focused: bool,
    status: String,
    connected: bool,
    quit: bool,
    pairing_requests: Vec<v1::PairingRequest>,
    pairing: Option<PairingSession>,
    bundle_cache: HashMap<String, (UserBundle, Instant)>,
    reconnect_at: Instant,
    reconnect_backoff: u64,
}

impl App {
    pub async fn new(
        store: LocalStore,
        vault: VaultSession,
        profile: RuntimeProfile,
        rpc: RpcClient,
        events: mpsc::Receiver<v1::Frame>,
        mouse_enabled: bool,
    ) -> Result<Self> {
        let contacts = store.contacts().await?;
        let migration_store = store.clone();
        let migration_vault = vault.clone();
        tokio::spawn(async move {
            let _ = migration_store
                .migrate_legacy_messages(&migration_vault)
                .await;
        });
        let mut app = Self {
            store,
            vault,
            profile,
            rpc,
            events,
            contacts,
            selected: None,
            messages: vec![],
            editor: EditorState::new(),
            focus: FocusPane::Composer,
            completion: CompletionState::default(),
            help_visible: false,
            redraw_requested: false,
            contact_scroll: 0,
            message_scroll: 0,
            new_messages_below: 0,
            history_exhausted: false,
            persisted_draft: String::new(),
            layout: UiLayout::default(),
            dragging: None,
            mouse_enabled,
            terminal_focused: true,
            status: "输入 /chat 用户名 开始私聊；/help 查看命令".to_owned(),
            connected: true,
            quit: false,
            pairing_requests: vec![],
            pairing: None,
            bundle_cache: HashMap::new(),
            reconnect_at: Instant::now(),
            reconnect_backoff: 1,
        };
        app.resend_outbox().await;
        let _ = app.sync().await;
        Ok(app)
    }

    pub async fn run(mut self) -> Result<()> {
        let mut session = TerminalSession::enter(self.mouse_enabled)?;
        let result = self.event_loop(session.terminal_mut()).await;
        let _ = self.save_current_draft().await;
        result
    }

    async fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        let (mut terminal_events, mut exit_requested, _input_task) = spawn_terminal_input();
        let mut service_tick = tokio::time::interval(Duration::from_secs(1));
        service_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut render_tick = tokio::time::interval(Duration::from_millis(16));
        render_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut heartbeat_counter = 0_u8;
        let mut dirty = true;
        let interrupt = tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        while !self.quit {
            tokio::select! {
                _ = render_tick.tick(), if dirty => {
                    terminal.draw(|frame| self.draw(frame))?;
                    dirty = false;
                }
                event = terminal_events.recv() => {
                    match event {
                        Some(Ok(event)) => {
                            self.handle_terminal_event(event).await?;
                            if self.redraw_requested {
                                terminal.clear()?;
                                self.redraw_requested = false;
                            }
                        }
                        Some(Err(error)) => return Err(anyhow!(error)),
                        None => self.quit = true,
                    }
                    dirty = true;
                }
                server = self.events.recv(), if self.connected => {
                    if let Some(server) = server {
                        if let Err(error) = self.handle_server_event(server).await {
                            tracing::warn!(%error, "failed to process a server event");
                            self.status = format!(
                                "处理一条服务端事件失败，已保持 TUI 运行：{error:#}"
                            );
                        }
                    } else {
                        self.connected = false;
                        self.status = "连接已关闭；退出后重新启动将按游标续传".to_owned();
                    }
                    dirty = true;
                }
                _ = service_tick.tick() => {
                    self.service_step(&mut heartbeat_counter).await;
                    dirty = true;
                }
                _ = &mut interrupt => self.quit = true,
                _ = exit_requested.changed() => self.quit = true,
            }
        }
        Ok(())
    }

    async fn service_step(&mut self, heartbeat_counter: &mut u8) {
        if let Err(error) = self.autosave_draft().await {
            self.status = format!("草稿自动保存失败：{error:#}");
        }
        if self.connected {
            *heartbeat_counter = heartbeat_counter.wrapping_add(1);
            if heartbeat_counter.is_multiple_of(20) {
                let _ = self
                    .rpc
                    .notify(Body::Ping(v1::Ping {
                        sent_at_ms: now_ms(),
                    }))
                    .await;
            }
        } else if Instant::now() >= self.reconnect_at {
            self.try_reconnect().await;
        }
    }

    fn draw(&mut self, frame: &mut ratatui::Frame<'_>) {
        if frame.area().width < 32 || frame.area().height < 10 {
            frame.render_widget(
                Paragraph::new("终端至少需要 32×10；Ctrl-C 仍可退出")
                    .block(Block::default().title("窗口过小").borders(Borders::ALL)),
                frame.area(),
            );
            self.layout = UiLayout {
                area: frame.area(),
                ..UiLayout::default()
            };
            return;
        }
        let editor_lines = editor_visual_line_count(
            self.editor.as_str(),
            frame.area().width.saturating_sub(2).max(1),
        )
        .max(self.editor.line_count());
        self.layout = UiLayout::calculate(frame.area(), self.focus, editor_lines);
        let layout = self.layout;

        let contact_height = usize::from(layout.conversations.height.saturating_sub(2)).max(1);
        if let Some(selected) = self.selected {
            if selected < self.contact_scroll {
                self.contact_scroll = selected;
            } else if selected >= self.contact_scroll + contact_height {
                self.contact_scroll = selected + 1 - contact_height;
            }
        }
        let contacts: Vec<_> = self
            .contacts
            .iter()
            .enumerate()
            .skip(self.contact_scroll)
            .take(contact_height)
            .map(|(index, contact)| {
                let marker = if contact.identity_changed {
                    "!"
                } else if contact.verified {
                    "✓"
                } else {
                    "?"
                };
                let style = if Some(index) == self.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                let unread = if contact.unread_count > 0 {
                    format!("  {}", contact.unread_count)
                } else {
                    String::new()
                };
                let activity = if contact.last_activity_ms > 0 {
                    chrono::DateTime::from_timestamp_millis(contact.last_activity_ms)
                        .map(|time| {
                            time.with_timezone(&chrono::Local)
                                .format("%H:%M")
                                .to_string()
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let suffix = if activity.is_empty() {
                    unread
                } else {
                    format!("{unread}  {activity}")
                };
                ListItem::new(format!("{marker} {}{suffix}", contact.bundle.username)).style(style)
            })
            .collect();
        if layout.conversations.area() > 0 {
            let title = if layout.narrow {
                "会话 · Tab 进入聊天"
            } else {
                "会话"
            };
            frame.render_widget(
                List::new(contacts)
                    .block(focus_block(title, self.focus == FocusPane::Conversations)),
                layout.conversations,
            );
            if self.contacts.len() > contact_height {
                let mut state = ScrollbarState::new(self.contacts.len())
                    .position(self.contact_scroll)
                    .viewport_content_length(contact_height);
                frame.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight),
                    layout.conversations,
                    &mut state,
                );
            }
        }

        let visible_messages = usize::from(layout.messages.height.saturating_sub(2)).max(1);
        let lines: Vec<Line<'_>> = if self.messages.is_empty() {
            vec![Line::from(Span::styled(
                "没有消息",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            self.messages
                .iter()
                .map(|message| {
                    let sender = if message.inbound {
                        self.selected_contact()
                            .map(|c| c.bundle.username.as_str())
                            .unwrap_or("对方")
                    } else {
                        "我"
                    };
                    let color = if message.inbound {
                        Color::Green
                    } else {
                        Color::Cyan
                    };
                    Line::from(vec![
                        Span::styled(
                            format!("{sender}: "),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(sanitize_terminal_text(&message.body)),
                        Span::styled(
                            format!("  [{}]", message.status.label()),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ])
                })
                .collect()
        };
        let title = self
            .selected_contact()
            .map(|contact| format!("与 {} 的私聊", contact.bundle.username))
            .unwrap_or_else(|| "消息".to_owned());
        if layout.messages.area() > 0 {
            let title = if self.new_messages_below > 0 && self.message_scroll > 0 {
                format!(
                    "{title} · {} 条新消息 · End 到底部",
                    self.new_messages_below
                )
            } else {
                title
            };
            let mut paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
            let visual_lines = self.visual_lines_for_messages(&self.messages).max(1);
            let maximum = visual_lines.saturating_sub(visible_messages);
            self.message_scroll = self.message_scroll.min(maximum);
            let from_top = maximum.saturating_sub(self.message_scroll);
            paragraph = paragraph
                .scroll((from_top.min(usize::from(u16::MAX)) as u16, 0))
                .block(focus_block(&title, self.focus == FocusPane::Messages));
            frame.render_widget(paragraph, layout.messages);
            if visual_lines > visible_messages {
                let mut state = ScrollbarState::new(visual_lines)
                    .position(from_top)
                    .viewport_content_length(visible_messages);
                frame.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight),
                    layout.messages,
                    &mut state,
                );
            }
        }

        let (cursor_row, cursor_column) = editor_cursor_position(
            self.editor.as_str(),
            self.editor.cursor(),
            layout.composer.width.saturating_sub(2).max(1),
        );
        let inner_height = layout.composer.height.saturating_sub(2).max(1);
        let editor_scroll = cursor_row.saturating_sub(inner_height.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(self.editor.as_str())
                .scroll((editor_scroll, 0))
                .wrap(Wrap { trim: false })
                .block(focus_block(
                    "输入 · Enter 发送 · Shift-Enter 换行",
                    self.focus == FocusPane::Composer,
                )),
            layout.composer,
        );
        let state = if self.connected {
            "● 已连接"
        } else {
            "○ 已断开"
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    state,
                    Style::default().fg(if self.connected {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                ),
                Span::raw("  "),
                Span::raw(sanitize_terminal_text(&self.status)),
            ])),
            layout.status,
        );

        self.render_completion(frame);
        if self.help_visible {
            self.render_help(frame);
        }
        if self.focus == FocusPane::Composer && !self.help_visible {
            frame.set_cursor_position(Position::new(
                layout.composer.x + 1 + cursor_column,
                layout.composer.y + 1 + cursor_row.saturating_sub(editor_scroll),
            ));
        }
    }

    async fn handle_terminal_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::FocusGained => {
                let was_focused = self.terminal_focused;
                self.terminal_focused = true;
                if !was_focused {
                    self.mark_selected_read().await?;
                }
                Ok(())
            }
            Event::FocusLost => {
                self.terminal_focused = false;
                Ok(())
            }
            Event::Key(key) => self.handle_key(key).await,
            Event::Mouse(mouse) if self.mouse_enabled => self.handle_mouse(mouse).await,
            Event::Paste(text) => {
                self.focus = FocusPane::Composer;
                if !self.editor.insert(&text, tui_chat_protocol::MAX_TEXT_BYTES) {
                    self.status = "粘贴内容已截断到 16 KiB".to_owned();
                }
                self.refresh_completion();
                Ok(())
            }
            Event::Resize(width, height) => {
                self.layout.area.width = width;
                self.layout.area.height = height;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        if key.kind != KeyEventKind::Press {
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'q'))
        {
            self.quit = true;
            return Ok(());
        }
        if key.code == KeyCode::F(1) {
            self.help_visible = !self.help_visible;
            return Ok(());
        }
        if self.help_visible {
            if key.code == KeyCode::Esc {
                self.help_visible = false;
            }
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Up => return self.select_relative(-1).await,
                KeyCode::Down => return self.select_relative(1).await,
                KeyCode::Backspace => {
                    self.editor.delete_word_backward();
                    self.refresh_completion();
                    return Ok(());
                }
                KeyCode::Enter => {
                    self.focus = FocusPane::Composer;
                    self.editor.insert("\n", tui_chat_protocol::MAX_TEXT_BYTES);
                    self.refresh_completion();
                    return Ok(());
                }
                _ => {}
            }
        }
        if key.code == KeyCode::Tab || key.code == KeyCode::BackTab {
            let backwards =
                key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT);
            if self.focus == FocusPane::Composer && self.completion.is_open() {
                let already_applied = self
                    .completion
                    .selected()
                    .is_some_and(|candidate| candidate == self.editor.as_str());
                if already_applied || backwards {
                    self.completion.cycle(if backwards { -1 } else { 1 });
                }
                self.apply_completion();
            } else {
                self.focus = if backwards {
                    self.focus.previous()
                } else {
                    self.focus.next()
                };
            }
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('a') => self.editor.move_start(),
                KeyCode::Char('e') => self.editor.move_end(),
                KeyCode::Char('w') => self.editor.delete_word_backward(),
                KeyCode::Char('u') => self.editor.delete_to_line_start(),
                KeyCode::Char('d') => self.editor.delete_forward(),
                KeyCode::Char('k') => {
                    self.focus = FocusPane::Composer;
                    self.editor.set("/".to_owned());
                    self.refresh_completion();
                }
                KeyCode::Char('f') => {
                    self.focus = FocusPane::Composer;
                    self.editor.set("/search ".to_owned());
                    self.refresh_completion();
                    self.status = "输入关键词后按 Enter，搜索当前已加载的会话历史".to_owned();
                }
                KeyCode::Char('r') => {
                    if self.connected {
                        self.sync().await?;
                    } else {
                        self.reconnect_at = Instant::now();
                        self.try_reconnect().await;
                    }
                }
                KeyCode::Char('l') => self.redraw_requested = true,
                KeyCode::Char('p') if self.completion.is_open() => self.completion.cycle(-1),
                KeyCode::Char('n') if self.completion.is_open() => self.completion.cycle(1),
                KeyCode::Home if self.focus == FocusPane::Messages => {
                    self.scroll_messages_to_top();
                    self.load_older_messages().await?;
                }
                KeyCode::End if self.focus == FocusPane::Messages => {
                    self.scroll_messages_to_bottom()
                }
                _ => return Ok(()),
            }
            self.refresh_completion();
            return Ok(());
        }
        match key.code {
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.focus = FocusPane::Composer;
                self.editor.insert("\n", tui_chat_protocol::MAX_TEXT_BYTES);
            }
            KeyCode::Enter => {
                if self.completion.is_open()
                    && self
                        .completion
                        .selected()
                        .is_some_and(|candidate| candidate != self.editor.as_str())
                {
                    self.apply_completion();
                    return Ok(());
                }
                let input = self.editor.as_str().to_owned();
                if !input.trim().is_empty() && self.execute_input(&input).await {
                    if !input.trim_start().starts_with("/chat ") {
                        self.editor.clear();
                    }
                    self.completion = CompletionState::default();
                }
            }
            KeyCode::Backspace => {
                self.editor.delete_backward();
                self.refresh_completion();
            }
            KeyCode::Delete => {
                self.editor.delete_forward();
                self.refresh_completion();
            }
            KeyCode::Left => self.editor.move_left(),
            KeyCode::Right => self.editor.move_right(),
            KeyCode::Home => self.editor.move_line_start(),
            KeyCode::End if self.focus == FocusPane::Messages => self.scroll_messages_to_bottom(),
            KeyCode::End => self.editor.move_line_end(),
            KeyCode::Char(character) => {
                self.focus = FocusPane::Composer;
                let mut bytes = [0_u8; 4];
                self.editor.insert(
                    character.encode_utf8(&mut bytes),
                    tui_chat_protocol::MAX_TEXT_BYTES,
                );
                self.refresh_completion();
            }
            KeyCode::Up if self.completion.is_open() => self.completion.cycle(-1),
            KeyCode::Down if self.completion.is_open() => self.completion.cycle(1),
            KeyCode::Up => match self.focus {
                FocusPane::Conversations => self.select_relative(-1).await?,
                FocusPane::Messages => {
                    self.scroll_messages(3);
                    self.load_older_messages().await?;
                }
                FocusPane::Composer => self.editor.move_vertical(-1),
            },
            KeyCode::Down => match self.focus {
                FocusPane::Conversations => self.select_relative(1).await?,
                FocusPane::Messages => self.scroll_messages(-3),
                FocusPane::Composer => self.editor.move_vertical(1),
            },
            KeyCode::PageUp => {
                self.focus = FocusPane::Messages;
                self.scroll_messages(i32::from(self.layout.messages.height.saturating_sub(3)));
                self.load_older_messages().await?;
            }
            KeyCode::PageDown => {
                self.focus = FocusPane::Messages;
                self.scroll_messages(-i32::from(self.layout.messages.height.saturating_sub(3)));
            }
            KeyCode::Esc if self.completion.is_open() => {
                self.completion = CompletionState::default()
            }
            KeyCode::Esc => self.focus = FocusPane::Composer,
            _ => {}
        }
        Ok(())
    }

    async fn execute_input(&mut self, input: &str) -> bool {
        let trimmed = input.trim();
        let result = if matches!(trimmed, "/quit" | "/exit") {
            self.quit = true;
            Ok(())
        } else if trimmed == "/help" {
            self.help_visible = true;
            Ok(())
        } else if trimmed == "/verify" {
            self.verify_selected().await
        } else if trimmed == "/confirm" {
            self.confirm_pairing().await
        } else if trimmed == "/pair" {
            self.start_pairing(None).await
        } else if let Some(device) = trimmed.strip_prefix("/pair ") {
            self.start_pairing(Some(device.trim())).await
        } else if trimmed == "/sync" {
            self.sync().await
        } else if let Some(query) = trimmed.strip_prefix("/search ") {
            self.search_loaded_messages(query.trim())
        } else if let Some(username) = trimmed.strip_prefix("/chat ") {
            self.open_contact(username.trim()).await
        } else if let Some(message) = input.strip_prefix("//") {
            self.send_text(&format!("/{message}")).await
        } else if trimmed.starts_with('/') {
            Err(anyhow!(
                "未知命令；输入 /help 查看命令，使用 // 发送以 / 开头的消息"
            ))
        } else {
            self.send_text(input).await
        };
        if let Err(error) = result {
            self.status = format!("错误：{error:#}");
            false
        } else {
            true
        }
    }

    fn refresh_completion(&mut self) {
        let input = self.editor.as_str();
        if self.editor.cursor() != input.len() || !input.starts_with('/') || input.starts_with("//")
        {
            self.completion = CompletionState::default();
            return;
        }
        let commands = [
            "/chat ", "/search ", "/verify", "/pair ", "/confirm", "/sync", "/help", "/exit",
            "/quit",
        ];
        let candidates = if let Some(prefix) = input.strip_prefix("/chat ") {
            self.contacts
                .iter()
                .filter(|contact| contact.bundle.username.starts_with(prefix))
                .map(|contact| format!("/chat {}", contact.bundle.username))
                .collect()
        } else if let Some(prefix) = input.strip_prefix("/pair ") {
            self.pairing_requests
                .iter()
                .filter(|request| {
                    request.pending_device_id.starts_with(prefix)
                        || request.pending_device_name.starts_with(prefix)
                })
                .map(|request| format!("/pair {}", request.pending_device_id))
                .collect()
        } else if !input.contains(' ') {
            commands
                .into_iter()
                .filter(|command| command.starts_with(input))
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        let selected = self
            .completion
            .selected()
            .and_then(|old| candidates.iter().position(|candidate| candidate == old))
            .unwrap_or(0);
        self.completion = CompletionState {
            candidates,
            selected,
        };
    }

    fn apply_completion(&mut self) {
        if let Some(candidate) = self.completion.selected().map(str::to_owned) {
            self.editor.set(candidate);
        }
    }

    fn render_completion(&self, frame: &mut ratatui::Frame<'_>) {
        if !self.completion.is_open() || self.help_visible {
            return;
        }
        let count = self.completion.candidates.len().min(6) as u16;
        let height = count + 2;
        let width = self.layout.composer.width.clamp(20, 48);
        let area = Rect::new(
            self.layout.composer.x,
            self.layout.composer.y.saturating_sub(height),
            width,
            height,
        );
        let first = self.completion.selected.saturating_sub(5);
        let items: Vec<_> = self
            .completion
            .candidates
            .iter()
            .skip(first)
            .take(6)
            .enumerate()
            .map(|(index, candidate)| {
                let style = if first + index == self.completion.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(candidate.as_str()).style(style)
            })
            .collect();
        frame.render_widget(Clear, area);
        frame.render_widget(
            List::new(items).block(Block::default().title("Tab 补全").borders(Borders::ALL)),
            area,
        );
    }

    fn render_help(&self, frame: &mut ratatui::Frame<'_>) {
        let width = frame.area().width.saturating_sub(4).min(70);
        let height = frame.area().height.saturating_sub(2).min(20);
        let area = centered_rect(width, height, frame.area());
        let help = [
            Line::from(Span::styled(
                "安全私聊操作",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Tab / Shift-Tab     切换焦点或补全"),
            Line::from("Alt-Up / Alt-Down   切换会话"),
            Line::from("PageUp / PageDown   滚动消息"),
            Line::from("Ctrl-Home / End     消息顶部 / 底部"),
            Line::from("Enter / Shift/Alt-Enter  发送 / 换行"),
            Line::from("Ctrl-A/E/W/U        文首 / 文末 / 删词 / 删到行首"),
            Line::from("Ctrl-K / Ctrl-F     命令面板 / 搜索已加载消息"),
            Line::from("Ctrl-R / Ctrl-L     同步重连 / 重绘屏幕"),
            Line::from("Ctrl-C / Ctrl-Q      退出"),
            Line::from(""),
            Line::from("/chat 用户名 · /search 关键词 · /verify · /pair · /confirm · /sync"),
            Line::from("/exit · /quit · //文本（发送以 / 开头的正文）"),
            Line::from(""),
            Line::from(Span::styled(
                "Esc 或 F1 关闭帮助",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(help.to_vec())
                .wrap(Wrap { trim: false })
                .block(focus_block("帮助", true)),
            area,
        );
    }

    async fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        let position = Position::new(mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if self.layout.conversations.contains(position) {
                    self.focus = FocusPane::Conversations;
                    if mouse.column == self.layout.conversations.right().saturating_sub(1) {
                        self.dragging = Some(DragTarget::Conversations);
                        self.drag_scrollbar(mouse.row);
                    } else if mouse.row > self.layout.conversations.y
                        && mouse.row < self.layout.conversations.bottom().saturating_sub(1)
                    {
                        let index = self.contact_scroll
                            + usize::from(mouse.row - self.layout.conversations.y - 1);
                        if index < self.contacts.len() {
                            self.save_current_draft().await?;
                            self.selected = Some(index);
                            self.load_selected_messages().await?;
                            if self.selected_contact().is_some_and(|contact| {
                                !contact.verified || contact.identity_changed
                            }) {
                                self.show_safety_code();
                            }
                        }
                    }
                } else if self.layout.messages.contains(position) {
                    self.focus = FocusPane::Messages;
                    if mouse.column == self.layout.messages.right().saturating_sub(1) {
                        self.dragging = Some(DragTarget::Messages);
                        self.drag_scrollbar(mouse.row);
                    }
                } else if self.layout.composer.contains(position) {
                    self.focus = FocusPane::Composer;
                    let wrap_width = self.layout.composer.width.saturating_sub(2).max(1);
                    let (cursor_row, _) = editor_cursor_position(
                        self.editor.as_str(),
                        self.editor.cursor(),
                        wrap_width,
                    );
                    let inner_height = self.layout.composer.height.saturating_sub(2).max(1);
                    let editor_scroll = cursor_row.saturating_sub(inner_height.saturating_sub(1));
                    let line = usize::from(
                        mouse
                            .row
                            .saturating_sub(self.layout.composer.y.saturating_add(1)),
                    ) + usize::from(editor_scroll);
                    let column = usize::from(
                        mouse
                            .column
                            .saturating_sub(self.layout.composer.x.saturating_add(1)),
                    );
                    self.editor.set_cursor_by_visual_position(
                        line,
                        column,
                        usize::from(wrap_width),
                    );
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => self.drag_scrollbar(mouse.row),
            MouseEventKind::Up(MouseButton::Left) => {
                let load_older = self.dragging == Some(DragTarget::Messages);
                self.dragging = None;
                if load_older {
                    self.load_older_messages().await?;
                }
            }
            MouseEventKind::ScrollUp => {
                if self.layout.conversations.contains(position) {
                    self.contact_scroll = self.contact_scroll.saturating_sub(3);
                } else if self.layout.messages.contains(position) {
                    self.scroll_messages(3);
                    self.load_older_messages().await?;
                }
            }
            MouseEventKind::ScrollDown => {
                if self.layout.conversations.contains(position) {
                    let maximum = self.contacts.len().saturating_sub(usize::from(
                        self.layout.conversations.height.saturating_sub(2).max(1),
                    ));
                    self.contact_scroll = (self.contact_scroll + 3).min(maximum);
                } else if self.layout.messages.contains(position) {
                    self.scroll_messages(-3);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn drag_scrollbar(&mut self, row: u16) {
        match self.dragging {
            Some(DragTarget::Conversations) => {
                let inner = self.layout.conversations.height.saturating_sub(2).max(1);
                let relative = row
                    .saturating_sub(self.layout.conversations.y.saturating_add(1))
                    .min(inner);
                let maximum = self.contacts.len().saturating_sub(usize::from(inner));
                self.contact_scroll = maximum * usize::from(relative) / usize::from(inner);
            }
            Some(DragTarget::Messages) => {
                let inner = self.layout.messages.height.saturating_sub(2).max(1);
                let relative = row
                    .saturating_sub(self.layout.messages.y.saturating_add(1))
                    .min(inner);
                let maximum = self.message_scroll_maximum();
                let from_top = maximum * usize::from(relative) / usize::from(inner);
                self.message_scroll = maximum.saturating_sub(from_top);
                if self.message_scroll == 0 {
                    self.new_messages_below = 0;
                }
            }
            None => {}
        }
    }

    fn scroll_messages(&mut self, delta: i32) {
        let maximum = self.message_scroll_maximum();
        self.message_scroll = if delta >= 0 {
            (self.message_scroll + delta as usize).min(maximum)
        } else {
            self.message_scroll
                .saturating_sub(delta.unsigned_abs() as usize)
        };
        if self.message_scroll == 0 {
            self.new_messages_below = 0;
        }
    }

    fn scroll_messages_to_bottom(&mut self) {
        self.message_scroll = 0;
        self.new_messages_below = 0;
    }

    fn scroll_messages_to_top(&mut self) {
        self.message_scroll = self.message_scroll_maximum();
    }

    async fn load_older_messages(&mut self) -> Result<()> {
        if self.history_exhausted || self.messages.is_empty() {
            return Ok(());
        }
        let maximum = self.message_scroll_maximum();
        if self.message_scroll < maximum {
            return Ok(());
        }
        let Some(contact) = self.selected_contact() else {
            return Ok(());
        };
        let conversation = conversation_id(&self.profile.account_id, &contact.bundle.account_id);
        let oldest = self
            .messages
            .first()
            .map(|message| (message.sent_at_ms, message.id.clone()))
            .ok_or_else(|| anyhow!("消息页为空"))?;
        let older = self
            .store
            .messages_before(&self.vault, &conversation, oldest.0, &oldest.1)
            .await?;
        self.history_exhausted = older.len() < MESSAGE_PAGE_SIZE;
        if older.is_empty() {
            self.status = "已到达本地历史消息顶部".to_owned();
            return Ok(());
        }
        let loaded = older.len();
        let loaded_visual_lines = self.visual_lines_for_messages(&older);
        self.messages.splice(0..0, older);
        let maximum = self.message_scroll_maximum();
        let viewport = usize::from(self.layout.messages.height.saturating_sub(2).max(1));
        self.message_scroll =
            (self.message_scroll + loaded_visual_lines.min(viewport)).min(maximum);
        self.status = format!("已加载更早的 {loaded} 条消息");
        Ok(())
    }

    async fn open_contact(&mut self, username: &str) -> Result<()> {
        self.save_current_draft().await?;
        let response = self
            .rpc
            .request(Body::LookupUser(v1::LookupUser {
                exact_username: username.to_owned(),
            }))
            .await?;
        let Some(Body::UserBundle(bundle)) = response.body else {
            bail!("服务器返回了错误的查询响应");
        };
        self.bundle_cache
            .insert(bundle.username.clone(), (bundle.clone(), Instant::now()));
        validate_bundle(&bundle)?;
        let contact = self.store.upsert_contact(&bundle).await?;
        let account_id = contact.bundle.account_id.clone();
        self.contacts = self.store.contacts().await?;
        self.selected = self
            .contacts
            .iter()
            .position(|item| item.bundle.account_id == account_id);
        self.load_selected_messages().await?;
        self.show_safety_code();
        Ok(())
    }

    async fn verify_selected(&mut self) -> Result<()> {
        let account = self
            .selected_contact()
            .ok_or_else(|| anyhow!("请先选择会话"))?
            .bundle
            .account_id
            .clone();
        self.store.verify_contact(&account).await?;
        if let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|contact| contact.bundle.account_id == account)
        {
            contact.verified = true;
            contact.identity_changed = false;
        }
        self.status =
            "联系人密钥已在本机标记为已核验；请确保你确实通过可信渠道比较过安全码".to_owned();
        self.sync().await?;
        Ok(())
    }

    fn show_safety_code(&mut self) {
        let Some(contact) = self.selected_contact() else {
            return;
        };
        let Some(our_master) = self.profile.identity.master_public_key() else {
            self.status = "该设备仍在等待旧设备配对".to_owned();
            return;
        };
        self.status = format!(
            "安全码：{}；通过电话/当面比较后输入 /verify",
            safety_code(
                &self.profile.username,
                &our_master,
                &contact.bundle.username,
                &contact.bundle.account_master_key
            )
        );
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        if text.len() > tui_chat_protocol::MAX_TEXT_BYTES {
            bail!("消息超过 16 KiB");
        }
        let contact = self
            .selected_contact()
            .cloned()
            .ok_or_else(|| anyhow!("使用 /chat <用户名> 选择会话"))?;
        if !contact.verified || contact.identity_changed {
            self.show_safety_code();
            bail!("必须先核验联系人安全码");
        }
        validate_bundle(&contact.bundle)?;
        let username = self.profile.username.clone();
        let self_bundle = self.lookup_bundle(&username).await?;
        if self_bundle.account_master_key
            != self
                .profile
                .identity
                .master_public_key()
                .unwrap_or_default()
        {
            bail!("服务器返回的本账号主密钥不匹配");
        }

        let logical_id = Uuid::now_v7().to_string();
        let sent_at = now_ms();
        let conversation = conversation_id(&self.profile.account_id, &contact.bundle.account_id);
        let payload = serde_json::to_vec(&WirePayload {
            version: 2,
            kind: "text".into(),
            message_id: logical_id.clone(),
            sender_username: self.profile.username.clone(),
            sender_account_id: self.profile.account_id.clone(),
            peer_account_id: contact.bundle.account_id.clone(),
            sent_at_ms: sent_at,
            text: text.to_owned(),
            related_message_id: None,
            related_message_ids: vec![],
        })?;
        let mut envelopes = Vec::new();
        let mut targets: Vec<(String, Vec<u8>, v1::DeviceBundle)> = contact
            .bundle
            .devices
            .iter()
            .filter(|device| !device.revoked)
            .map(|device| {
                (
                    contact.bundle.account_id.clone(),
                    contact.bundle.account_master_key.clone(),
                    device.clone(),
                )
            })
            .collect();
        targets.extend(
            self_bundle
                .devices
                .iter()
                .filter(|device| {
                    !device.revoked && device.device_id != self.profile.identity.device_id()
                })
                .map(|device| {
                    (
                        self.profile.account_id.clone(),
                        self_bundle.account_master_key.clone(),
                        device.clone(),
                    )
                }),
        );
        let mut next_machine = OlmMachine::from_bytes(&self.profile.machine.to_bytes()?)?;
        for (account_id, master, device) in targets {
            verify_device_bundle(&master, &account_id, &device)?;
            let encrypted = self
                .encrypt_for(&mut next_machine, &device, &account_id, &payload)
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: logical_id.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: account_id,
                recipient_device_id: device.device_id,
                ciphertext: encrypted.ciphertext,
                olm_message_type: encrypted.message_type,
                client_sent_at_ms: sent_at,
            });
        }
        if envelopes.is_empty() {
            bail!("联系人没有可用设备");
        }
        let body = Body::SendEnvelopes(SendEnvelopes { envelopes });
        let queued_frame = frame(Uuid::new_v4().to_string(), body);
        let draft_conversation = conversation.clone();
        let local_message = ChatMessage {
            id: logical_id.clone(),
            conversation_id: conversation,
            peer_account_id: contact.bundle.account_id,
            sender_account_id: self.profile.account_id.clone(),
            body: text.to_owned(),
            sent_at_ms: sent_at,
            status: MessageStatus::Sending,
            inbound: false,
        };
        let previous_machine = std::mem::replace(&mut self.profile.machine, next_machine);
        let committed = self
            .store
            .commit_outgoing(
                &self.vault,
                &self.profile,
                &local_message,
                &encode_frame(&queued_frame),
            )
            .await;
        if let Err(error) = committed {
            self.profile.machine = previous_machine;
            return Err(error);
        }
        self.messages.push(local_message);
        self.scroll_messages_to_bottom();
        if self.rpc.request_frame(queued_frame).await.is_ok() {
            self.store.remove_outbox(&logical_id).await?;
            self.store
                .update_status(&logical_id, MessageStatus::Sent)
                .await?;
            if let Some(message) = self
                .messages
                .iter_mut()
                .find(|message| message.id == logical_id)
            {
                message.status = MessageStatus::Sent;
            }
            self.status = "消息已由服务端持久化".to_owned();
        } else {
            self.connected = false;
            self.reconnect_at = Instant::now();
            self.status = "网络不可用，消息已安全保存到本地发件箱，重连后自动补发".to_owned();
        }
        self.store
            .save_draft(&self.vault, &draft_conversation, "")
            .await?;
        self.persisted_draft.clear();
        self.refresh_contacts_preserve_selection().await?;
        Ok(())
    }

    async fn encrypt_for(
        &self,
        machine: &mut OlmMachine,
        device: &v1::DeviceBundle,
        account_id: &str,
        payload: &[u8],
    ) -> Result<EncryptedOlm> {
        if machine.has_session(&device.device_id) {
            return machine.encrypt_existing(&device.device_id, payload);
        }
        let response = self
            .rpc
            .request(Body::ClaimPreKey(v1::ClaimPreKey {
                account_id: account_id.to_owned(),
                device_id: device.device_id.clone(),
            }))
            .await?;
        let Some(Body::PreKeyBundle(bundle)) = response.body else {
            bail!("服务器返回了错误的预密钥响应");
        };
        let claimed_device = bundle.device.ok_or_else(|| anyhow!("预密钥响应缺少设备"))?;
        let key = bundle.one_time_key.ok_or_else(|| anyhow!("预密钥已耗尽"))?;
        if claimed_device != *device {
            bail!("领取预密钥时设备身份发生变化");
        }
        verify_prekey(device, &key)?;
        machine.encrypt(
            &PreKeyMaterial {
                device_id: device.device_id.clone(),
                identity_key: device
                    .olm_curve25519_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("无效的设备曲线密钥"))?,
                one_time_key: key
                    .curve25519_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("无效的预密钥"))?,
            },
            payload,
        )
    }

    async fn start_pairing(&mut self, requested_device: Option<&str>) -> Result<()> {
        if self.profile.pending {
            bail!("待批准设备不能批准其他设备");
        }
        if self.pairing.is_some() {
            bail!("已有正在进行的设备配对");
        }
        let index = if let Some(device) = requested_device {
            self.pairing_requests
                .iter()
                .position(|item| item.pending_device_id == device)
        } else if self.pairing_requests.len() == 1 {
            Some(0)
        } else {
            None
        };
        let index = index.ok_or_else(|| anyhow!("没有唯一的配对请求；使用 /pair <设备ID>"))?;
        let request = self.pairing_requests.remove(index);
        let pending_device = request
            .pending_device
            .clone()
            .ok_or_else(|| anyhow!("配对请求缺少设备公钥"))?;
        let peer_key: [u8; 32] = request
            .sas_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("无效的配对公钥"))?;
        let state = PairingState::new();
        let our_public = state.public_key();
        let channel = state.establish(peer_key, &request.pairing_id)?;
        let sas = channel.sas_decimals();
        self.rpc
            .notify(Body::PairingEvent(v1::PairingEvent {
                pairing_id: request.pairing_id.clone(),
                target_device_id: request.pending_device_id.clone(),
                event_type: "sas_public".into(),
                payload: our_public.to_vec(),
                sender_device_id: String::new(),
                server_event_id: 0,
            }))
            .await?;
        self.status = format!(
            "与 {} 比较短认证码：{}-{}-{}；一致后双方输入 /confirm",
            request.pending_device_name, sas.0, sas.1, sas.2
        );
        self.pairing = Some(PairingSession {
            pairing_id: request.pairing_id,
            peer_device_id: request.pending_device_id,
            pending_device,
            channel,
            role: PairingRole::Approver,
            our_confirmed: false,
            peer_confirmed: false,
        });
        Ok(())
    }

    async fn confirm_pairing(&mut self) -> Result<()> {
        let pairing = self
            .pairing
            .as_mut()
            .ok_or_else(|| anyhow!("当前没有进行中的配对"))?;
        pairing.our_confirmed = true;
        match pairing.role {
            PairingRole::Pending => {
                let payload = pairing
                    .channel
                    .encrypt(&pairing.pairing_id, b"sas-confirmed")?;
                self.rpc
                    .notify(Body::PairingEvent(v1::PairingEvent {
                        pairing_id: pairing.pairing_id.clone(),
                        target_device_id: pairing.peer_device_id.clone(),
                        event_type: "sas_confirmed".into(),
                        payload,
                        sender_device_id: String::new(),
                        server_event_id: 0,
                    }))
                    .await?;
                self.status = "已确认短认证码，等待旧设备批准并迁移历史".to_owned();
            }
            PairingRole::Approver => {
                if pairing.peer_confirmed {
                    self.finish_pairing_as_approver().await?;
                } else {
                    self.status = "已确认短认证码，等待新设备确认".to_owned();
                }
            }
        }
        Ok(())
    }

    async fn handle_pairing_event(&mut self, event: v1::PairingEvent) -> Result<()> {
        match event.event_type.as_str() {
            "sas_public" if self.profile.pending => {
                if self.pairing.is_some() {
                    return Ok(());
                }
                let secret = self
                    .profile
                    .pairing_secret
                    .ok_or_else(|| anyhow!("本地缺少待批准设备的配对密钥"))?;
                let peer: [u8; 32] = event
                    .payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("无效的配对公钥"))?;
                let channel =
                    PairingState::from_secret(secret).establish(peer, &event.pairing_id)?;
                let sas = channel.sas_decimals();
                self.status = format!(
                    "与旧设备比较短认证码：{}-{}-{}；一致后双方输入 /confirm",
                    sas.0, sas.1, sas.2
                );
                self.pairing = Some(PairingSession {
                    pairing_id: event.pairing_id,
                    peer_device_id: event.sender_device_id,
                    pending_device: v1::DeviceBundle::default(),
                    channel,
                    role: PairingRole::Pending,
                    our_confirmed: false,
                    peer_confirmed: false,
                });
            }
            "sas_confirmed" => {
                let pairing = self
                    .pairing
                    .as_mut()
                    .ok_or_else(|| anyhow!("收到不属于当前配对的确认"))?;
                if pairing.pairing_id != event.pairing_id
                    || pairing
                        .channel
                        .decrypt(&pairing.pairing_id, &event.payload)?
                        != b"sas-confirmed"
                {
                    bail!("配对确认认证失败");
                }
                pairing.peer_confirmed = true;
                if pairing.our_confirmed && matches!(pairing.role, PairingRole::Approver) {
                    self.finish_pairing_as_approver().await?;
                } else {
                    self.status = "新设备已确认短认证码；核对无误后输入 /confirm".to_owned();
                }
            }
            "bootstrap" if self.profile.pending => {
                let pairing = self
                    .pairing
                    .as_ref()
                    .ok_or_else(|| anyhow!("没有已认证的配对通道"))?;
                if !pairing.our_confirmed {
                    bail!("在本机确认短认证码前拒绝密钥迁移");
                }
                let plaintext = pairing
                    .channel
                    .decrypt(&pairing.pairing_id, &event.payload)?;
                let transfer: BootstrapTransfer = serde_json::from_slice(&plaintext)?;
                let public = SigningKey::from_bytes(&transfer.master_secret)
                    .verifying_key()
                    .to_bytes();
                if public.as_slice() != self.profile.account_master_public {
                    bail!("旧设备传来的账号主密钥与待配对身份不一致");
                }
                self.profile
                    .identity
                    .install_master_secret(transfer.master_secret);
                self.store.import_contacts(&transfer.contacts).await?;
                self.contacts = self.store.contacts().await?;
                self.store.save_profile(&self.vault, &self.profile).await?;
                self.status = "账号密钥已安全迁移，正在接收历史消息".to_owned();
            }
            "history_chunk" if self.profile.pending => {
                let pairing = self
                    .pairing
                    .as_ref()
                    .ok_or_else(|| anyhow!("没有已认证的配对通道"))?;
                let plaintext = pairing
                    .channel
                    .decrypt(&pairing.pairing_id, &event.payload)?;
                let transfer: HistoryTransfer = serde_json::from_slice(&plaintext)?;
                self.store
                    .import_messages(&self.vault, &transfer.messages)
                    .await?;
                self.status = format!("已迁移一批历史消息（{} 条）", transfer.messages.len());
            }
            "history_complete" if self.profile.pending => {
                self.status = "历史迁移完成，等待服务器激活设备".to_owned()
            }
            "device_activated" if self.profile.pending => {
                if !self.profile.identity.has_master_secret() {
                    bail!("设备激活时尚未收到账号主密钥");
                }
                self.profile.pending = false;
                self.profile.pairing_secret = None;
                self.store.save_profile(&self.vault, &self.profile).await?;
                self.status = "设备已激活；请重启客户端，之后将使用设备签名认证".to_owned();
            }
            _ => {}
        }
        Ok(())
    }

    async fn finish_pairing_as_approver(&mut self) -> Result<()> {
        let mut pairing = self.pairing.take().ok_or_else(|| anyhow!("配对状态消失"))?;
        if !pairing.our_confirmed || !pairing.peer_confirmed {
            self.pairing = Some(pairing);
            bail!("双方尚未确认短认证码");
        }
        self.profile
            .identity
            .certify_bundle(&mut pairing.pending_device)?;
        let master_secret = self
            .profile
            .identity
            .master_secret()
            .ok_or_else(|| anyhow!("账号主密钥不可用"))?;
        let contacts = self.store.export_contacts().await?;
        let bootstrap = serde_json::to_vec(&BootstrapTransfer {
            master_secret,
            contacts,
        })?;
        self.send_pairing_payload(&pairing, "bootstrap", &bootstrap)
            .await?;
        let history = self.store.export_messages(&self.vault).await?;
        for messages in history.chunks(4) {
            self.send_pairing_payload(
                &pairing,
                "history_chunk",
                &serde_json::to_vec(&HistoryTransfer {
                    messages: messages.to_vec(),
                })?,
            )
            .await?;
        }
        self.send_pairing_payload(&pairing, "history_complete", b"complete")
            .await?;
        let username = self.profile.username.clone();
        let self_bundle = self.lookup_bundle(&username).await?;
        let revision = self_bundle.roster_revision + 1;
        let roster_signature = self
            .profile
            .identity
            .sign_roster(revision, &pairing.pending_device.device_id)?;
        self.rpc
            .request(Body::ActivateDevice(v1::ActivateDevice {
                pairing_id: pairing.pairing_id.clone(),
                device: Some(pairing.pending_device),
                roster_revision: revision,
                roster_signature,
            }))
            .await?;
        self.status = format!("设备已批准，迁移了 {} 条可用历史消息", history.len());
        Ok(())
    }

    async fn send_pairing_payload(
        &self,
        pairing: &PairingSession,
        event_type: &str,
        plaintext: &[u8],
    ) -> Result<()> {
        let payload = pairing.channel.encrypt(&pairing.pairing_id, plaintext)?;
        self.rpc
            .notify(Body::PairingEvent(v1::PairingEvent {
                pairing_id: pairing.pairing_id.clone(),
                target_device_id: pairing.peer_device_id.clone(),
                event_type: event_type.to_owned(),
                payload,
                sender_device_id: String::new(),
                server_event_id: 0,
            }))
            .await
    }

    async fn sync(&mut self) -> Result<()> {
        if !self.connected {
            bail!("当前没有连接");
        }
        let (cursor, status_cursor) = self.store.cursors().await?;
        let response = self
            .rpc
            .request(Body::SyncRequest(SyncRequest {
                after_cursor: cursor,
                limit: 100,
                after_status_cursor: status_cursor,
            }))
            .await?;
        self.handle_server_event(response).await
    }

    async fn handle_server_event(&mut self, frame: v1::Frame) -> Result<()> {
        match frame.body {
            Some(Body::SyncBatch(batch)) => self.handle_sync_batch(batch).await?,
            Some(Body::DeliveryUpdate(update)) => {
                self.store
                    .update_status(&update.logical_message_id, MessageStatus::Delivered)
                    .await?;
                if let Some(message) = self
                    .messages
                    .iter_mut()
                    .find(|message| message.id == update.logical_message_id)
                    && message.status.rank() < MessageStatus::Delivered.rank()
                {
                    message.status = MessageStatus::Delivered;
                }
            }
            Some(Body::PairingRequest(request))
                if request.pending_device_id != self.profile.identity.device_id()
                    && !self
                        .pairing_requests
                        .iter()
                        .any(|item| item.pairing_id == request.pairing_id) =>
            {
                self.status = format!(
                    "设备 {} 请求加入；输入 /pair {} 开始比较短认证码",
                    request.pending_device_name, request.pending_device_id
                );
                self.pairing_requests.push(request);
            }
            Some(Body::PairingEvent(event)) => {
                let server_event_id = event.server_event_id;
                if server_event_id == 0
                    || !self.store.pairing_event_processed(server_event_id).await?
                {
                    self.handle_pairing_event(event).await?;
                    if server_event_id != 0 {
                        self.store
                            .mark_pairing_event_processed(server_event_id)
                            .await?;
                    }
                }
                if server_event_id != 0 {
                    self.rpc
                        .notify(Body::AckPairingEvent(v1::AckPairingEvent {
                            server_event_id,
                        }))
                        .await?;
                }
            }
            Some(Body::Error(error)) => {
                if error.code == "connection_closed" {
                    self.connected = false;
                    self.reconnect_at =
                        Instant::now() + Duration::from_secs(self.reconnect_backoff);
                }
                self.status = format!("{}: {}", error.code, error.message);
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_sync_batch(&mut self, batch: v1::SyncBatch) -> Result<()> {
        let (mut cursor, mut status_cursor) = self.store.cursors().await?;
        for status in batch.delivery_updates {
            if let Some(update) = status.update {
                self.store
                    .update_status(&update.logical_message_id, MessageStatus::Delivered)
                    .await?;
            }
            status_cursor = status.cursor;
        }
        for stored in batch.envelopes {
            if stored.cursor <= cursor {
                continue;
            }
            let envelope = stored.envelope.ok_or_else(|| anyhow!("同步信封缺失"))?;
            let bundle = self.lookup_bundle(&stored.sender_username).await?;
            let sender_is_self = stored.sender_account_id == self.profile.account_id;
            let verified = if sender_is_self {
                true
            } else {
                self.store.upsert_contact(&bundle).await?.verified
            };
            if !verified {
                self.contacts = self.store.contacts().await?;
                self.status = format!(
                    "收到来自 {} 的未核验密文；选择会话并比较安全码后输入 /verify",
                    stored.sender_username
                );
                break;
            }
            validate_bundle(&bundle)?;
            let sender = bundle
                .devices
                .iter()
                .find(|device| device.device_id == stored.sender_device_id && !device.revoked)
                .ok_or_else(|| anyhow!("发送设备未获账号主密钥认证"))?;
            verify_device_bundle(&bundle.account_master_key, &bundle.account_id, sender)?;
            let mut next_machine = OlmMachine::from_bytes(&self.profile.machine.to_bytes()?)?;
            let plaintext = next_machine.decrypt(
                &stored.sender_device_id,
                sender
                    .olm_curve25519_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("无效发送设备曲线密钥"))?,
                &EncryptedOlm {
                    message_type: envelope.olm_message_type,
                    ciphertext: envelope.ciphertext,
                },
            )?;
            let payload: WirePayload = serde_json::from_slice(&plaintext)?;
            if !wire_metadata_matches(
                &payload,
                &stored.sender_account_id,
                &stored.sender_username,
                &envelope.logical_message_id,
                envelope.client_sent_at_ms,
            ) {
                bail!("端到端载荷校验失败");
            }
            if matches!(payload.kind.as_str(), "read" | "read_batch") {
                let related_ids = if payload.kind == "read" {
                    vec![
                        payload
                            .related_message_id
                            .ok_or_else(|| anyhow!("已读回执缺少消息 ID"))?,
                    ]
                } else {
                    payload.related_message_ids
                };
                if related_ids.is_empty() || related_ids.len() > 100 {
                    bail!("已读回执批量大小无效");
                }
                for related in related_ids {
                    self.store
                        .update_outbound_status_for_peer(
                            &related,
                            &stored.sender_account_id,
                            MessageStatus::Read,
                        )
                        .await?;
                    if let Some(message) = self.messages.iter_mut().find(|message| {
                        message.id == related
                            && !message.inbound
                            && message.peer_account_id == stored.sender_account_id
                    }) {
                        message.status = MessageStatus::Read;
                    }
                }
                let previous_machine = std::mem::replace(&mut self.profile.machine, next_machine);
                let committed = self
                    .store
                    .commit_control(&self.vault, &self.profile, stored.cursor)
                    .await;
                if let Err(error) = committed {
                    self.profile.machine = previous_machine;
                    return Err(error);
                }
                cursor = stored.cursor;
                self.rpc
                    .notify(Body::AckEnvelope(v1::AckEnvelope {
                        envelope_id: envelope.envelope_id,
                        cursor,
                    }))
                    .await?;
                continue;
            }
            if payload.kind != "text" {
                bail!("未知的端到端事件类型");
            }
            if payload.text.len() > tui_chat_protocol::MAX_TEXT_BYTES
                || (!sender_is_self && payload.peer_account_id != self.profile.account_id)
            {
                bail!("端到端正文元数据无效");
            }
            let peer = if sender_is_self {
                payload.peer_account_id.clone()
            } else {
                stored.sender_account_id.clone()
            };
            let message = ChatMessage {
                id: payload.message_id,
                conversation_id: envelope.conversation_id,
                peer_account_id: peer,
                sender_account_id: stored.sender_account_id,
                body: payload.text,
                sent_at_ms: payload.sent_at_ms,
                status: MessageStatus::Delivered,
                inbound: !sender_is_self,
            };
            let previous_machine = std::mem::replace(&mut self.profile.machine, next_machine);
            let committed = self
                .store
                .commit_inbound(&self.vault, &self.profile, &message, stored.cursor)
                .await;
            if let Err(error) = committed {
                self.profile.machine = previous_machine;
                return Err(error);
            }
            cursor = stored.cursor;
            self.rpc
                .notify(Body::AckEnvelope(v1::AckEnvelope {
                    envelope_id: envelope.envelope_id,
                    cursor,
                }))
                .await?;
            let selected_conversation = self.selected_contact().is_some_and(|contact| {
                conversation_id(&self.profile.account_id, &contact.bundle.account_id)
                    == message.conversation_id
            });
            if selected_conversation {
                let related = message.id.clone();
                if !self.messages.iter().any(|item| item.id == message.id) {
                    if self.message_scroll > 0 {
                        self.message_scroll +=
                            self.visual_lines_for_messages(std::slice::from_ref(&message));
                        self.new_messages_below += 1;
                    }
                    self.messages.push(message);
                }
                if should_send_read_receipt(
                    self.terminal_focused,
                    !sender_is_self,
                    selected_conversation,
                ) && self
                    .send_read_receipts(&bundle, std::slice::from_ref(&related))
                    .await
                    .is_ok()
                {
                    self.store
                        .update_status(&related, MessageStatus::Read)
                        .await?;
                    if let Some(message) = self.messages.iter_mut().find(|item| item.id == related)
                    {
                        message.status = MessageStatus::Read;
                    }
                }
            }
        }
        self.store
            .set_cursors(cursor, status_cursor.max(batch.next_status_cursor))
            .await?;
        self.refresh_contacts_preserve_selection().await?;
        if batch.has_more && cursor == batch.next_cursor {
            self.status = "仍有历史消息，输入 /sync 继续加载".to_owned();
        }
        Ok(())
    }

    async fn lookup_bundle(&mut self, username: &str) -> Result<UserBundle> {
        if let Some((bundle, fetched_at)) = self.bundle_cache.get(username)
            && fetched_at.elapsed() < Duration::from_secs(60)
        {
            return Ok(bundle.clone());
        }
        let response = self
            .rpc
            .request(Body::LookupUser(v1::LookupUser {
                exact_username: username.to_owned(),
            }))
            .await?;
        match response.body {
            Some(Body::UserBundle(bundle)) => {
                self.bundle_cache
                    .insert(bundle.username.clone(), (bundle.clone(), Instant::now()));
                Ok(bundle)
            }
            _ => bail!("服务器返回了错误的用户目录响应"),
        }
    }

    async fn send_read_receipts(
        &mut self,
        recipient: &UserBundle,
        related_message_ids: &[String],
    ) -> Result<()> {
        if related_message_ids.is_empty() || related_message_ids.len() > 100 {
            bail!("已读回执批量大小必须为 1..=100");
        }
        let logical = Uuid::now_v7().to_string();
        let conversation = conversation_id(&self.profile.account_id, &recipient.account_id);
        let sent_at_ms = now_ms();
        let payload = serde_json::to_vec(&WirePayload {
            version: 2,
            kind: "read_batch".into(),
            message_id: logical.clone(),
            sender_username: self.profile.username.clone(),
            sender_account_id: self.profile.account_id.clone(),
            peer_account_id: recipient.account_id.clone(),
            sent_at_ms,
            text: String::new(),
            related_message_id: None,
            related_message_ids: related_message_ids.to_vec(),
        })?;
        let mut envelopes = Vec::new();
        let mut next_machine = OlmMachine::from_bytes(&self.profile.machine.to_bytes()?)?;
        for device in recipient.devices.iter().filter(|device| !device.revoked) {
            verify_device_bundle(&recipient.account_master_key, &recipient.account_id, device)?;
            let encrypted = self
                .encrypt_for(&mut next_machine, device, &recipient.account_id, &payload)
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: logical.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: recipient.account_id.clone(),
                recipient_device_id: device.device_id.clone(),
                ciphertext: encrypted.ciphertext,
                olm_message_type: encrypted.message_type,
                client_sent_at_ms: sent_at_ms,
            });
        }
        let queued_frame = frame(
            Uuid::new_v4().to_string(),
            Body::SendEnvelopes(SendEnvelopes { envelopes }),
        );
        let previous_machine = std::mem::replace(&mut self.profile.machine, next_machine);
        let committed = self
            .store
            .commit_control_outgoing(
                &self.vault,
                &self.profile,
                &logical,
                &encode_frame(&queued_frame),
            )
            .await;
        if let Err(error) = committed {
            self.profile.machine = previous_machine;
            return Err(error);
        }
        if self.rpc.request_frame(queued_frame).await.is_ok() {
            self.store.remove_outbox(&logical).await?;
        }
        Ok(())
    }

    async fn resend_outbox(&mut self) {
        let Ok(items) = self.store.outbox().await else {
            return;
        };
        for (logical_id, encoded) in items {
            let result = match decode_frame(&encoded) {
                Ok(frame) => self.rpc.request_frame(frame).await.map(|_| ()),
                Err(error) => Err(error.into()),
            };
            if result.is_ok() {
                let _ = self.store.remove_outbox(&logical_id).await;
                let _ = self
                    .store
                    .update_status(&logical_id, MessageStatus::Sent)
                    .await;
            }
        }
    }

    async fn try_reconnect(&mut self) {
        if self.profile.pending {
            self.status = "待批准设备断线后需要重启并再次输入账号密码".to_owned();
            self.reconnect_at = Instant::now() + Duration::from_secs(30);
            return;
        }
        let result: Result<(RpcClient, mpsc::Receiver<v1::Frame>)> = async {
            let mut raw =
                RawConnection::connect(&self.profile.server_url, self.profile.spki_pin.as_deref())
                    .await?;
            let response = raw
                .request(Body::ClientHello(v1::ClientHello {
                    username: self.profile.username.clone(),
                    device_id: self.profile.identity.device_id().to_owned(),
                }))
                .await?;
            let Some(Body::AuthChallenge(challenge)) = response.body else {
                bail!("重连握手缺少挑战");
            };
            let host = url::Url::parse(&self.profile.server_url)?
                .host_str()
                .ok_or_else(|| anyhow!("服务器 URL 缺少主机名"))?
                .to_owned();
            let payload = tui_chat_protocol::auth_challenge_payload(
                &host,
                &self.profile.username,
                self.profile.identity.device_id(),
                &challenge.nonce,
                challenge.expires_at_ms,
            );
            let response = raw
                .request(Body::DeviceAuth(v1::DeviceAuth {
                    username: self.profile.username.clone(),
                    device_id: self.profile.identity.device_id().to_owned(),
                    signature: self.profile.identity.sign_auth_challenge(&payload),
                }))
                .await?;
            let Some(Body::Authenticated(auth)) = response.body else {
                bail!("重连认证失败");
            };
            if auth.account_id != self.profile.account_id
                || auth.account_master_key != self.profile.account_master_public
            {
                bail!("重连时账号身份发生变化");
            }
            Ok(raw.start())
        }
        .await;
        match result {
            Ok((rpc, events)) => {
                self.rpc = rpc;
                self.events = events;
                self.connected = true;
                self.reconnect_backoff = 1;
                self.status = "已重新连接，正在补拉离线消息".to_owned();
                self.resend_outbox().await;
                let _ = self.sync().await;
            }
            Err(error) => {
                self.status = format!("重连失败：{error:#}");
                self.reconnect_backoff = (self.reconnect_backoff * 2).min(30);
                let jitter = u64::from(Uuid::new_v4().as_bytes()[0] % 3);
                self.reconnect_at =
                    Instant::now() + Duration::from_secs(self.reconnect_backoff + jitter);
            }
        }
    }

    async fn select_relative(&mut self, direction: isize) -> Result<()> {
        if self.contacts.is_empty() {
            return Ok(());
        }
        self.save_current_draft().await?;
        self.selected = Some(match self.selected {
            Some(current) => {
                (current as isize + direction).clamp(0, self.contacts.len() as isize - 1) as usize
            }
            None => 0,
        });
        self.load_selected_messages().await?;
        if self
            .selected_contact()
            .is_some_and(|contact| !contact.verified || contact.identity_changed)
        {
            self.show_safety_code();
        }
        Ok(())
    }

    fn search_loaded_messages(&mut self, query: &str) -> Result<()> {
        if query.is_empty() {
            bail!("搜索关键词不能为空");
        }
        let query = query.to_lowercase();
        let Some(index) = self
            .messages
            .iter()
            .rposition(|message| message.body.to_lowercase().contains(&query))
        else {
            bail!("当前已加载的消息中没有匹配项；可先 PageUp 加载更早历史");
        };
        self.message_scroll = self.visual_lines_for_messages(&self.messages[index + 1..]);
        self.focus = FocusPane::Messages;
        self.status = format!("已定位匹配消息（{}/{})", index + 1, self.messages.len());
        Ok(())
    }

    fn visual_lines_for_messages(&self, messages: &[ChatMessage]) -> usize {
        let width = self.layout.messages.width.saturating_sub(2).max(1);
        let peer_name = self
            .selected_contact()
            .map(|contact| contact.bundle.username.as_str())
            .unwrap_or("对方");
        messages
            .iter()
            .map(|message| {
                let sender = if message.inbound { peer_name } else { "我" };
                let rendered = format!(
                    "{sender}: {}  [{}]",
                    sanitize_terminal_text(&message.body),
                    message.status.label()
                );
                editor_visual_line_count(&rendered, width)
            })
            .sum()
    }

    fn message_scroll_maximum(&self) -> usize {
        self.visual_lines_for_messages(&self.messages)
            .saturating_sub(usize::from(
                self.layout.messages.height.saturating_sub(2).max(1),
            ))
    }

    async fn load_selected_messages(&mut self) -> Result<()> {
        let Some(contact) = self.selected_contact() else {
            self.messages.clear();
            self.editor.clear();
            self.persisted_draft.clear();
            self.history_exhausted = true;
            return Ok(());
        };
        let conversation = conversation_id(&self.profile.account_id, &contact.bundle.account_id);
        self.messages = self.store.messages(&self.vault, &conversation).await?;
        self.history_exhausted = self.messages.len() < MESSAGE_PAGE_SIZE;
        let draft = self.store.load_draft(&self.vault, &conversation).await?;
        self.persisted_draft.clone_from(&draft);
        self.editor.set(draft);
        self.message_scroll = 0;
        self.new_messages_below = 0;
        self.mark_selected_read().await?;
        Ok(())
    }

    async fn save_current_draft(&mut self) -> Result<()> {
        let Some(contact) = self.selected_contact() else {
            return Ok(());
        };
        if self.editor.as_str().trim_start().starts_with('/') {
            return Ok(());
        }
        let conversation = conversation_id(&self.profile.account_id, &contact.bundle.account_id);
        self.store
            .save_draft(&self.vault, &conversation, self.editor.as_str())
            .await?;
        self.persisted_draft = self.editor.as_str().to_owned();
        Ok(())
    }

    async fn autosave_draft(&mut self) -> Result<()> {
        if self.editor.as_str() == self.persisted_draft
            || self.editor.as_str().trim_start().starts_with('/')
        {
            return Ok(());
        }
        self.save_current_draft().await
    }

    async fn mark_selected_read(&mut self) -> Result<()> {
        let Some(contact) = self.selected_contact() else {
            return Ok(());
        };
        if !self.terminal_focused
            || !contact.verified
            || contact.identity_changed
            || !self.connected
        {
            return Ok(());
        }
        let recipient = contact.bundle.clone();
        let unread: Vec<String> = self
            .messages
            .iter()
            .filter(|message| message.inbound && message.status != MessageStatus::Read)
            .map(|message| message.id.clone())
            .collect();
        for batch in unread.chunks(100) {
            self.send_read_receipts(&recipient, batch).await?;
            for message_id in batch {
                self.store
                    .update_status(message_id, MessageStatus::Read)
                    .await?;
                if let Some(message) = self
                    .messages
                    .iter_mut()
                    .find(|message| message.id == *message_id)
                {
                    message.status = MessageStatus::Read;
                }
            }
        }
        self.refresh_contacts_preserve_selection().await?;
        Ok(())
    }

    async fn refresh_contacts_preserve_selection(&mut self) -> Result<()> {
        let selected_account = self
            .selected_contact()
            .map(|contact| contact.bundle.account_id.clone());
        self.contacts = self.store.contacts().await?;
        self.selected = selected_account.and_then(|account| {
            self.contacts
                .iter()
                .position(|contact| contact.bundle.account_id == account)
        });
        Ok(())
    }

    fn selected_contact(&self) -> Option<&Contact> {
        self.selected.and_then(|index| self.contacts.get(index))
    }
}

fn validate_bundle(bundle: &UserBundle) -> Result<()> {
    if bundle.account_master_key.len() != 32 {
        bail!("账号主密钥长度无效");
    }
    for device in bundle.devices.iter().filter(|device| !device.revoked) {
        verify_device_bundle(&bundle.account_master_key, &bundle.account_id, device)?;
    }
    Ok(())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn sanitize_terminal_text(text: &str) -> Cow<'_, str> {
    if text
        .chars()
        .all(|character| character == '\n' || !character.is_control())
    {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(
            text.chars()
                .map(|character| {
                    if character == '\n' || !character.is_control() {
                        character
                    } else {
                        '�'
                    }
                })
                .collect(),
        )
    }
}

fn focus_block<'a>(title: &'a str, focused: bool) -> Block<'a> {
    let color = if focused {
        Color::Rgb(78, 201, 216)
    } else {
        Color::DarkGray
    };
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color).add_modifier(if focused {
            Modifier::BOLD
        } else {
            Modifier::empty()
        }))
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    )
}

fn editor_cursor_position(text: &str, cursor: usize, width: u16) -> (u16, u16) {
    let width = usize::from(width.max(1));
    let mut row = 0_usize;
    let mut column = 0_usize;
    for grapheme in text[..cursor].graphemes(true) {
        if grapheme == "\n" {
            row += 1;
            column = 0;
            continue;
        }
        let character_width = UnicodeWidthStr::width(grapheme).max(1);
        if column == width || (column > 0 && column + character_width > width) {
            row += 1;
            column = 0;
        }
        column += character_width;
    }
    if column == width {
        row += 1;
        column = 0;
    }
    (
        row.min(usize::from(u16::MAX)) as u16,
        column.min(usize::from(u16::MAX)) as u16,
    )
}

fn editor_visual_line_count(text: &str, width: u16) -> usize {
    usize::from(editor_cursor_position(text, text.len(), width).0) + 1
}

fn should_send_read_receipt(
    terminal_focused: bool,
    inbound: bool,
    selected_conversation: bool,
) -> bool {
    terminal_focused && inbound && selected_conversation
}

fn wire_metadata_matches(
    payload: &WirePayload,
    stored_sender_account_id: &str,
    stored_sender_username: &str,
    envelope_logical_id: &str,
    envelope_sent_at_ms: i64,
) -> bool {
    let timestamp_matches = payload.sent_at_ms == envelope_sent_at_ms
        || (matches!(payload.kind.as_str(), "read" | "read_batch")
            && payload.sent_at_ms.abs_diff(envelope_sent_at_ms) <= 60_000);
    matches!(payload.version, 1 | 2)
        && payload.message_id == envelope_logical_id
        && payload.sender_account_id == stored_sender_account_id
        && payload.sender_username == stored_sender_username
        && timestamp_matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_layout_shows_only_the_focused_main_pane() {
        let area = Rect::new(0, 0, 60, 24);
        let conversations = UiLayout::calculate(area, FocusPane::Conversations, 1);
        assert!(conversations.narrow);
        assert!(conversations.conversations.area() > 0);
        assert_eq!(conversations.messages, Rect::default());

        let messages = UiLayout::calculate(area, FocusPane::Messages, 1);
        assert_eq!(messages.conversations, Rect::default());
        assert!(messages.messages.area() > 0);
    }

    #[test]
    fn wide_layout_keeps_conversations_and_messages_visible() {
        let layout = UiLayout::calculate(Rect::new(0, 0, 100, 30), FocusPane::Composer, 3);
        assert!(!layout.narrow);
        assert!(layout.conversations.area() > 0);
        assert!(layout.messages.area() > 0);
        assert_eq!(layout.composer.height, 5);
    }

    #[test]
    fn rendered_dynamic_text_cannot_contain_escape_sequences() {
        assert_eq!(sanitize_terminal_text("hello"), "hello");
        assert_eq!(sanitize_terminal_text("hello\x1b[31m"), "hello�[31m");
    }

    #[test]
    fn cursor_wrapping_does_not_double_count_a_newline() {
        assert_eq!(editor_cursor_position("abcd", 4, 4), (1, 0));
        assert_eq!(editor_cursor_position("abcd\nx", 5, 4), (1, 0));
        assert_eq!(editor_cursor_position("ab中x", "ab中".len(), 4), (1, 0));
    }

    #[test]
    fn read_receipts_require_a_focused_terminal_and_selected_inbound_conversation() {
        assert!(should_send_read_receipt(true, true, true));
        assert!(!should_send_read_receipt(false, true, true));
        assert!(!should_send_read_receipt(true, false, true));
        assert!(!should_send_read_receipt(true, true, false));
    }

    #[test]
    fn read_receipt_compatibility_allows_the_legacy_timestamp_race_only() {
        let payload = WirePayload {
            version: 2,
            kind: "read_batch".into(),
            message_id: "logical".into(),
            sender_username: "alice".into(),
            sender_account_id: "account".into(),
            peer_account_id: "peer".into(),
            sent_at_ms: 1_000,
            text: String::new(),
            related_message_id: None,
            related_message_ids: vec!["message".into()],
        };
        assert!(wire_metadata_matches(
            &payload, "account", "alice", "logical", 1_004
        ));
        assert!(!wire_metadata_matches(
            &payload, "account", "alice", "logical", 61_001
        ));
        let mut text_payload = payload;
        text_payload.kind = "text".into();
        assert!(!wire_metadata_matches(
            &text_payload,
            "account",
            "alice",
            "logical",
            1_004
        ));
    }
}
