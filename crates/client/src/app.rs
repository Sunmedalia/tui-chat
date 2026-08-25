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
use prost::Message as _;
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
        ChatMessage, Contact, LocalStore, MESSAGE_PAGE_SIZE, MessageStatus, Notification,
        NotificationData, NotificationKind, NotificationState, RuntimeProfile, TransferContact,
        VaultSession,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidebarTab {
    Conversations,
    Notifications,
}

#[derive(Debug, Clone, Copy)]
struct EmojiEntry {
    glyph: &'static str,
    name: &'static str,
    keywords: &'static str,
}

const EMOJI_CATALOG: &[EmojiEntry] = &[
    EmojiEntry {
        glyph: "😀",
        name: "笑脸",
        keywords: "smile happy 开心",
    },
    EmojiEntry {
        glyph: "😂",
        name: "笑哭",
        keywords: "joy laugh 哈哈",
    },
    EmojiEntry {
        glyph: "🤣",
        name: "笑翻",
        keywords: "rofl laugh 爆笑",
    },
    EmojiEntry {
        glyph: "😊",
        name: "微笑",
        keywords: "blush smile 温暖",
    },
    EmojiEntry {
        glyph: "😍",
        name: "喜欢",
        keywords: "heart eyes love 爱",
    },
    EmojiEntry {
        glyph: "🥰",
        name: "喜爱",
        keywords: "love hearts 喜欢",
    },
    EmojiEntry {
        glyph: "😘",
        name: "飞吻",
        keywords: "kiss love 亲亲",
    },
    EmojiEntry {
        glyph: "😎",
        name: "酷",
        keywords: "cool sunglasses 墨镜",
    },
    EmojiEntry {
        glyph: "🤔",
        name: "思考",
        keywords: "think hmm 想想",
    },
    EmojiEntry {
        glyph: "🫡",
        name: "敬礼",
        keywords: "salute 收到",
    },
    EmojiEntry {
        glyph: "😢",
        name: "难过",
        keywords: "cry sad 哭",
    },
    EmojiEntry {
        glyph: "😭",
        name: "大哭",
        keywords: "sob cry 难受",
    },
    EmojiEntry {
        glyph: "😡",
        name: "生气",
        keywords: "angry mad 愤怒",
    },
    EmojiEntry {
        glyph: "😴",
        name: "睡觉",
        keywords: "sleep tired 困",
    },
    EmojiEntry {
        glyph: "🤯",
        name: "震惊",
        keywords: "mind blown shocked",
    },
    EmojiEntry {
        glyph: "🥳",
        name: "庆祝",
        keywords: "party celebrate 恭喜",
    },
    EmojiEntry {
        glyph: "👍",
        name: "赞",
        keywords: "thumbs up good 好",
    },
    EmojiEntry {
        glyph: "👎",
        name: "不赞",
        keywords: "thumbs down bad",
    },
    EmojiEntry {
        glyph: "👏",
        name: "鼓掌",
        keywords: "clap applause",
    },
    EmojiEntry {
        glyph: "🙏",
        name: "感谢",
        keywords: "pray thanks please",
    },
    EmojiEntry {
        glyph: "🤝",
        name: "握手",
        keywords: "handshake agreement 合作",
    },
    EmojiEntry {
        glyph: "💪",
        name: "加油",
        keywords: "strong muscle 努力",
    },
    EmojiEntry {
        glyph: "👌",
        name: "可以",
        keywords: "ok okay 好的",
    },
    EmojiEntry {
        glyph: "✌️",
        name: "胜利",
        keywords: "victory peace 耶",
    },
    EmojiEntry {
        glyph: "❤️",
        name: "红心",
        keywords: "heart love 爱心",
    },
    EmojiEntry {
        glyph: "💔",
        name: "心碎",
        keywords: "broken heart 难过",
    },
    EmojiEntry {
        glyph: "🔥",
        name: "火",
        keywords: "fire hot 厉害",
    },
    EmojiEntry {
        glyph: "✨",
        name: "闪亮",
        keywords: "sparkles magic 漂亮",
    },
    EmojiEntry {
        glyph: "🎉",
        name: "礼花",
        keywords: "tada party celebrate",
    },
    EmojiEntry {
        glyph: "🎂",
        name: "蛋糕",
        keywords: "cake birthday 生日",
    },
    EmojiEntry {
        glyph: "🎁",
        name: "礼物",
        keywords: "gift present",
    },
    EmojiEntry {
        glyph: "✅",
        name: "完成",
        keywords: "check done yes",
    },
    EmojiEntry {
        glyph: "❌",
        name: "错误",
        keywords: "cross no error",
    },
    EmojiEntry {
        glyph: "⚠️",
        name: "警告",
        keywords: "warning alert 注意",
    },
    EmojiEntry {
        glyph: "💡",
        name: "想法",
        keywords: "idea bulb 灵感",
    },
    EmojiEntry {
        glyph: "🚀",
        name: "火箭",
        keywords: "rocket launch 发布",
    },
    EmojiEntry {
        glyph: "🐛",
        name: "虫子",
        keywords: "bug debug 问题",
    },
    EmojiEntry {
        glyph: "💻",
        name: "电脑",
        keywords: "computer code 编程",
    },
    EmojiEntry {
        glyph: "📌",
        name: "图钉",
        keywords: "pin important 重点",
    },
    EmojiEntry {
        glyph: "📎",
        name: "附件",
        keywords: "paperclip attach",
    },
    EmojiEntry {
        glyph: "🔒",
        name: "安全",
        keywords: "lock secure 加密",
    },
    EmojiEntry {
        glyph: "👀",
        name: "关注",
        keywords: "eyes look 看看",
    },
    EmojiEntry {
        glyph: "🙌",
        name: "欢呼",
        keywords: "raised hands hooray",
    },
    EmojiEntry {
        glyph: "🫶",
        name: "爱心手",
        keywords: "heart hands love",
    },
    EmojiEntry {
        glyph: "🧑‍💻",
        name: "开发者",
        keywords: "developer coder 编程",
    },
];

#[derive(Debug, Default)]
struct EmojiPickerState {
    visible: bool,
    query: String,
    selected: usize,
    scroll: usize,
    columns: usize,
    page_size: usize,
}

#[derive(Debug, Clone)]
enum DeleteTarget {
    Conversation {
        account_id: String,
        username: String,
        conversation_id: String,
    },
    Notification {
        notification_id: String,
        title: String,
        request_id: String,
    },
}

#[derive(Debug, Clone)]
struct DeleteConfirmation {
    target: DeleteTarget,
    confirm_selected: bool,
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
    sidebar_tab: SidebarTab,
    completion: CompletionState,
    emoji_picker: EmojiPickerState,
    emoji_picker_area: Rect,
    emoji_grid_area: Rect,
    emoji_button_area: Rect,
    help_visible: bool,
    redraw_requested: bool,
    contact_scroll: usize,
    notification_scroll: usize,
    notifications: Vec<Notification>,
    notification_selected: Option<usize>,
    message_scroll: usize,
    new_messages_below: usize,
    history_exhausted: bool,
    persisted_draft: String,
    layout: UiLayout,
    conversation_tab_area: Rect,
    notification_tab_area: Rect,
    conversation_delete_areas: Vec<(usize, Rect)>,
    notification_delete_areas: Vec<(usize, Rect)>,
    delete_confirmation: Option<DeleteConfirmation>,
    delete_confirm_area: Rect,
    delete_cancel_area: Rect,
    notification_primary_action_area: Rect,
    notification_secondary_action_area: Rect,
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
        let notifications = store.notifications(&vault).await?;
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
            sidebar_tab: SidebarTab::Conversations,
            completion: CompletionState::default(),
            emoji_picker: EmojiPickerState::default(),
            emoji_picker_area: Rect::default(),
            emoji_grid_area: Rect::default(),
            emoji_button_area: Rect::default(),
            help_visible: false,
            redraw_requested: false,
            contact_scroll: 0,
            notification_scroll: 0,
            notifications,
            notification_selected: None,
            message_scroll: 0,
            new_messages_below: 0,
            history_exhausted: false,
            persisted_draft: String::new(),
            layout: UiLayout::default(),
            conversation_tab_area: Rect::default(),
            notification_tab_area: Rect::default(),
            conversation_delete_areas: Vec::new(),
            notification_delete_areas: Vec::new(),
            delete_confirmation: None,
            delete_confirm_area: Rect::default(),
            delete_cancel_area: Rect::default(),
            notification_primary_action_area: Rect::default(),
            notification_secondary_action_area: Rect::default(),
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
        app.restore_pairing_requests_from_notifications();
        app.resend_outbox().await;
        let _ = app.sync().await;
        Ok(app)
    }

    fn selected_notification(&self) -> Option<&Notification> {
        self.notification_selected
            .and_then(|index| self.notifications.get(index))
    }

    fn restore_pairing_requests_from_notifications(&mut self) {
        for notification in &self.notifications {
            if !matches!(
                notification.state,
                NotificationState::Pending | NotificationState::InProgress
            ) {
                continue;
            }
            let NotificationData::Pairing {
                pairing_id,
                pending_device_id,
                pending_device_name,
                sas_public_key,
                pending_device,
            } = &notification.data
            else {
                continue;
            };
            if self
                .pairing_requests
                .iter()
                .any(|request| request.pairing_id == *pairing_id)
            {
                continue;
            }
            let Ok(device) = v1::DeviceBundle::decode(pending_device.as_slice()) else {
                continue;
            };
            self.pairing_requests.push(v1::PairingRequest {
                pairing_id: pairing_id.clone(),
                pending_device_id: pending_device_id.clone(),
                pending_device_name: pending_device_name.clone(),
                sas_public_key: sas_public_key.clone(),
                pending_device: Some(device),
            });
        }
    }

    fn pending_notification_count(&self) -> usize {
        self.notifications
            .iter()
            .filter(|notification| notification_requires_action(notification.state))
            .count()
    }

    fn has_pending_chat_request(&self, account_id: &str) -> bool {
        self.notifications.iter().any(|notification| {
            notification.kind == NotificationKind::ChatRequest
                && notification.actor_account_id == account_id
                && matches!(
                    notification.state,
                    NotificationState::Pending | NotificationState::InProgress
                )
        })
    }

    async fn refresh_notifications(&mut self) -> Result<()> {
        let selected_request = self
            .selected_notification()
            .map(|notification| notification.request_id.clone());
        self.notifications = self.store.notifications(&self.vault).await?;
        self.notification_selected = selected_request
            .and_then(|request_id| {
                self.notifications
                    .iter()
                    .position(|notification| notification.request_id == request_id)
            })
            .or_else(|| (!self.notifications.is_empty()).then_some(0));
        if let Some(selected) = self.notification_selected
            && selected >= self.notifications.len()
        {
            self.notification_selected = self.notifications.len().checked_sub(1);
        }
        Ok(())
    }

    async fn save_pairing_notification(&mut self, request: &v1::PairingRequest) -> Result<()> {
        let pending_device = request
            .pending_device
            .as_ref()
            .ok_or_else(|| anyhow!("配对请求缺少设备公钥"))?;
        let old = self
            .store
            .notification_by_request_id(&self.vault, &request.pairing_id)
            .await?;
        let now = now_ms();
        let notification = Notification {
            id: old
                .as_ref()
                .map(|item| item.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            kind: NotificationKind::Pairing,
            request_id: request.pairing_id.clone(),
            actor_account_id: self.profile.account_id.clone(),
            actor_username: request.pending_device_name.clone(),
            actor_device_id: request.pending_device_id.clone(),
            state: old
                .as_ref()
                .map(|item| item.state)
                .unwrap_or(NotificationState::Pending),
            read: old.as_ref().is_some_and(|item| item.read),
            created_at_ms: old.as_ref().map(|item| item.created_at_ms).unwrap_or(now),
            updated_at_ms: now,
            data: NotificationData::Pairing {
                pairing_id: request.pairing_id.clone(),
                pending_device_id: request.pending_device_id.clone(),
                pending_device_name: request.pending_device_name.clone(),
                sas_public_key: request.sas_public_key.clone(),
                pending_device: pending_device.encode_to_vec(),
            },
        };
        self.store
            .save_notification(&self.vault, &notification)
            .await?;
        self.refresh_notifications().await
    }

    async fn save_chat_request_notification(
        &mut self,
        request_id: &str,
        sender: &UserBundle,
        sender_device_id: &str,
    ) -> Result<()> {
        let old = self
            .store
            .notification_by_request_id(&self.vault, request_id)
            .await?;
        let now = now_ms();
        let notification = Notification {
            id: old
                .as_ref()
                .map(|item| item.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            kind: NotificationKind::ChatRequest,
            request_id: request_id.to_owned(),
            actor_account_id: sender.account_id.clone(),
            actor_username: sender.username.clone(),
            actor_device_id: sender_device_id.to_owned(),
            state: old
                .as_ref()
                .map(|item| item.state)
                .unwrap_or(NotificationState::Pending),
            read: old.as_ref().is_some_and(|item| item.read),
            created_at_ms: old.as_ref().map(|item| item.created_at_ms).unwrap_or(now),
            updated_at_ms: now,
            data: NotificationData::ChatRequest {
                outgoing: false,
                request_id: request_id.to_owned(),
                sender_account_id: sender.account_id.clone(),
                sender_username: sender.username.clone(),
                sender_device_id: sender_device_id.to_owned(),
                sender_bundle: sender.encode_to_vec(),
            },
        };
        self.store
            .save_notification(&self.vault, &notification)
            .await?;
        self.refresh_notifications().await
    }

    async fn save_outgoing_chat_request_notification(
        &mut self,
        request_id: &str,
        recipient: &UserBundle,
        sender_device_id: &str,
        initially_read: bool,
    ) -> Result<()> {
        let old = self
            .store
            .notification_by_request_id(&self.vault, request_id)
            .await?;
        let now = now_ms();
        let notification = Notification {
            id: old
                .as_ref()
                .map(|item| item.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            kind: NotificationKind::ChatRequest,
            request_id: request_id.to_owned(),
            actor_account_id: recipient.account_id.clone(),
            actor_username: recipient.username.clone(),
            actor_device_id: sender_device_id.to_owned(),
            state: old
                .as_ref()
                .map(|item| item.state)
                .unwrap_or(NotificationState::Pending),
            read: old.as_ref().map(|item| item.read).unwrap_or(initially_read),
            created_at_ms: old.as_ref().map(|item| item.created_at_ms).unwrap_or(now),
            updated_at_ms: now,
            data: NotificationData::ChatRequest {
                outgoing: true,
                request_id: request_id.to_owned(),
                sender_account_id: recipient.account_id.clone(),
                sender_username: recipient.username.clone(),
                sender_device_id: sender_device_id.to_owned(),
                sender_bundle: recipient.encode_to_vec(),
            },
        };
        self.store
            .save_notification(&self.vault, &notification)
            .await?;
        self.refresh_notifications().await
    }

    async fn save_chat_response_notification(
        &mut self,
        original: &Notification,
        accepted: bool,
        read: bool,
    ) -> Result<()> {
        let notification = Notification {
            id: original.id.clone(),
            kind: NotificationKind::ChatResponse,
            request_id: original.request_id.clone(),
            actor_account_id: original.actor_account_id.clone(),
            actor_username: original.actor_username.clone(),
            actor_device_id: original.actor_device_id.clone(),
            state: if accepted {
                NotificationState::Accepted
            } else {
                NotificationState::Rejected
            },
            read,
            created_at_ms: original.created_at_ms,
            updated_at_ms: now_ms(),
            data: NotificationData::ChatResponse {
                request_id: original.request_id.clone(),
                accepted,
            },
        };
        self.store
            .save_notification(&self.vault, &notification)
            .await?;
        self.refresh_notifications().await
    }

    async fn select_notification_relative(&mut self, direction: isize) -> Result<()> {
        if self.notifications.is_empty() {
            self.notification_selected = None;
            return Ok(());
        }
        let selected = self.notification_selected.unwrap_or(0) as isize;
        self.notification_selected =
            Some((selected + direction).clamp(0, self.notifications.len() as isize - 1) as usize);
        if let Some(notification) = self.selected_notification() {
            self.store.mark_notification_read(&notification.id).await?;
        }
        self.refresh_notifications().await
    }

    async fn open_notification_tab(&mut self) -> Result<()> {
        self.sidebar_tab = SidebarTab::Notifications;
        self.focus = FocusPane::Conversations;
        if self.notification_selected.is_none() && !self.notifications.is_empty() {
            self.notification_selected = Some(0);
        }
        if let Some(notification_id) = self
            .selected_notification()
            .filter(|notification| !notification.read)
            .map(|notification| notification.id.clone())
        {
            self.store.mark_notification_read(&notification_id).await?;
            self.refresh_notifications().await?;
        }
        if let Err(error) = self.reconcile_pairing_notifications().await {
            self.status = format!("通知状态同步失败：{error:#}");
        }
        Ok(())
    }

    async fn mark_notification_state(
        &mut self,
        notification_id: &str,
        state: NotificationState,
        read: bool,
    ) -> Result<()> {
        self.store
            .update_notification_state(notification_id, state, read)
            .await?;
        self.refresh_notifications().await
    }

    async fn activate_selected_notification(&mut self) -> Result<()> {
        let Some(notification) = self.selected_notification().cloned() else {
            self.status = "当前没有选中的通知".to_owned();
            return Ok(());
        };
        self.store.mark_notification_read(&notification.id).await?;
        match notification.kind {
            NotificationKind::Pairing => {
                let NotificationData::Pairing {
                    pairing_id,
                    pending_device_id,
                    pending_device_name,
                    sas_public_key,
                    pending_device,
                } = notification.data
                else {
                    bail!("配对通知数据无效");
                };
                let device = v1::DeviceBundle::decode(pending_device.as_slice())?;
                if !self
                    .pairing_requests
                    .iter()
                    .any(|item| item.pairing_id == pairing_id)
                {
                    self.pairing_requests.push(v1::PairingRequest {
                        pairing_id: pairing_id.clone(),
                        pending_device_id,
                        pending_device_name,
                        sas_public_key,
                        pending_device: Some(device),
                    });
                }
                self.start_pairing(Some(&pairing_id)).await?;
                self.mark_notification_state(&notification.id, NotificationState::InProgress, true)
                    .await?;
            }
            NotificationKind::ChatRequest => {
                self.accept_chat_request(&notification).await?;
            }
            NotificationKind::ChatResponse => {
                self.status = "该通知已经处理".to_owned();
            }
        }
        Ok(())
    }

    async fn activate_notification_primary(&mut self) -> Result<()> {
        let Some(notification) = self.selected_notification().cloned() else {
            return Ok(());
        };
        if notification.kind == NotificationKind::Pairing
            && notification.state == NotificationState::InProgress
            && self
                .pairing
                .as_ref()
                .is_some_and(|pairing| pairing.pairing_id == notification.request_id)
        {
            self.confirm_pairing().await
        } else if notification.kind == NotificationKind::ChatResponse
            && notification.state == NotificationState::Accepted
        {
            self.verify_notification_contact(&notification).await
        } else {
            self.activate_selected_notification().await
        }
    }

    async fn accept_chat_request(&mut self, notification: &Notification) -> Result<()> {
        let NotificationData::ChatRequest {
            outgoing,
            request_id,
            sender_account_id,
            sender_bundle,
            ..
        } = &notification.data
        else {
            bail!("会话请求通知数据无效");
        };
        if *outgoing {
            self.status = "会话请求已发出，等待对方在通知 Tab 中接受".to_owned();
            return Ok(());
        }
        let sender = UserBundle::decode(sender_bundle.as_slice())?;
        if sender.account_id != *sender_account_id {
            bail!("会话请求账号身份不匹配");
        }
        validate_bundle(&sender)?;
        self.store.upsert_contact(&sender).await?;
        self.contacts = self.store.contacts().await?;
        self.selected = self
            .contacts
            .iter()
            .position(|contact| contact.bundle.account_id == sender.account_id);
        self.load_selected_messages().await?;
        self.send_chat_decision(&sender, request_id, true).await?;
        self.save_chat_response_notification(notification, true, true)
            .await?;
        self.sidebar_tab = SidebarTab::Notifications;
        self.focus = FocusPane::Conversations;
        self.status = "已接受会话请求；比较通知详情中的安全码后点击“已核对，认证”".to_owned();
        Ok(())
    }

    async fn verify_notification_contact(&mut self, notification: &Notification) -> Result<()> {
        let Some(index) = self
            .contacts
            .iter()
            .position(|contact| contact.bundle.account_id == notification.actor_account_id)
        else {
            bail!("认证对象不在联系人列表中；请重新执行 /chat 查询联系人");
        };
        self.selected = Some(index);
        self.load_selected_messages().await?;
        self.verify_selected().await?;
        self.sidebar_tab = SidebarTab::Notifications;
        self.focus = FocusPane::Conversations;
        self.status = format!(
            "已认证 {} 的账号密钥，可以开始聊天",
            notification.actor_username
        );
        Ok(())
    }

    async fn reject_selected_chat_request(&mut self) -> Result<()> {
        let Some(notification) = self.selected_notification().cloned() else {
            return Ok(());
        };
        if notification.kind != NotificationKind::ChatRequest {
            self.status = "只有会话请求可以拒绝".to_owned();
            return Ok(());
        }
        let NotificationData::ChatRequest {
            outgoing,
            request_id,
            sender_bundle,
            ..
        } = &notification.data
        else {
            bail!("会话请求通知数据无效");
        };
        if *outgoing {
            self.status = "发出的会话请求不能在本机拒绝".to_owned();
            return Ok(());
        }
        let sender = UserBundle::decode(sender_bundle.as_slice())?;
        validate_bundle(&sender)?;
        self.send_chat_decision(&sender, request_id, false).await?;
        self.save_chat_response_notification(&notification, false, true)
            .await?;
        self.status = "已拒绝会话请求".to_owned();
        Ok(())
    }

    async fn dismiss_selected_notification(&mut self) -> Result<()> {
        let Some(notification) = self.selected_notification().cloned() else {
            return Ok(());
        };
        if matches!(
            notification.state,
            NotificationState::Pending | NotificationState::InProgress
        ) {
            self.status = "待处理通知不能关闭；请先完成操作".to_owned();
            return Ok(());
        }
        self.mark_notification_state(&notification.id, notification.state, true)
            .await?;
        self.status = "通知已标记为已读".to_owned();
        Ok(())
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
                let _ = self.reconcile_pairing_notifications().await;
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
        self.conversation_tab_area = Rect::default();
        self.notification_tab_area = Rect::default();
        self.conversation_delete_areas.clear();
        self.notification_delete_areas.clear();
        self.delete_confirm_area = Rect::default();
        self.delete_cancel_area = Rect::default();
        self.notification_primary_action_area = Rect::default();
        self.notification_secondary_action_area = Rect::default();
        self.emoji_button_area = Rect::default();

        let sidebar_parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(layout.conversations);
        let sidebar_tabs = sidebar_parts[0];
        let sidebar_body = sidebar_parts[1];
        let contact_height = usize::from(sidebar_body.height.saturating_sub(2)).max(1);
        if let Some(selected) = self.selected {
            if selected < self.contact_scroll {
                self.contact_scroll = selected;
            } else if selected >= self.contact_scroll + contact_height {
                self.contact_scroll = selected + 1 - contact_height;
            }
        }
        if let Some(selected) = self.notification_selected {
            if selected < self.notification_scroll {
                self.notification_scroll = selected;
            } else if selected >= self.notification_scroll + contact_height {
                self.notification_scroll = selected + 1 - contact_height;
            }
        }
        if self.sidebar_tab == SidebarTab::Conversations && sidebar_body.width >= 3 {
            self.conversation_delete_areas = list_delete_button_areas(
                sidebar_body,
                self.contact_scroll,
                self.contacts.len(),
                contact_height,
            );
        } else if self.sidebar_tab == SidebarTab::Notifications && sidebar_body.width >= 3 {
            self.notification_delete_areas = list_delete_button_areas(
                sidebar_body,
                self.notification_scroll,
                self.notifications.len(),
                contact_height,
            );
        }
        let list_label_width = usize::from(sidebar_body.width.saturating_sub(3));
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
                let label = fit_to_display_width(
                    &format!("{marker} {}{suffix}", contact.bundle.username),
                    list_label_width,
                );
                ListItem::new(Line::from(vec![Span::raw(label), Span::raw("x")])).style(style)
            })
            .collect();
        if layout.conversations.area() > 0 {
            let pending = self.pending_notification_count();
            let notification_label = if pending == 0 {
                "通知".to_owned()
            } else {
                format!("通知 · {pending}")
            };
            (self.conversation_tab_area, self.notification_tab_area) =
                sidebar_tab_areas(sidebar_tabs, &notification_label);
            let tabs = Line::from(vec![
                Span::styled(
                    if self.sidebar_tab == SidebarTab::Conversations {
                        "[会话]".to_owned()
                    } else {
                        " 会话 ".to_owned()
                    },
                    Style::default().fg(if self.sidebar_tab == SidebarTab::Conversations {
                        Color::Cyan
                    } else {
                        Color::DarkGray
                    }),
                ),
                Span::raw("  "),
                Span::styled(
                    if self.sidebar_tab == SidebarTab::Notifications {
                        format!("[{notification_label}]")
                    } else {
                        format!(" {notification_label} ")
                    },
                    Style::default().fg(if self.sidebar_tab == SidebarTab::Notifications {
                        Color::Cyan
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]);
            frame.render_widget(Paragraph::new(tabs), sidebar_tabs);
            if self.sidebar_tab == SidebarTab::Conversations {
                let title = if layout.narrow {
                    "会话 · Tab 进入聊天"
                } else {
                    "会话 · Alt-N 查看通知"
                };
                frame.render_widget(
                    List::new(contacts)
                        .block(focus_block(title, self.focus == FocusPane::Conversations)),
                    sidebar_body,
                );
            } else {
                let items: Vec<_> = self
                    .notifications
                    .iter()
                    .enumerate()
                    .skip(self.notification_scroll)
                    .take(contact_height)
                    .map(|(index, notification)| {
                        let marker = match notification.kind {
                            NotificationKind::Pairing => "设备",
                            NotificationKind::ChatRequest => "会话",
                            NotificationKind::ChatResponse => "结果",
                        };
                        let state = match notification.state {
                            NotificationState::Pending => "待处理",
                            NotificationState::InProgress => "进行中",
                            NotificationState::Accepted => "已接受",
                            NotificationState::Rejected => "已拒绝",
                            NotificationState::Completed => "已完成",
                            NotificationState::Failed => "失败",
                        };
                        let unread = if notification.read { "" } else { " ●" };
                        let style = if Some(index) == self.notification_selected {
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        let label = fit_to_display_width(
                            &format!("{marker} {} · {state}{unread}", notification.actor_username),
                            list_label_width,
                        );
                        ListItem::new(Line::from(vec![Span::raw(label), Span::raw("x")]))
                            .style(style)
                    })
                    .collect();
                frame.render_widget(
                    List::new(items).block(focus_block(
                        "通知 · Enter 处理",
                        self.focus == FocusPane::Conversations,
                    )),
                    sidebar_body,
                );
            }
            let item_count = if self.sidebar_tab == SidebarTab::Conversations {
                self.contacts.len()
            } else {
                self.notifications.len()
            };
            let scroll = if self.sidebar_tab == SidebarTab::Conversations {
                self.contact_scroll
            } else {
                self.notification_scroll
            };
            if item_count > contact_height {
                let mut state = ScrollbarState::new(item_count)
                    .position(scroll)
                    .viewport_content_length(contact_height);
                frame.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight),
                    sidebar_body,
                    &mut state,
                );
            }
        }

        if self.sidebar_tab == SidebarTab::Notifications {
            self.render_notification_detail(frame, layout.messages);
        } else {
            let visible_messages = usize::from(layout.messages.height.saturating_sub(2)).max(1);
            let contact_verified = self
                .selected_contact()
                .is_some_and(|contact| contact.verified && !contact.identity_changed);
            let lines: Vec<Line<'_>> = if !contact_verified && !self.messages.is_empty() {
                vec![Line::from(Span::styled(
                    "消息已加密保存；请在通知页接受请求、比较安全码并认证后查看",
                    Style::default().fg(Color::DarkGray),
                ))]
            } else if self.messages.is_empty() {
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
        }

        let (cursor_row, cursor_column) = editor_cursor_position(
            self.editor.as_str(),
            self.editor.cursor(),
            layout.composer.width.saturating_sub(2).max(1),
        );
        let inner_height = layout.composer.height.saturating_sub(2).max(1);
        let editor_scroll = cursor_row.saturating_sub(inner_height.saturating_sub(1));
        let (composer_title, emoji_offset, emoji_width) = composer_title(
            &self.profile.username,
            layout.composer.width.saturating_sub(2),
        );
        self.emoji_button_area = Rect::new(
            layout
                .composer
                .x
                .saturating_add(1)
                .saturating_add(emoji_offset),
            layout.composer.y,
            emoji_width.min(
                layout.composer.right().saturating_sub(1).saturating_sub(
                    layout
                        .composer
                        .x
                        .saturating_add(1)
                        .saturating_add(emoji_offset),
                ),
            ),
            1,
        );
        frame.render_widget(
            Paragraph::new(self.editor.as_str())
                .scroll((editor_scroll, 0))
                .wrap(Wrap { trim: false })
                .block(focus_block(
                    &composer_title,
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
        self.render_emoji_picker(frame);
        if self.help_visible {
            self.render_help(frame);
        }
        self.render_delete_confirmation(frame);
        if self.focus == FocusPane::Composer
            && !self.help_visible
            && !self.emoji_picker.visible
            && self.delete_confirmation.is_none()
        {
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
                if self.emoji_picker.visible {
                    self.append_emoji_query(&text);
                    return Ok(());
                }
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
        if self.delete_confirmation.is_some() {
            self.handle_delete_confirmation_key(key).await?;
            return Ok(());
        }
        if key.modifiers.contains(KeyModifiers::ALT) && key.code == KeyCode::Char('e') {
            if self.emoji_picker.visible {
                self.emoji_picker.visible = false;
                self.emoji_picker_area = Rect::default();
                self.emoji_grid_area = Rect::default();
            } else {
                self.open_emoji_picker("");
            }
            return Ok(());
        }
        if self.emoji_picker.visible {
            self.handle_emoji_key(key);
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
                KeyCode::Up => {
                    return if self.sidebar_tab == SidebarTab::Notifications
                        && self.focus == FocusPane::Conversations
                    {
                        self.select_notification_relative(-1).await
                    } else {
                        self.select_relative(-1).await
                    };
                }
                KeyCode::Down => {
                    return if self.sidebar_tab == SidebarTab::Notifications
                        && self.focus == FocusPane::Conversations
                    {
                        self.select_notification_relative(1).await
                    } else {
                        self.select_relative(1).await
                    };
                }
                KeyCode::Char('n') => {
                    self.open_notification_tab().await?;
                    return Ok(());
                }
                KeyCode::Char('c') => {
                    self.sidebar_tab = SidebarTab::Conversations;
                    self.focus = FocusPane::Conversations;
                    return Ok(());
                }
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
                KeyCode::Char('n') if !self.completion.is_open() => {
                    self.open_notification_tab().await?;
                }
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
            KeyCode::Char('x') if self.focus == FocusPane::Conversations => {
                match self.sidebar_tab {
                    SidebarTab::Conversations => {
                        if let Some(index) = self.selected {
                            self.request_delete_conversation(index);
                        }
                    }
                    SidebarTab::Notifications => {
                        if let Some(index) = self.notification_selected {
                            self.request_delete_notification(index);
                        }
                    }
                }
            }
            KeyCode::Enter
                if self.focus == FocusPane::Conversations
                    && self.sidebar_tab == SidebarTab::Notifications =>
            {
                self.activate_notification_primary().await?;
            }
            KeyCode::Char('r')
                if self.focus == FocusPane::Conversations
                    && self.sidebar_tab == SidebarTab::Notifications =>
            {
                self.reject_selected_chat_request().await?;
            }
            KeyCode::Char('d')
                if self.focus == FocusPane::Conversations
                    && self.sidebar_tab == SidebarTab::Notifications =>
            {
                self.dismiss_selected_notification().await?;
            }
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
                FocusPane::Conversations if self.sidebar_tab == SidebarTab::Notifications => {
                    self.select_notification_relative(-1).await?
                }
                FocusPane::Conversations => self.select_relative(-1).await?,
                FocusPane::Messages => {
                    self.scroll_messages(3);
                    self.load_older_messages().await?;
                }
                FocusPane::Composer => self.editor.move_vertical(-1),
            },
            KeyCode::Down => match self.focus {
                FocusPane::Conversations if self.sidebar_tab == SidebarTab::Notifications => {
                    self.select_notification_relative(1).await?
                }
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
        } else if trimmed == "/emoji" {
            self.open_emoji_picker("");
            Ok(())
        } else if let Some(query) = trimmed.strip_prefix("/emoji ") {
            self.open_emoji_picker(query.trim());
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

    fn emoji_matches(&self) -> Vec<usize> {
        matching_emojis(&self.emoji_picker.query)
    }

    fn open_emoji_picker(&mut self, query: &str) {
        self.emoji_picker.visible = true;
        self.emoji_picker.query.clear();
        self.append_emoji_query(query);
        self.emoji_picker.selected = 0;
        self.emoji_picker.scroll = 0;
        self.completion = CompletionState::default();
        self.focus = FocusPane::Composer;
        self.status = "输入中文或英文搜索 Emoji；Enter 或点击插入".to_owned();
    }

    fn append_emoji_query(&mut self, text: &str) {
        for grapheme in text.graphemes(true) {
            if grapheme.chars().any(char::is_control)
                || self.emoji_picker.query.len() + grapheme.len() > 128
            {
                continue;
            }
            self.emoji_picker.query.push_str(grapheme);
        }
        self.emoji_picker.selected = 0;
        self.emoji_picker.scroll = 0;
    }

    fn cycle_emoji(&mut self, direction: isize) {
        let count = self.emoji_matches().len();
        if count == 0 {
            self.emoji_picker.selected = 0;
            self.emoji_picker.scroll = 0;
            return;
        }
        self.emoji_picker.selected =
            (self.emoji_picker.selected as isize + direction).rem_euclid(count as isize) as usize;
    }

    fn insert_selected_emoji(&mut self) {
        let matches = self.emoji_matches();
        let Some(index) = matches.get(self.emoji_picker.selected) else {
            self.status = "没有匹配的 Emoji".to_owned();
            return;
        };
        let emoji = EMOJI_CATALOG[*index];
        if self
            .editor
            .insert(emoji.glyph, tui_chat_protocol::MAX_TEXT_BYTES)
        {
            self.status = format!("已插入 {} {}", emoji.glyph, emoji.name);
        } else {
            self.status = "消息已达到 16 KiB，无法继续插入".to_owned();
        }
        self.emoji_picker.visible = false;
        self.emoji_picker_area = Rect::default();
        self.emoji_grid_area = Rect::default();
        self.focus = FocusPane::Composer;
        self.refresh_completion();
    }

    fn handle_emoji_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.emoji_picker.visible = false;
                self.emoji_picker_area = Rect::default();
                self.emoji_grid_area = Rect::default();
            }
            KeyCode::Enter => self.insert_selected_emoji(),
            KeyCode::Left => self.cycle_emoji(-1),
            KeyCode::Right => self.cycle_emoji(1),
            KeyCode::Up => self.cycle_emoji(-(self.emoji_picker.columns.max(1) as isize)),
            KeyCode::Down => self.cycle_emoji(self.emoji_picker.columns.max(1) as isize),
            KeyCode::PageUp => self.cycle_emoji(-(self.emoji_picker.page_size.max(1) as isize)),
            KeyCode::PageDown => self.cycle_emoji(self.emoji_picker.page_size.max(1) as isize),
            KeyCode::Tab => self.cycle_emoji(1),
            KeyCode::BackTab => self.cycle_emoji(-1),
            KeyCode::Backspace => {
                if let Some((index, _)) = self.emoji_picker.query.grapheme_indices(true).next_back()
                {
                    self.emoji_picker.query.truncate(index);
                }
                self.emoji_picker.selected = 0;
                self.emoji_picker.scroll = 0;
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.emoji_picker.query.clear();
                self.emoji_picker.selected = 0;
                self.emoji_picker.scroll = 0;
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let mut bytes = [0_u8; 4];
                self.append_emoji_query(character.encode_utf8(&mut bytes));
            }
            _ => {}
        }
        true
    }

    fn refresh_completion(&mut self) {
        let input = self.editor.as_str();
        if self.editor.cursor() != input.len() || !input.starts_with('/') || input.starts_with("//")
        {
            self.completion = CompletionState::default();
            return;
        }
        let commands = [
            "/chat ", "/emoji", "/search ", "/verify", "/pair ", "/confirm", "/sync", "/help",
            "/exit", "/quit",
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

    fn render_emoji_picker(&mut self, frame: &mut ratatui::Frame<'_>) {
        if !self.emoji_picker.visible || self.help_visible {
            self.emoji_picker_area = Rect::default();
            self.emoji_grid_area = Rect::default();
            return;
        }
        let width = frame.area().width.saturating_sub(4).min(68);
        let height = frame.area().height.saturating_sub(2).min(14);
        let area = centered_rect(width, height, frame.area());
        self.emoji_picker_area = area;
        let (grid_area, columns, cell_width) = emoji_grid_layout(area);
        self.emoji_grid_area = grid_area;
        self.emoji_picker.columns = columns;
        let matches = self.emoji_matches();
        let visible_rows = usize::from(grid_area.height).max(1);
        self.emoji_picker.page_size = columns.saturating_mul(visible_rows);
        if self.emoji_picker.selected >= matches.len() {
            self.emoji_picker.selected = matches.len().saturating_sub(1);
        }
        if matches.is_empty() {
            self.emoji_picker.scroll = 0;
        } else {
            let selected_row = self.emoji_picker.selected / columns;
            let mut first_row = self.emoji_picker.scroll / columns;
            if selected_row < first_row {
                first_row = selected_row;
            } else if selected_row >= first_row + visible_rows {
                first_row = selected_row + 1 - visible_rows;
            }
            self.emoji_picker.scroll = first_row * columns;
        }
        let mut lines = vec![Line::from(vec![
            Span::styled("搜索：", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if self.emoji_picker.query.is_empty() {
                    "输入中文或英文关键词"
                } else {
                    self.emoji_picker.query.as_str()
                },
                Style::default().fg(Color::White),
            ),
        ])];
        if matches.is_empty() {
            lines.push(Line::from("没有匹配项，Backspace 修改关键词"));
        } else {
            for row in 0..visible_rows {
                let row_start = self.emoji_picker.scroll + row * columns;
                if row_start >= matches.len() {
                    break;
                }
                let mut cells = Vec::with_capacity(columns);
                for column in 0..columns {
                    let visible_index = row_start + column;
                    let Some(catalog_index) = matches.get(visible_index) else {
                        break;
                    };
                    let emoji = EMOJI_CATALOG[*catalog_index];
                    let label = fit_to_display_width(
                        &format!("{} {}", emoji.glyph, emoji.name),
                        usize::from(cell_width),
                    );
                    let style = if visible_index == self.emoji_picker.selected {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    cells.push(Span::styled(label, style));
                }
                lines.push(Line::from(cells));
            }
        }
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title("Emoji · 方向键选择 · Enter/点击插入 · Esc 关闭")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            ),
            area,
        );
    }

    fn render_notification_detail(&mut self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        if area.area() == 0 {
            return;
        }
        let Some(notification) = self.selected_notification().cloned() else {
            frame.render_widget(
                Paragraph::new("暂无通知；当设备配对或收到新的会话请求时会显示在这里")
                    .block(focus_block("通知详情", self.focus == FocusPane::Messages)),
                area,
            );
            return;
        };
        let verification_contact = self
            .contacts
            .iter()
            .find(|contact| contact.bundle.account_id == notification.actor_account_id);
        let can_verify = verification_contact.is_some_and(|contact| {
            should_offer_contact_verification(
                notification.kind,
                notification.state,
                contact.verified,
                contact.identity_changed,
            )
        });
        let (kind, action) = match notification.kind {
            NotificationKind::Pairing => (
                "多设备配对请求",
                "Enter 开始 SAS 配对；双方核对短认证码后输入 /confirm".to_owned(),
            ),
            NotificationKind::ChatRequest => {
                let outgoing = matches!(
                    &notification.data,
                    NotificationData::ChatRequest { outgoing: true, .. }
                );
                if outgoing {
                    (
                        "会话请求已发出",
                        "等待对方接受；收到结果后在这里比较安全码".to_owned(),
                    )
                } else {
                    (
                        "新的会话请求",
                        "Enter 或点击接受；接受后在这里比较安全码并认证；r 拒绝".to_owned(),
                    )
                }
            }
            NotificationKind::ChatResponse if can_verify => (
                "会话请求结果",
                "通过电话或当面比较安全码；完全一致后点击“已核对，认证”".to_owned(),
            ),
            NotificationKind::ChatResponse
                if notification.state == NotificationState::Completed =>
            {
                (
                    "会话请求结果",
                    "账号密钥已认证，可以进入会话发送消息".to_owned(),
                )
            }
            NotificationKind::ChatResponse => ("会话请求结果", "该会话请求已经处理".to_owned()),
        };
        let state = match notification.state {
            NotificationState::Pending => "待处理",
            NotificationState::InProgress => "进行中",
            NotificationState::Accepted => "已接受",
            NotificationState::Rejected => "已拒绝",
            NotificationState::Completed => "已完成",
            NotificationState::Failed => "失败",
        };
        let mut lines = vec![
            Line::from(Span::styled(
                kind,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("对象：{}", notification.actor_username)),
            Line::from(format!("状态：{state}")),
            Line::from(format!("请求 ID：{}", notification.request_id)),
        ];
        if matches!(
            notification.state,
            NotificationState::Accepted | NotificationState::Completed
        ) && let Some(code) =
            verification_contact.and_then(|contact| self.safety_code_for_contact(contact))
        {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("安全码：", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    code,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(action));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(focus_block("通知详情", self.focus == FocusPane::Messages)),
            area,
        );
        let (primary, secondary) = match notification.kind {
            NotificationKind::Pairing
                if matches!(
                    notification.state,
                    NotificationState::Pending | NotificationState::InProgress
                ) =>
            {
                let label = if self
                    .pairing
                    .as_ref()
                    .is_some_and(|pairing| pairing.pairing_id == notification.request_id)
                {
                    "确认 SAS"
                } else if notification.state == NotificationState::InProgress {
                    "继续配对"
                } else {
                    "开始配对"
                };
                (Some((label, Color::Yellow)), None)
            }
            NotificationKind::ChatRequest
                if notification.state == NotificationState::Pending
                    && matches!(
                        &notification.data,
                        NotificationData::ChatRequest {
                            outgoing: false,
                            ..
                        }
                    ) =>
            {
                (Some(("接受", Color::Green)), Some(("拒绝", Color::Red)))
            }
            NotificationKind::ChatResponse if can_verify => {
                (Some(("已核对，认证", Color::Green)), None)
            }
            _ => (None, None),
        };
        let button_y = area.bottom().saturating_sub(2);
        let mut button_x = area.x.saturating_add(2);
        if let Some((label, color)) = primary {
            let width = (UnicodeWidthStr::width(label) as u16).saturating_add(4);
            self.notification_primary_action_area = Rect::new(
                button_x,
                button_y,
                width.min(area.right().saturating_sub(button_x)),
                1,
            );
            render_action_button(frame, self.notification_primary_action_area, label, color);
            button_x = button_x.saturating_add(width).saturating_add(2);
        }
        if let Some((label, color)) = secondary {
            let width = (UnicodeWidthStr::width(label) as u16).saturating_add(4);
            self.notification_secondary_action_area = Rect::new(
                button_x,
                button_y,
                width.min(area.right().saturating_sub(button_x)),
                1,
            );
            render_action_button(frame, self.notification_secondary_action_area, label, color);
        }
    }

    fn request_delete_conversation(&mut self, contact_index: usize) {
        let Some(contact) = self.contacts.get(contact_index) else {
            return;
        };
        self.delete_confirmation = Some(DeleteConfirmation {
            target: DeleteTarget::Conversation {
                account_id: contact.bundle.account_id.clone(),
                username: contact.bundle.username.clone(),
                conversation_id: conversation_id(
                    &self.profile.account_id,
                    &contact.bundle.account_id,
                ),
            },
            confirm_selected: false,
        });
        self.completion = CompletionState::default();
        self.status = format!("确认是否删除与 {} 的本机会话", contact.bundle.username);
    }

    fn request_delete_notification(&mut self, notification_index: usize) {
        let Some(notification) = self.notifications.get(notification_index) else {
            return;
        };
        let kind = match notification.kind {
            NotificationKind::Pairing => "设备配对",
            NotificationKind::ChatRequest => "会话请求",
            NotificationKind::ChatResponse => "会话结果",
        };
        let title = format!("{kind} · {}", notification.actor_username);
        self.delete_confirmation = Some(DeleteConfirmation {
            target: DeleteTarget::Notification {
                notification_id: notification.id.clone(),
                title,
                request_id: notification.request_id.clone(),
            },
            confirm_selected: false,
        });
        self.completion = CompletionState::default();
        self.status = "确认是否删除这条本机通知".to_owned();
    }

    async fn handle_delete_confirmation_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<()> {
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
                if let Some(dialog) = self.delete_confirmation.as_mut() {
                    dialog.confirm_selected = !dialog.confirm_selected;
                }
            }
            KeyCode::Char('y') => {
                if let Err(error) = self.confirm_delete().await {
                    self.status = format!("删除失败：{error:#}");
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => self.cancel_delete(),
            KeyCode::Enter => {
                if self
                    .delete_confirmation
                    .as_ref()
                    .is_some_and(|dialog| dialog.confirm_selected)
                {
                    if let Err(error) = self.confirm_delete().await {
                        self.status = format!("删除失败：{error:#}");
                    }
                } else {
                    self.cancel_delete();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn cancel_delete(&mut self) {
        self.delete_confirmation = None;
        self.delete_confirm_area = Rect::default();
        self.delete_cancel_area = Rect::default();
        self.status = "已取消删除".to_owned();
    }

    async fn confirm_delete(&mut self) -> Result<()> {
        let Some(dialog) = self.delete_confirmation.clone() else {
            return Ok(());
        };
        match dialog.target {
            DeleteTarget::Conversation {
                account_id,
                username,
                conversation_id,
            } => {
                let selected_account = self
                    .selected_contact()
                    .map(|contact| contact.bundle.account_id.clone());
                self.store
                    .delete_conversation(&account_id, &conversation_id)
                    .await?;
                self.bundle_cache.remove(&username);
                self.contacts = self.store.contacts().await?;
                self.selected = selected_account
                    .filter(|selected| selected != &account_id)
                    .and_then(|selected| {
                        self.contacts
                            .iter()
                            .position(|contact| contact.bundle.account_id == selected)
                    });
                if self.selected.is_none() {
                    self.messages.clear();
                    self.editor.clear();
                    self.persisted_draft.clear();
                    self.message_scroll = 0;
                    self.new_messages_below = 0;
                    self.history_exhausted = true;
                }
                self.contact_scroll = self
                    .contact_scroll
                    .min(self.contacts.len().saturating_sub(1));
                self.refresh_notifications().await?;
                self.status =
                    format!("已删除与 {username} 的本机会话；再次收到消息时需要在通知页重新认证");
            }
            DeleteTarget::Notification {
                notification_id,
                title,
                request_id,
            } => {
                self.store.delete_notification(&notification_id).await?;
                if self
                    .pairing
                    .as_ref()
                    .is_none_or(|pairing| pairing.pairing_id != request_id)
                {
                    self.pairing_requests
                        .retain(|request| request.pairing_id != request_id);
                }
                self.refresh_notifications().await?;
                self.status = format!("已删除通知“{title}”；不会拒绝或取消对应请求");
            }
        }
        self.delete_confirmation = None;
        self.delete_confirm_area = Rect::default();
        self.delete_cancel_area = Rect::default();
        Ok(())
    }

    fn render_delete_confirmation(&mut self, frame: &mut ratatui::Frame<'_>) {
        let Some(dialog) = self.delete_confirmation.as_ref() else {
            self.delete_confirm_area = Rect::default();
            self.delete_cancel_area = Rect::default();
            return;
        };
        let width = frame.area().width.saturating_sub(4).min(62);
        let height = frame.area().height.saturating_sub(2).min(10);
        let area = centered_rect(width, height, frame.area());
        let (title, question, first_warning, second_warning) = match &dialog.target {
            DeleteTarget::Conversation { username, .. } => {
                let username = sanitize_terminal_text(username);
                (
                    "删除会话",
                    format!("确定删除与 {username} 的会话？"),
                    "将删除本机的聊天记录、草稿、联系人入口和相关通知。",
                    "不会撤回消息；再次收到对方消息时需要重新认证。",
                )
            }
            DeleteTarget::Notification { title, .. } => (
                "删除通知",
                format!("确定删除通知“{}”？", sanitize_terminal_text(title)),
                "将只删除这台设备上的通知记录。",
                "不会拒绝会话请求，也不会取消正在进行的设备配对。",
            ),
        };
        let lines = vec![
            Line::from(Span::styled(
                question,
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(first_warning),
            Line::from(second_warning),
            Line::from(""),
            Line::from("←/→ 选择 · Enter 执行 · Esc 取消 · y 直接确认"),
        ];
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            ),
            area,
        );

        let cancel_label = "取消";
        let confirm_label = "确认删除";
        let cancel_width = UnicodeWidthStr::width(format!("[ {cancel_label} ]").as_str()) as u16;
        let confirm_width = UnicodeWidthStr::width(format!("[ {confirm_label} ]").as_str()) as u16;
        let gap = 2;
        let total_width = cancel_width
            .saturating_add(gap)
            .saturating_add(confirm_width);
        let start_x = area
            .x
            .saturating_add(area.width.saturating_sub(total_width) / 2);
        let button_y = area.bottom().saturating_sub(2);
        self.delete_cancel_area = Rect::new(start_x, button_y, cancel_width, 1);
        self.delete_confirm_area = Rect::new(
            start_x.saturating_add(cancel_width).saturating_add(gap),
            button_y,
            confirm_width,
            1,
        );
        render_choice_button(
            frame,
            self.delete_cancel_area,
            cancel_label,
            Color::Cyan,
            !dialog.confirm_selected,
        );
        render_choice_button(
            frame,
            self.delete_confirm_area,
            confirm_label,
            Color::Red,
            dialog.confirm_selected,
        );
    }

    fn render_help(&self, frame: &mut ratatui::Frame<'_>) {
        let width = frame.area().width.saturating_sub(4).min(70);
        let height = frame.area().height.saturating_sub(2).min(22);
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
            Line::from("Alt-N / Alt-C       通知 / 会话 Tab"),
            Line::from("Alt-E               打开 Unicode Emoji 选择器"),
            Line::from("会话 Tab: x         删除会话并打开二次确认"),
            Line::from("通知 Tab: Enter 处理，r 拒绝，d 已读，x 删除"),
            Line::from("PageUp / PageDown   滚动消息"),
            Line::from("Ctrl-Home / End     消息顶部 / 底部"),
            Line::from("Enter / Shift/Alt-Enter  发送 / 换行"),
            Line::from("Ctrl-A/E/W/U        文首 / 文末 / 删词 / 删到行首"),
            Line::from("Ctrl-K / Ctrl-F     命令面板 / 搜索已加载消息"),
            Line::from("Ctrl-R / Ctrl-L     同步重连 / 重绘屏幕"),
            Line::from("Ctrl-C / Ctrl-Q      退出"),
            Line::from(""),
            Line::from(
                "/chat 用户名 · /emoji [关键词] · /search 关键词 · /verify · /pair · /confirm",
            ),
            Line::from("/sync · /help · /exit · /quit"),
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
        if self.delete_confirmation.is_some() {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                let position = Position::new(mouse.column, mouse.row);
                if self.delete_confirm_area.contains(position) {
                    if let Err(error) = self.confirm_delete().await {
                        self.status = format!("删除失败：{error:#}");
                    }
                } else if self.delete_cancel_area.contains(position) {
                    self.cancel_delete();
                }
            }
            return Ok(());
        }
        if self.emoji_picker.visible {
            self.handle_emoji_mouse(mouse);
            return Ok(());
        }
        let position = Position::new(mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if self.emoji_button_area.contains(position) {
                    self.open_emoji_picker("");
                    return Ok(());
                }
                if self.conversation_tab_area.contains(position) {
                    self.sidebar_tab = SidebarTab::Conversations;
                    self.focus = FocusPane::Conversations;
                    return Ok(());
                }
                if self.notification_tab_area.contains(position) {
                    self.open_notification_tab().await?;
                    return Ok(());
                }
                if self.notification_primary_action_area.contains(position) {
                    self.activate_notification_primary().await?;
                    return Ok(());
                }
                if self.notification_secondary_action_area.contains(position) {
                    self.reject_selected_chat_request().await?;
                    return Ok(());
                }
                if let Some(contact_index) = self
                    .conversation_delete_areas
                    .iter()
                    .find_map(|(index, area)| area.contains(position).then_some(*index))
                {
                    self.request_delete_conversation(contact_index);
                    return Ok(());
                }
                if let Some(notification_index) = self
                    .notification_delete_areas
                    .iter()
                    .find_map(|(index, area)| area.contains(position).then_some(*index))
                {
                    self.request_delete_notification(notification_index);
                    return Ok(());
                }
                if self.layout.conversations.contains(position) {
                    self.focus = FocusPane::Conversations;
                    if mouse.column == self.layout.conversations.right().saturating_sub(1) {
                        self.dragging = Some(DragTarget::Conversations);
                        self.drag_scrollbar(mouse.row);
                    } else if mouse.row > self.layout.conversations.y.saturating_add(1)
                        && mouse.row < self.layout.conversations.bottom().saturating_sub(1)
                    {
                        if self.sidebar_tab == SidebarTab::Conversations {
                            let index = self.contact_scroll
                                + usize::from(mouse.row - self.layout.conversations.y - 2);
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
                        } else {
                            let index = self.notification_scroll
                                + usize::from(mouse.row - self.layout.conversations.y - 2);
                            if index < self.notifications.len() {
                                self.notification_selected = Some(index);
                                let id = self.notifications[index].id.clone();
                                self.store.mark_notification_read(&id).await?;
                                self.refresh_notifications().await?;
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
                    if self.sidebar_tab == SidebarTab::Conversations {
                        self.contact_scroll = self.contact_scroll.saturating_sub(3);
                    } else {
                        self.notification_scroll = self.notification_scroll.saturating_sub(3);
                    }
                } else if self.layout.messages.contains(position) {
                    self.scroll_messages(3);
                    self.load_older_messages().await?;
                }
            }
            MouseEventKind::ScrollDown => {
                if self.layout.conversations.contains(position) {
                    let maximum = if self.sidebar_tab == SidebarTab::Conversations {
                        self.contacts.len().saturating_sub(usize::from(
                            self.layout.conversations.height.saturating_sub(3).max(1),
                        ))
                    } else {
                        self.notifications.len().saturating_sub(usize::from(
                            self.layout.conversations.height.saturating_sub(3).max(1),
                        ))
                    };
                    if self.sidebar_tab == SidebarTab::Conversations {
                        self.contact_scroll = (self.contact_scroll + 3).min(maximum);
                    } else {
                        self.notification_scroll = (self.notification_scroll + 3).min(maximum);
                    }
                } else if self.layout.messages.contains(position) {
                    self.scroll_messages(-3);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_emoji_mouse(&mut self, mouse: MouseEvent) {
        let position = Position::new(mouse.column, mouse.row);
        if !self.emoji_picker_area.contains(position) {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                self.emoji_picker.visible = false;
                self.emoji_picker_area = Rect::default();
                self.emoji_grid_area = Rect::default();
            }
            return;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.cycle_emoji(-(self.emoji_picker.columns.max(1) as isize))
            }
            MouseEventKind::ScrollDown => {
                self.cycle_emoji(self.emoji_picker.columns.max(1) as isize)
            }
            MouseEventKind::Down(MouseButton::Left) if self.emoji_grid_area.contains(position) => {
                let matches = self.emoji_matches();
                let columns = self.emoji_picker.columns.max(1);
                let cell_width = self.emoji_grid_area.width / columns as u16;
                let row = usize::from(mouse.row - self.emoji_grid_area.y);
                let column = usize::from(mouse.column - self.emoji_grid_area.x)
                    / usize::from(cell_width.max(1));
                let selected = self.emoji_picker.scroll + row * columns + column;
                if selected < matches.len() {
                    self.emoji_picker.selected = selected;
                    self.insert_selected_emoji();
                }
            }
            _ => {}
        }
    }

    fn drag_scrollbar(&mut self, row: u16) {
        match self.dragging {
            Some(DragTarget::Conversations) => {
                let inner = self.layout.conversations.height.saturating_sub(3).max(1);
                let relative = row
                    .saturating_sub(self.layout.conversations.y.saturating_add(2))
                    .min(inner);
                let item_count = if self.sidebar_tab == SidebarTab::Conversations {
                    self.contacts.len()
                } else {
                    self.notifications.len()
                };
                let maximum = item_count.saturating_sub(usize::from(inner));
                let value = maximum * usize::from(relative) / usize::from(inner);
                if self.sidebar_tab == SidebarTab::Conversations {
                    self.contact_scroll = value;
                } else {
                    self.notification_scroll = value;
                }
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
        if !contact.verified || contact.identity_changed {
            self.send_chat_request(&bundle).await?;
        }
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
        if self.has_pending_chat_request(&account) {
            bail!("会话请求尚未被对方接受；请先在通知 Tab 等待结果");
        }
        self.store.verify_contact(&account).await?;
        if let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|contact| contact.bundle.account_id == account)
        {
            contact.verified = true;
            contact.identity_changed = false;
        }
        if let Some(notification_id) = self
            .notifications
            .iter()
            .find(|notification| {
                notification.kind == NotificationKind::ChatResponse
                    && notification.actor_account_id == account
                    && notification.state == NotificationState::Accepted
            })
            .map(|notification| notification.id.clone())
        {
            self.mark_notification_state(&notification_id, NotificationState::Completed, true)
                .await?;
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
        let Some(code) = self.safety_code_for_contact(contact) else {
            self.status = "该设备仍在等待旧设备配对".to_owned();
            return;
        };
        self.status = format!("安全码：{code}；通过电话/当面比较后输入 /verify");
    }

    fn safety_code_for_contact(&self, contact: &Contact) -> Option<String> {
        let our_master = self.profile.identity.master_public_key()?;
        Some(safety_code(
            &self.profile.username,
            &our_master,
            &contact.bundle.username,
            &contact.bundle.account_master_key,
        ))
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
        let pairing_id = self
            .pairing
            .as_ref()
            .map(|pairing| pairing.pairing_id.clone());
        if let Some(pairing_id) = pairing_id
            && let Some(notification) = self
                .store
                .notification_by_request_id(&self.vault, &pairing_id)
                .await?
        {
            self.mark_notification_state(&notification.id, NotificationState::InProgress, true)
                .await?;
        }
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
                if let Some(notification) = self
                    .store
                    .notification_by_request_id(&self.vault, &event.pairing_id)
                    .await?
                {
                    self.mark_notification_state(
                        &notification.id,
                        NotificationState::Completed,
                        true,
                    )
                    .await?;
                }
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
        let self_bundle = self.lookup_bundle_fresh(&username).await?;
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
        if let Some(notification) = self
            .store
            .notification_by_request_id(&self.vault, &pairing.pairing_id)
            .await?
        {
            self.mark_notification_state(&notification.id, NotificationState::Completed, true)
                .await?;
        }
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
        self.handle_server_event(response).await?;
        self.reconcile_pairing_notifications().await
    }

    async fn reconcile_pairing_notifications(&mut self) -> Result<()> {
        if self.profile.pending
            || !self.notifications.iter().any(|notification| {
                notification.kind == NotificationKind::Pairing
                    && notification_requires_action(notification.state)
            })
        {
            return Ok(());
        }
        let username = self.profile.username.clone();
        let bundle = self.lookup_bundle_fresh(&username).await?;
        validate_bundle(&bundle)?;
        if bundle.account_id != self.profile.account_id
            || bundle.account_master_key != self.profile.account_master_public
        {
            bail!("服务器返回的本账号设备列表不匹配");
        }
        let completed: Vec<(String, String)> = self
            .notifications
            .iter()
            .filter(|notification| {
                notification.kind == NotificationKind::Pairing
                    && notification_requires_action(notification.state)
                    && bundle.devices.iter().any(|device| {
                        !device.revoked && device.device_id == notification.actor_device_id
                    })
            })
            .map(|notification| {
                (
                    notification.id.clone(),
                    notification.actor_device_id.clone(),
                )
            })
            .collect();
        if completed.is_empty() {
            return Ok(());
        }
        for (notification_id, _) in &completed {
            self.store
                .update_notification_state(notification_id, NotificationState::Completed, true)
                .await?;
        }
        self.pairing_requests.retain(|request| {
            !completed
                .iter()
                .any(|(_, device_id)| request.pending_device_id == *device_id)
        });
        self.refresh_notifications().await?;
        self.status = format!("已同步 {} 条设备配对结果", completed.len());
        Ok(())
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
                if request.pending_device_id != self.profile.identity.device_id() =>
            {
                self.save_pairing_notification(&request).await?;
                if !self
                    .pairing_requests
                    .iter()
                    .any(|item| item.pairing_id == request.pairing_id)
                {
                    self.status = format!(
                        "设备 {} 请求加入；通知 Tab 中按 Enter 开始配对",
                        request.pending_device_name
                    );
                    self.pairing_requests.push(request);
                }
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
            let is_control = matches!(
                payload.kind.as_str(),
                "read" | "read_batch" | "chat_request" | "chat_response"
            );
            if !verified && !is_control {
                if payload.kind != "text"
                    || payload.text.len() > tui_chat_protocol::MAX_TEXT_BYTES
                    || payload.peer_account_id != self.profile.account_id
                {
                    bail!("未认证的端到端正文元数据无效");
                }
                // Use one stable local re-authentication request per conversation so a burst of
                // quarantined messages does not flood the notification list.
                let request_id = format!("reauth-{}", envelope.conversation_id);
                let message = ChatMessage {
                    id: payload.message_id.clone(),
                    conversation_id: envelope.conversation_id.clone(),
                    peer_account_id: stored.sender_account_id.clone(),
                    sender_account_id: stored.sender_account_id.clone(),
                    body: payload.text.clone(),
                    sent_at_ms: payload.sent_at_ms,
                    status: MessageStatus::Delivered,
                    inbound: true,
                };
                let now = now_ms();
                let previous_notification = self
                    .store
                    .notification_by_request_id(&self.vault, &request_id)
                    .await?;
                let notification = if let Some(previous) =
                    previous_notification.as_ref().filter(|notification| {
                        matches!(
                            notification.state,
                            NotificationState::Accepted | NotificationState::InProgress
                        )
                    }) {
                    let mut notification = previous.clone();
                    notification.updated_at_ms = now;
                    notification
                } else {
                    Notification {
                        id: previous_notification
                            .as_ref()
                            .map(|notification| notification.id.clone())
                            .unwrap_or_else(|| Uuid::new_v4().to_string()),
                        kind: NotificationKind::ChatRequest,
                        request_id: request_id.clone(),
                        actor_account_id: bundle.account_id.clone(),
                        actor_username: bundle.username.clone(),
                        actor_device_id: stored.sender_device_id.clone(),
                        state: NotificationState::Pending,
                        read: false,
                        created_at_ms: previous_notification
                            .as_ref()
                            .filter(|notification| notification.state == NotificationState::Pending)
                            .map(|notification| notification.created_at_ms)
                            .unwrap_or(now),
                        updated_at_ms: now,
                        data: NotificationData::ChatRequest {
                            outgoing: false,
                            request_id,
                            sender_account_id: bundle.account_id.clone(),
                            sender_username: bundle.username.clone(),
                            sender_device_id: stored.sender_device_id.clone(),
                            sender_bundle: bundle.encode_to_vec(),
                        },
                    }
                };
                let previous_machine = std::mem::replace(&mut self.profile.machine, next_machine);
                let committed = self
                    .store
                    .commit_unverified_inbound(
                        &self.vault,
                        &self.profile,
                        &message,
                        &notification,
                        stored.cursor,
                    )
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
                self.contacts = self.store.contacts().await?;
                self.refresh_notifications().await?;
                self.status = format!(
                    "收到来自 {} 的消息；请在通知页接受请求、比较安全码并认证",
                    stored.sender_username
                );
                continue;
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
            if payload.kind == "chat_request" {
                if sender_is_self {
                    if payload.peer_account_id == self.profile.account_id
                        || payload.text.trim().is_empty()
                    {
                        bail!("本账号会话请求同步元数据无效");
                    }
                    let peer = self.lookup_bundle(payload.text.trim()).await?;
                    if peer.account_id != payload.peer_account_id {
                        bail!("本账号会话请求同步对象不匹配");
                    }
                    validate_bundle(&peer)?;
                    self.store.upsert_contact(&peer).await?;
                    self.save_outgoing_chat_request_notification(
                        &payload.message_id,
                        &peer,
                        &stored.sender_device_id,
                        false,
                    )
                    .await?;
                } else {
                    if payload.peer_account_id != self.profile.account_id
                        || !payload.text.is_empty()
                    {
                        bail!("会话请求元数据无效");
                    }
                    self.save_chat_request_notification(
                        &payload.message_id,
                        &bundle,
                        &stored.sender_device_id,
                    )
                    .await?;
                }
                self.contacts = self.store.contacts().await?;
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
                self.status = if sender_is_self {
                    format!(
                        "另一台设备已向 {} 发出会话请求；通知 Tab 可查看进度",
                        payload.text
                    )
                } else {
                    format!(
                        "收到来自 {} 的会话请求；通知 Tab 中按 Enter 接受",
                        stored.sender_username
                    )
                };
                continue;
            }
            if payload.kind == "chat_response" {
                let Some(request_id) = payload.related_message_id.as_deref() else {
                    bail!("会话响应缺少请求 ID");
                };
                let peer_matches = if sender_is_self {
                    payload.peer_account_id != self.profile.account_id
                } else {
                    payload.peer_account_id == self.profile.account_id
                };
                if !peer_matches || !matches!(payload.text.as_str(), "accepted" | "rejected") {
                    bail!("会话响应元数据无效");
                }
                if let Some(notification) = self
                    .store
                    .notification_by_request_id(&self.vault, request_id)
                    .await?
                {
                    if !chat_response_actor_matches(
                        sender_is_self,
                        &notification.actor_account_id,
                        &payload.peer_account_id,
                        &stored.sender_account_id,
                    ) {
                        bail!("会话响应对象与原请求不匹配");
                    }
                    let state = chat_decision_state(&payload.text)?;
                    self.save_chat_response_notification(
                        &notification,
                        state == NotificationState::Accepted,
                        true,
                    )
                    .await?;
                    self.status = if payload.text == "accepted" {
                        self.selected = self.contacts.iter().position(|contact| {
                            contact.bundle.account_id == notification.actor_account_id
                        });
                        format!(
                            "{} 已接受会话请求；在通知详情比较安全码后点击“已核对，认证”",
                            notification.actor_username
                        )
                    } else {
                        format!("{} 拒绝了会话请求", notification.actor_username)
                    };
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
        self.lookup_bundle_fresh(username).await
    }

    async fn lookup_bundle_fresh(&mut self, username: &str) -> Result<UserBundle> {
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

    async fn send_chat_request(&mut self, recipient: &UserBundle) -> Result<()> {
        if self.notifications.iter().any(|notification| {
            notification.kind == NotificationKind::ChatRequest
                && notification.actor_account_id == recipient.account_id
                && matches!(
                    notification.state,
                    NotificationState::Pending | NotificationState::InProgress
                )
        }) {
            self.status = format!("已向 {} 发出会话请求，等待对方确认", recipient.username);
            return Ok(());
        }
        validate_bundle(recipient)?;
        let username = self.profile.username.clone();
        let self_bundle = self.lookup_bundle_fresh(&username).await?;
        validate_bundle(&self_bundle)?;
        if self_bundle.account_master_key
            != self
                .profile
                .identity
                .master_public_key()
                .unwrap_or_default()
        {
            bail!("服务器返回的本账号主密钥不匹配");
        }
        let request_id = Uuid::now_v7().to_string();
        let sent_at_ms = now_ms();
        let payload = serde_json::to_vec(&WirePayload {
            version: 3,
            kind: "chat_request".into(),
            message_id: request_id.clone(),
            sender_username: self.profile.username.clone(),
            sender_account_id: self.profile.account_id.clone(),
            peer_account_id: recipient.account_id.clone(),
            sent_at_ms,
            text: String::new(),
            related_message_id: None,
            related_message_ids: vec![],
        })?;
        let conversation = conversation_id(&self.profile.account_id, &recipient.account_id);
        let mut next_machine = OlmMachine::from_bytes(&self.profile.machine.to_bytes()?)?;
        let mut envelopes = Vec::new();
        for device in recipient.devices.iter().filter(|device| !device.revoked) {
            verify_device_bundle(&recipient.account_master_key, &recipient.account_id, device)?;
            let encrypted = self
                .encrypt_for(&mut next_machine, device, &recipient.account_id, &payload)
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: request_id.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: recipient.account_id.clone(),
                recipient_device_id: device.device_id.clone(),
                ciphertext: encrypted.ciphertext,
                olm_message_type: encrypted.message_type,
                client_sent_at_ms: sent_at_ms,
            });
        }
        if envelopes.is_empty() {
            bail!("联系人没有可用设备");
        }
        let self_payload = serde_json::to_vec(&WirePayload {
            version: 3,
            kind: "chat_request".into(),
            message_id: request_id.clone(),
            sender_username: self.profile.username.clone(),
            sender_account_id: self.profile.account_id.clone(),
            peer_account_id: recipient.account_id.clone(),
            sent_at_ms,
            text: recipient.username.clone(),
            related_message_id: None,
            related_message_ids: vec![],
        })?;
        for device in self_bundle.devices.iter().filter(|device| {
            !device.revoked && device.device_id != self.profile.identity.device_id()
        }) {
            verify_device_bundle(
                &self_bundle.account_master_key,
                &self_bundle.account_id,
                device,
            )?;
            let encrypted = self
                .encrypt_for(
                    &mut next_machine,
                    device,
                    &self_bundle.account_id,
                    &self_payload,
                )
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: request_id.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: self_bundle.account_id.clone(),
                recipient_device_id: device.device_id.clone(),
                ciphertext: encrypted.ciphertext,
                olm_message_type: encrypted.message_type,
                client_sent_at_ms: sent_at_ms,
            });
        }
        let sender_device_id = self.profile.identity.device_id().to_owned();
        self.save_outgoing_chat_request_notification(
            &request_id,
            recipient,
            &sender_device_id,
            true,
        )
        .await?;
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
                &request_id,
                &encode_frame(&queued_frame),
            )
            .await;
        if let Err(error) = committed {
            self.profile.machine = previous_machine;
            return Err(error);
        }
        if self.rpc.request_frame(queued_frame).await.is_ok() {
            self.store.remove_outbox(&request_id).await?;
        }
        self.status = format!("已向 {} 发出会话请求，等待对方确认", recipient.username);
        Ok(())
    }

    async fn send_chat_decision(
        &mut self,
        recipient: &UserBundle,
        request_id: &str,
        accepted: bool,
    ) -> Result<()> {
        validate_bundle(recipient)?;
        let username = self.profile.username.clone();
        let self_bundle = self.lookup_bundle_fresh(&username).await?;
        validate_bundle(&self_bundle)?;
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
        let sent_at_ms = now_ms();
        let payload = serde_json::to_vec(&WirePayload {
            version: 3,
            kind: "chat_response".into(),
            message_id: logical_id.clone(),
            sender_username: self.profile.username.clone(),
            sender_account_id: self.profile.account_id.clone(),
            peer_account_id: recipient.account_id.clone(),
            sent_at_ms,
            text: if accepted { "accepted" } else { "rejected" }.to_owned(),
            related_message_id: Some(request_id.to_owned()),
            related_message_ids: vec![],
        })?;
        let conversation = conversation_id(&self.profile.account_id, &recipient.account_id);
        let mut next_machine = OlmMachine::from_bytes(&self.profile.machine.to_bytes()?)?;
        let mut envelopes = Vec::new();
        for device in recipient.devices.iter().filter(|device| !device.revoked) {
            verify_device_bundle(&recipient.account_master_key, &recipient.account_id, device)?;
            let encrypted = self
                .encrypt_for(&mut next_machine, device, &recipient.account_id, &payload)
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: logical_id.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: recipient.account_id.clone(),
                recipient_device_id: device.device_id.clone(),
                ciphertext: encrypted.ciphertext,
                olm_message_type: encrypted.message_type,
                client_sent_at_ms: sent_at_ms,
            });
        }
        if envelopes.is_empty() {
            bail!("请求方没有可用设备");
        }
        for device in self_bundle.devices.iter().filter(|device| {
            !device.revoked && device.device_id != self.profile.identity.device_id()
        }) {
            verify_device_bundle(
                &self_bundle.account_master_key,
                &self_bundle.account_id,
                device,
            )?;
            let encrypted = self
                .encrypt_for(&mut next_machine, device, &self_bundle.account_id, &payload)
                .await?;
            envelopes.push(EncryptedEnvelope {
                envelope_id: Uuid::now_v7().to_string(),
                logical_message_id: logical_id.clone(),
                conversation_id: conversation.clone(),
                recipient_account_id: self_bundle.account_id.clone(),
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
                &logical_id,
                &encode_frame(&queued_frame),
            )
            .await;
        if let Err(error) = committed {
            self.profile.machine = previous_machine;
            return Err(error);
        }
        if self.rpc.request_frame(queued_frame).await.is_ok() {
            self.store.remove_outbox(&logical_id).await?;
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

fn matching_emojis(query: &str) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    EMOJI_CATALOG
        .iter()
        .enumerate()
        .filter(|(_, emoji)| {
            query.is_empty()
                || emoji.name.to_lowercase().contains(&query)
                || emoji.keywords.to_lowercase().contains(&query)
                || emoji.glyph.contains(&query)
        })
        .map(|(index, _)| index)
        .collect()
}

fn notification_requires_action(state: NotificationState) -> bool {
    matches!(
        state,
        NotificationState::Pending | NotificationState::InProgress
    )
}

fn chat_decision_state(decision: &str) -> Result<NotificationState> {
    match decision {
        "accepted" => Ok(NotificationState::Accepted),
        "rejected" => Ok(NotificationState::Rejected),
        _ => bail!("未知的会话请求处理结果"),
    }
}

fn chat_response_actor_matches(
    sender_is_self: bool,
    notification_actor_account_id: &str,
    payload_peer_account_id: &str,
    sender_account_id: &str,
) -> bool {
    if sender_is_self {
        notification_actor_account_id == payload_peer_account_id
    } else {
        notification_actor_account_id == sender_account_id
    }
}

fn should_offer_contact_verification(
    kind: NotificationKind,
    state: NotificationState,
    contact_verified: bool,
    identity_changed: bool,
) -> bool {
    kind == NotificationKind::ChatResponse
        && state == NotificationState::Accepted
        && (!contact_verified || identity_changed)
}

fn composer_title(username: &str, available_width: u16) -> (String, u16, u16) {
    let detailed_prefix = format!("输入 · @{username} · Enter 发送 · ");
    let compact_prefix = format!("@{username} · Enter 发送 · ");
    let send_prefix = "Enter 发送 · ";
    let short_prefix = "发送 · ";
    let full_button = "[😊 表情]";
    let compact_button = "[😊]";
    let suffix = " · Shift-Enter 换行";
    let available_width = usize::from(available_width);

    let choices = [
        (detailed_prefix.as_str(), full_button, suffix),
        (detailed_prefix.as_str(), full_button, ""),
        (compact_prefix.as_str(), full_button, ""),
        (send_prefix, full_button, ""),
        (send_prefix, compact_button, ""),
        (short_prefix, compact_button, ""),
    ];
    let (prefix, button, suffix) = choices
        .into_iter()
        .find(|(prefix, button, suffix)| {
            UnicodeWidthStr::width(*prefix)
                + UnicodeWidthStr::width(*button)
                + UnicodeWidthStr::width(*suffix)
                <= available_width
        })
        .unwrap_or(("", compact_button, ""));
    let offset = UnicodeWidthStr::width(prefix) as u16;
    let button_width = UnicodeWidthStr::width(button) as u16;
    (format!("{prefix}{button}{suffix}"), offset, button_width)
}

fn emoji_grid_layout(area: Rect) -> (Rect, usize, u16) {
    let grid = Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(2),
        area.width.saturating_sub(2),
        area.height.saturating_sub(3),
    );
    let columns = usize::from((grid.width / 13).max(1));
    let cell_width = grid.width / columns as u16;
    (grid, columns, cell_width.max(1))
}

fn fit_to_display_width(text: &str, width: usize) -> String {
    let mut output = String::new();
    let mut used = 0;
    for grapheme in text.graphemes(true) {
        let grapheme_width = UnicodeWidthStr::width(grapheme).max(1);
        if used + grapheme_width > width {
            break;
        }
        output.push_str(grapheme);
        used += grapheme_width;
    }
    output.extend(std::iter::repeat_n(' ', width.saturating_sub(used)));
    output
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

fn render_action_button(frame: &mut ratatui::Frame<'_>, area: Rect, label: &str, color: Color) {
    if area.area() == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(format!("[ {label} ]")).style(
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        ),
        area,
    );
}

fn render_choice_button(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    label: &str,
    color: Color,
    selected: bool,
) {
    if area.area() == 0 {
        return;
    }
    let style = if selected {
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    };
    frame.render_widget(Paragraph::new(format!("[ {label} ]")).style(style), area);
}

fn sidebar_tab_areas(area: Rect, notification_label: &str) -> (Rect, Rect) {
    let conversation_width = UnicodeWidthStr::width("[会话]") as u16;
    let conversation = Rect::new(area.x, area.y, conversation_width.min(area.width), 1);
    let notification_x = area.x.saturating_add(conversation_width).saturating_add(2);
    let notification_width =
        UnicodeWidthStr::width(format!("[{notification_label}]").as_str()) as u16;
    let notification = Rect::new(
        notification_x,
        area.y,
        notification_width.min(area.right().saturating_sub(notification_x)),
        1,
    );
    (conversation, notification)
}

fn list_delete_button_areas(
    sidebar_body: Rect,
    first_contact: usize,
    contact_count: usize,
    visible_height: usize,
) -> Vec<(usize, Rect)> {
    (first_contact..contact_count)
        .take(visible_height)
        .enumerate()
        .map(|(visible_index, contact_index)| {
            (
                contact_index,
                Rect::new(
                    sidebar_body.right().saturating_sub(2),
                    sidebar_body
                        .y
                        .saturating_add(1)
                        .saturating_add(visible_index as u16),
                    1,
                    1,
                ),
            )
        })
        .collect()
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
    matches!(payload.version, 1..=3)
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
    fn emoji_button_stays_on_the_composer_title_at_narrow_widths() {
        let (wide, wide_offset, wide_button_width) = composer_title("alice", 80);
        assert!(wide.contains("Enter 发送 · [😊 表情]"));
        assert!(wide.contains("Shift-Enter 换行"));
        assert!(usize::from(wide_offset + wide_button_width) <= 80);

        let (narrow, narrow_offset, narrow_button_width) =
            composer_title("a-very-long-username", 20);
        assert!(narrow.contains("[😊"));
        assert!(UnicodeWidthStr::width(narrow.as_str()) <= 20);
        assert!(usize::from(narrow_offset + narrow_button_width) <= 20);
    }

    #[test]
    fn notification_tab_hit_area_matches_the_rendered_label() {
        let (conversation, notification) = sidebar_tab_areas(Rect::new(3, 2, 30, 1), "通知 · 2");
        assert!(conversation.contains(Position::new(3, 2)));
        assert!(!conversation.contains(Position::new(notification.x, 2)));
        assert!(notification.contains(Position::new(notification.x, 2)));
        assert!(notification.width >= UnicodeWidthStr::width("[通知 · 2]") as u16);
    }

    #[test]
    fn list_delete_buttons_match_visible_rows() {
        let body = Rect::new(4, 3, 24, 8);
        let buttons = list_delete_button_areas(body, 2, 10, 4);
        assert_eq!(buttons.len(), 4);
        assert_eq!(buttons[0].0, 2);
        assert_eq!(buttons[0].1, Rect::new(body.right() - 2, body.y + 1, 1, 1));
        assert_eq!(buttons[3].0, 5);
        assert_eq!(buttons[3].1.y, body.y + 4);
    }

    #[test]
    fn rendered_dynamic_text_cannot_contain_escape_sequences() {
        assert_eq!(sanitize_terminal_text("hello"), "hello");
        assert_eq!(sanitize_terminal_text("hello\x1b[31m"), "hello�[31m");
    }

    #[test]
    fn emoji_catalog_supports_chinese_english_and_unicode_search() {
        for query in ["火箭", "rocket", "🚀"] {
            let matches = matching_emojis(query);
            assert_eq!(EMOJI_CATALOG[matches[0]].glyph, "🚀");
        }
        assert!(matching_emojis("不存在的表情关键词").is_empty());
    }

    #[test]
    fn emoji_picker_uses_a_dense_grid_and_unicode_width_padding() {
        let area = Rect::new(4, 2, 68, 14);
        let (grid, columns, cell_width) = emoji_grid_layout(area);
        assert_eq!(grid.y, area.y + 2);
        assert!(columns >= 4);
        assert!(grid.height >= 2);

        let cell = fit_to_display_width("🧑‍💻 开发者", usize::from(cell_width));
        assert_eq!(
            UnicodeWidthStr::width(cell.as_str()),
            usize::from(cell_width)
        );
    }

    #[test]
    fn notification_badge_tracks_work_even_after_the_item_was_read() {
        assert!(notification_requires_action(NotificationState::Pending));
        assert!(notification_requires_action(NotificationState::InProgress));
        assert!(!notification_requires_action(NotificationState::Accepted));
        assert_eq!(
            chat_decision_state("accepted").expect("accepted is a valid decision"),
            NotificationState::Accepted
        );
        assert_eq!(
            chat_decision_state("rejected").expect("rejected is a valid decision"),
            NotificationState::Rejected
        );
        assert!(chat_decision_state("unknown").is_err());
        assert!(chat_response_actor_matches(
            false,
            "peer-account",
            "our-account",
            "peer-account"
        ));
        assert!(chat_response_actor_matches(
            true,
            "peer-account",
            "peer-account",
            "our-account"
        ));
        assert!(!chat_response_actor_matches(
            true,
            "different-account",
            "peer-account",
            "our-account"
        ));
        assert!(should_offer_contact_verification(
            NotificationKind::ChatResponse,
            NotificationState::Accepted,
            false,
            false
        ));
        assert!(should_offer_contact_verification(
            NotificationKind::ChatResponse,
            NotificationState::Accepted,
            true,
            true
        ));
        assert!(!should_offer_contact_verification(
            NotificationKind::ChatResponse,
            NotificationState::Accepted,
            true,
            false
        ));
        assert!(!should_offer_contact_verification(
            NotificationKind::ChatRequest,
            NotificationState::Pending,
            false,
            false
        ));
    }

    #[test]
    fn chat_control_payload_metadata_accepts_v3() {
        let payload = WirePayload {
            version: 3,
            kind: "chat_request".into(),
            message_id: "request-1".into(),
            sender_username: "alice".into(),
            sender_account_id: "account-a".into(),
            peer_account_id: "account-b".into(),
            sent_at_ms: 42,
            text: String::new(),
            related_message_id: None,
            related_message_ids: vec![],
        };
        assert!(wire_metadata_matches(
            &payload,
            "account-a",
            "alice",
            "request-1",
            42
        ));
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
