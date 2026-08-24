use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::ws::AppState;

const MAX_ADMIN_FRAME_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AdminRequest {
    Snapshot,
    KickSession { session_id: Uuid },
    KickAccount { account_id: String, reason: String },
    KickDevice { device_id: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub account_id: String,
    pub username: String,
    pub state: String,
    pub password_change_required: bool,
    pub active_devices: u64,
    pub pending_devices: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub session_id: Uuid,
    pub account_id: String,
    pub username: String,
    pub device_id: String,
    pub source_ip: String,
    pub connected_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConversation {
    pub conversation_id: String,
    pub first_username: String,
    pub second_username: String,
    pub logical_messages: u64,
    pub envelopes: u64,
    pub ciphertext_bytes: u64,
    pub undelivered_envelopes: u64,
    pub oldest_at_ms: i64,
    pub newest_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
    pub id: u64,
    pub occurred_at_ms: i64,
    pub category: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub source_ip: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminSnapshot {
    pub users: Vec<AdminUser>,
    pub sessions: Vec<AdminSession>,
    pub conversations: Vec<AdminConversation>,
    pub audit: Vec<AdminAuditEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    pub message: String,
    pub snapshot: Option<AdminSnapshot>,
}

impl AdminResponse {
    fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            snapshot: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            snapshot: None,
        }
    }
}

#[cfg(unix)]
pub async fn serve(path: &Path, state: Arc<AppState>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    use tokio::net::UnixListener;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
    }
    if tokio::fs::try_exists(path).await? {
        tokio::fs::remove_file(path).await?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind admin socket {}", path.display()))?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_stream(stream, state).await {
                tracing::warn!(%error, "admin control request failed");
            }
        });
    }
}

#[cfg(unix)]
async fn handle_stream(stream: tokio::net::UnixStream, state: Arc<AppState>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).take(MAX_ADMIN_FRAME_BYTES + 1);
    let mut encoded = Vec::new();
    reader.read_until(b'\n', &mut encoded).await?;
    if encoded.len() as u64 > MAX_ADMIN_FRAME_BYTES {
        bail!("admin request is too large");
    }
    let request: AdminRequest = serde_json::from_slice(&encoded)?;
    let response = match dispatch(request, &state).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "admin action rejected");
            AdminResponse::error("admin action failed")
        }
    };
    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn dispatch(request: AdminRequest, state: &AppState) -> Result<AdminResponse> {
    match request {
        AdminRequest::Snapshot => Ok(AdminResponse {
            ok: true,
            message: "snapshot".to_owned(),
            snapshot: Some(snapshot(state).await?),
        }),
        AdminRequest::KickSession { session_id } => {
            if !state.kick_session(session_id, "admin_kick").await {
                bail!("session not found");
            }
            state
                .db
                .audit(
                    "admin",
                    "local-admin",
                    "kick_session",
                    &session_id.to_string(),
                    "success",
                    (None, ""),
                )
                .await?;
            Ok(AdminResponse::success("session kicked"))
        }
        AdminRequest::KickAccount { account_id, reason } => {
            let count = state.kick_account(&account_id, &reason).await;
            Ok(AdminResponse::success(format!("kicked {count} sessions")))
        }
        AdminRequest::KickDevice { device_id, reason } => {
            let kicked = state.kick_device(&device_id, &reason).await;
            Ok(AdminResponse::success(if kicked {
                "device session kicked"
            } else {
                "device was not online"
            }))
        }
    }
}

async fn snapshot(state: &AppState) -> Result<AdminSnapshot> {
    let users = sqlx::query(
        "SELECT a.id, a.username, a.state, a.require_password_change, \
         SUM(CASE WHEN d.pending = 0 AND d.revoked = 0 THEN 1 ELSE 0 END) active_devices, \
         SUM(CASE WHEN d.pending = 1 AND d.revoked = 0 THEN 1 ELSE 0 END) pending_devices \
         FROM accounts a LEFT JOIN devices d ON d.account_id = a.id \
         GROUP BY a.id ORDER BY a.username",
    )
    .fetch_all(state.db.pool())
    .await?
    .into_iter()
    .map(|row| AdminUser {
        account_id: row.get("id"),
        username: row.get("username"),
        state: row.get("state"),
        password_change_required: row.get::<i64, _>("require_password_change") != 0,
        active_devices: row.get::<i64, _>("active_devices") as u64,
        pending_devices: row.get::<i64, _>("pending_devices") as u64,
    })
    .collect();

    let sessions = state
        .live_sessions()
        .await
        .into_iter()
        .map(|session| AdminSession {
            session_id: session.id,
            account_id: session.account_id,
            username: session.username,
            device_id: session.device_id,
            source_ip: session.source_ip.to_string(),
            connected_at_ms: session.connected_at_ms,
            last_seen_at_ms: session.last_seen_at_ms,
            pending: session.pending,
        })
        .collect();

    let conversations = sqlx::query(
        "SELECT lm.conversation_id, \
         MIN(sa.username, pa.username) first_username, \
         MAX(sa.username, pa.username) second_username, \
         COUNT(DISTINCT lm.logical_message_id) logical_messages, \
         COUNT(e.envelope_id) envelopes, COALESCE(SUM(length(e.ciphertext)), 0) ciphertext_bytes, \
         SUM(CASE WHEN e.delivered_at_ms IS NULL THEN 1 ELSE 0 END) undelivered_envelopes, \
         MIN(lm.accepted_at_ms) oldest_at_ms, MAX(lm.accepted_at_ms) newest_at_ms \
         FROM logical_messages lm \
         JOIN accounts sa ON sa.id = lm.sender_account_id \
         JOIN accounts pa ON pa.id = lm.peer_account_id \
         LEFT JOIN envelopes e ON e.logical_message_id = lm.logical_message_id \
         GROUP BY lm.conversation_id ORDER BY newest_at_ms DESC",
    )
    .fetch_all(state.db.pool())
    .await?
    .into_iter()
    .map(|row| AdminConversation {
        conversation_id: row.get("conversation_id"),
        first_username: row.get("first_username"),
        second_username: row.get("second_username"),
        logical_messages: row.get::<i64, _>("logical_messages") as u64,
        envelopes: row.get::<i64, _>("envelopes") as u64,
        ciphertext_bytes: row.get::<i64, _>("ciphertext_bytes") as u64,
        undelivered_envelopes: row.get::<i64, _>("undelivered_envelopes") as u64,
        oldest_at_ms: row.get("oldest_at_ms"),
        newest_at_ms: row.get("newest_at_ms"),
    })
    .collect();

    let audit = sqlx::query(
        "SELECT id, occurred_at_ms, category, actor, action, target, result, source_ip, details \
         FROM audit_events ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(state.db.pool())
    .await?
    .into_iter()
    .map(|row| AdminAuditEvent {
        id: row.get::<i64, _>("id") as u64,
        occurred_at_ms: row.get("occurred_at_ms"),
        category: row.get("category"),
        actor: row.get("actor"),
        action: row.get("action"),
        target: row.get("target"),
        result: row.get("result"),
        source_ip: row.get("source_ip"),
        details: row.get("details"),
    })
    .collect();

    Ok(AdminSnapshot {
        users,
        sessions,
        conversations,
        audit,
    })
}

#[cfg(unix)]
pub async fn request(path: &Path, request: &AdminRequest) -> Result<AdminResponse> {
    use tokio::net::UnixStream;

    let mut stream = tokio::time::timeout(Duration::from_secs(3), UnixStream::connect(path))
        .await
        .context("admin socket connection timed out")??;
    let mut encoded = serde_json::to_vec(request)?;
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    let mut reader = BufReader::new(stream).take(MAX_ADMIN_FRAME_BYTES + 1);
    let mut response = Vec::new();
    reader.read_until(b'\n', &mut response).await?;
    if response.len() as u64 > MAX_ADMIN_FRAME_BYTES {
        bail!("admin response is too large");
    }
    serde_json::from_slice(&response).map_err(Into::into)
}

#[cfg(not(unix))]
pub async fn serve(_path: &Path, _state: Arc<AppState>) -> Result<()> {
    Err(anyhow::anyhow!("the local admin socket requires Unix"))
}

#[cfg(not(unix))]
pub async fn request(_path: &Path, _request: &AdminRequest) -> Result<AdminResponse> {
    Err(anyhow::anyhow!("the local admin socket requires Unix"))
}

use std::time::Duration;
