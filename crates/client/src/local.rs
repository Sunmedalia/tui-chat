use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tui_chat_crypto::{
    DeviceIdentity, EncryptedBlob, OlmMachine, VaultKey, WrappedVaultKey, decrypt_blob,
};
use tui_chat_protocol::v1::UserBundle;
use zeroize::Zeroizing;

pub const MESSAGE_PAGE_SIZE: usize = 100;

#[derive(Clone)]
pub struct LocalStore {
    pool: SqlitePool,
    path: PathBuf,
}

#[derive(Clone)]
pub struct VaultSession {
    key: VaultKey,
    legacy_passphrase: Option<Arc<Zeroizing<String>>>,
}

impl VaultSession {
    fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob> {
        self.key.encrypt(aad, plaintext)
    }

    fn decrypt(&self, aad: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>> {
        match blob.version {
            2 => self.key.decrypt(aad, blob),
            1 => self
                .legacy_passphrase
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("legacy local data requires migration"))
                .and_then(|passphrase| decrypt_blob(passphrase, aad, blob)),
            version => anyhow::bail!("unsupported local encryption version {version}"),
        }
    }
}

pub struct RuntimeProfile {
    pub username: String,
    pub account_id: String,
    pub server_url: String,
    pub identity: DeviceIdentity,
    pub machine: OlmMachine,
    pub pending: bool,
    pub pairing_secret: Option<[u8; 32]>,
    pub account_master_public: Vec<u8>,
    pub spki_pin: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredProfile {
    username: String,
    account_id: String,
    server_url: String,
    identity: Vec<u8>,
    machine: Vec<u8>,
    pending: bool,
    pairing_secret: Option<[u8; 32]>,
    account_master_public: Vec<u8>,
    spki_pin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub bundle: UserBundle,
    pub verified: bool,
    pub identity_changed: bool,
    pub unread_count: u64,
    pub last_activity_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub peer_account_id: String,
    pub sender_account_id: String,
    pub body: String,
    pub sent_at_ms: i64,
    pub status: MessageStatus,
    pub inbound: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    #[serde(rename = "sending", alias = "发送中")]
    Sending,
    #[serde(rename = "sent", alias = "已发送")]
    Sent,
    #[serde(rename = "delivered", alias = "已送达")]
    Delivered,
    #[serde(rename = "read", alias = "已读")]
    Read,
}

impl MessageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Read => "read",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Sending => "发送中",
            Self::Sent => "已发送",
            Self::Delivered => "已送达",
            Self::Read => "已读",
        }
    }

    pub const fn rank(self) -> u8 {
        self as u8
    }
}

impl TryFrom<&str> for MessageStatus {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "sending" | "发送中" => Ok(Self::Sending),
            "sent" | "已发送" => Ok(Self::Sent),
            "delivered" | "已送达" => Ok(Self::Delivered),
            "read" | "已读" => Ok(Self::Read),
            _ => anyhow::bail!("unknown message status"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferContact {
    pub bundle: Vec<u8>,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationKind {
    Pairing,
    ChatRequest,
    ChatResponse,
}

impl NotificationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::ChatRequest => "chat_request",
            Self::ChatResponse => "chat_response",
        }
    }
}

impl TryFrom<&str> for NotificationKind {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "pairing" => Ok(Self::Pairing),
            "chat_request" => Ok(Self::ChatRequest),
            "chat_response" => Ok(Self::ChatResponse),
            _ => anyhow::bail!("unknown notification kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationState {
    Pending,
    InProgress,
    Accepted,
    Rejected,
    Completed,
    Failed,
}

impl NotificationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl TryFrom<&str> for NotificationState {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "in_progress" => Ok(Self::InProgress),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => anyhow::bail!("unknown notification state"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationData {
    Pairing {
        pairing_id: String,
        pending_device_id: String,
        pending_device_name: String,
        sas_public_key: Vec<u8>,
        pending_device: Vec<u8>,
    },
    ChatRequest {
        #[serde(default)]
        outgoing: bool,
        request_id: String,
        sender_account_id: String,
        sender_username: String,
        sender_device_id: String,
        sender_bundle: Vec<u8>,
    },
    ChatResponse {
        request_id: String,
        accepted: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub id: String,
    pub kind: NotificationKind,
    pub request_id: String,
    pub actor_account_id: String,
    pub actor_username: String,
    pub actor_device_id: String,
    pub state: NotificationState,
    pub read: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub data: NotificationData,
}

impl LocalStore {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self {
            pool,
            path: path.to_path_buf(),
        })
    }

    pub async fn unlock(&self, passphrase: &str) -> Result<VaultSession> {
        let existing =
            sqlx::query_scalar::<_, Vec<u8>>("SELECT wrapped_key FROM vault WHERE singleton = 1")
                .fetch_optional(&self.pool)
                .await?;
        if let Some(encoded) = existing {
            let wrapped = WrappedVaultKey::from_bytes(&encoded)?;
            let key = VaultKey::unlock(passphrase, &wrapped)?;
            let legacy_count: i64 = sqlx::query_scalar(
                "SELECT (SELECT COUNT(*) FROM profile WHERE encryption_version = 1) + (SELECT COUNT(*) FROM messages WHERE encryption_version = 1)",
            )
            .fetch_one(&self.pool)
            .await?;
            return Ok(VaultSession {
                key,
                legacy_passphrase: (legacy_count > 0)
                    .then(|| Arc::new(Zeroizing::new(passphrase.to_owned()))),
            });
        }

        let legacy_profile = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT encrypted_blob FROM profile WHERE singleton = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let profile_plain = if let Some(encoded) = legacy_profile.as_ref() {
            let blob = decode_encrypted_blob(encoded)?;
            Some(decrypt_blob(passphrase, b"profile/v1", &blob)?)
        } else {
            None
        };
        if legacy_profile.is_some() {
            self.backup_before_vault_migration().await?;
        }
        let (key, wrapped) = VaultKey::create(passphrase)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO vault(singleton, wrapped_key, created_at_ms) VALUES(1, ?, ?)")
            .bind(wrapped.to_bytes())
            .bind(now_ms())
            .execute(&mut *tx)
            .await?;
        if let Some(plain) = profile_plain {
            let blob = key.encrypt(b"profile/v1", &plain)?;
            sqlx::query("UPDATE profile SET encrypted_blob = ?, encryption_version = 2, updated_at_ms = ? WHERE singleton = 1")
                .bind(blob.to_bytes())
                .bind(now_ms())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        let legacy_messages: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE encryption_version = 1")
                .fetch_one(&self.pool)
                .await?;
        Ok(VaultSession {
            key,
            legacy_passphrase: (legacy_messages > 0)
                .then(|| Arc::new(Zeroizing::new(passphrase.to_owned()))),
        })
    }

    async fn backup_before_vault_migration(&self) -> Result<()> {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("client.db");
        let backup = self
            .path
            .with_file_name(format!("{name}.pre-v2-{timestamp}.bak"));
        let escaped = backup.to_string_lossy().replace('\'', "''");
        sqlx::query(&format!("VACUUM INTO '{escaped}'"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn migrate_legacy_messages(&self, vault: &VaultSession) -> Result<usize> {
        let rows = sqlx::query("SELECT logical_message_id, encrypted_body FROM messages WHERE encryption_version = 1 ORDER BY sent_at_ms")
            .fetch_all(&self.pool)
            .await?;
        let mut migrated = 0;
        for row in rows {
            let id: String = row.get("logical_message_id");
            let blob = decode_encrypted_blob(&row.get::<Vec<u8>, _>("encrypted_body"))?;
            let aad = format!("message/v1/{id}");
            let legacy_aad = aad.clone();
            let session = vault.clone();
            let plaintext =
                tokio::task::spawn_blocking(move || session.decrypt(legacy_aad.as_bytes(), &blob))
                    .await??;
            let encoded = vault.encrypt(aad.as_bytes(), &plaintext)?.to_bytes();
            sqlx::query("UPDATE messages SET encrypted_body = ?, encryption_version = 2 WHERE logical_message_id = ? AND encryption_version = 1")
                .bind(encoded)
                .bind(id)
                .execute(&self.pool)
                .await?;
            migrated += 1;
            tokio::task::yield_now().await;
        }
        Ok(migrated)
    }

    pub async fn has_profile(&self) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM profile")
            .fetch_one(&self.pool)
            .await?
            > 0)
    }

    pub async fn has_vault(&self) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM vault")
            .fetch_one(&self.pool)
            .await?
            > 0)
    }

    pub async fn load_profile(&self, vault: &VaultSession) -> Result<Option<RuntimeProfile>> {
        let row = sqlx::query("SELECT encrypted_blob FROM profile WHERE singleton = 1")
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let blob = decode_encrypted_blob(&row.get::<Vec<u8>, _>("encrypted_blob"))?;
        let decrypted = vault.decrypt(b"profile/v1", &blob)?;
        let plain: StoredProfile = if let Some(encoded) = decrypted.strip_prefix(b"TCP3") {
            postcard::from_bytes(encoded)?
        } else {
            serde_json::from_slice(&decrypted)?
        };
        Ok(Some(RuntimeProfile {
            username: plain.username,
            account_id: plain.account_id,
            server_url: plain.server_url,
            identity: DeviceIdentity::from_bytes(&plain.identity)?,
            machine: OlmMachine::from_bytes(&plain.machine)?,
            pending: plain.pending,
            pairing_secret: plain.pairing_secret,
            account_master_public: plain.account_master_public,
            spki_pin: plain.spki_pin,
        }))
    }

    pub async fn save_profile(&self, vault: &VaultSession, profile: &RuntimeProfile) -> Result<()> {
        let blob = encode_profile(vault, profile)?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(blob).bind(now_ms()).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn commit_outgoing(
        &self,
        vault: &VaultSession,
        profile: &RuntimeProfile,
        message: &ChatMessage,
        encoded_frame: &[u8],
    ) -> Result<()> {
        let profile_blob = encode_profile(vault, profile)?;
        let body = encode_message(vault, message)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(profile_blob).bind(now_ms()).execute(&mut *tx).await?;
        sqlx::query("INSERT OR IGNORE INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound, encryption_version) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 2)")
            .bind(&message.id).bind(&message.conversation_id).bind(&message.peer_account_id).bind(&message.sender_account_id)
            .bind(body).bind(message.sent_at_ms).bind(message.status.as_str()).bind(i64::from(message.inbound)).execute(&mut *tx).await?;
        sqlx::query("INSERT OR REPLACE INTO outbox(logical_message_id, encoded_frame, created_at_ms) VALUES(?, ?, ?)")
            .bind(&message.id).bind(encoded_frame).bind(now_ms()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_control_outgoing(
        &self,
        vault: &VaultSession,
        profile: &RuntimeProfile,
        logical_message_id: &str,
        encoded_frame: &[u8],
    ) -> Result<()> {
        let profile_blob = encode_profile(vault, profile)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(profile_blob).bind(now_ms()).execute(&mut *tx).await?;
        sqlx::query("INSERT OR REPLACE INTO outbox(logical_message_id, encoded_frame, created_at_ms) VALUES(?, ?, ?)")
            .bind(logical_message_id).bind(encoded_frame).bind(now_ms()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_inbound(
        &self,
        vault: &VaultSession,
        profile: &RuntimeProfile,
        message: &ChatMessage,
        cursor: u64,
    ) -> Result<()> {
        let profile_blob = encode_profile(vault, profile)?;
        let body = encode_message(vault, message)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(profile_blob).bind(now_ms()).execute(&mut *tx).await?;
        sqlx::query("INSERT OR IGNORE INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound, encryption_version) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 2)")
            .bind(&message.id).bind(&message.conversation_id).bind(&message.peer_account_id).bind(&message.sender_account_id)
            .bind(body).bind(message.sent_at_ms).bind(message.status.as_str()).bind(i64::from(message.inbound)).execute(&mut *tx).await?;
        sqlx::query("UPDATE sync_state SET envelope_cursor = ? WHERE singleton = 1")
            .bind(cursor as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_unverified_inbound(
        &self,
        vault: &VaultSession,
        profile: &RuntimeProfile,
        message: &ChatMessage,
        notification: &Notification,
        cursor: u64,
    ) -> Result<()> {
        let profile_blob = encode_profile(vault, profile)?;
        let body = encode_message(vault, message)?;
        let notification_payload = serde_json::to_vec(&notification.data)?;
        let notification_aad = format!("notification/v1/{}", notification.id);
        let encrypted_notification = vault
            .encrypt(notification_aad.as_bytes(), &notification_payload)?
            .to_bytes();
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(profile_blob).bind(now_ms()).execute(&mut *tx).await?;
        sqlx::query("INSERT OR IGNORE INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound, encryption_version) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 2)")
            .bind(&message.id).bind(&message.conversation_id).bind(&message.peer_account_id).bind(&message.sender_account_id)
            .bind(body).bind(message.sent_at_ms).bind(message.status.as_str()).bind(i64::from(message.inbound)).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO notifications(
                id, kind, request_id, actor_account_id, actor_username, actor_device_id,
                encrypted_payload, state, is_read, created_at_ms, updated_at_ms
             ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(request_id) DO UPDATE SET
                id=excluded.id,
                kind=excluded.kind,
                actor_account_id=excluded.actor_account_id,
                actor_username=excluded.actor_username,
                actor_device_id=excluded.actor_device_id,
                encrypted_payload=excluded.encrypted_payload,
                state=excluded.state,
                is_read=excluded.is_read,
                created_at_ms=excluded.created_at_ms,
                updated_at_ms=excluded.updated_at_ms",
        )
        .bind(&notification.id)
        .bind(notification.kind.as_str())
        .bind(&notification.request_id)
        .bind(&notification.actor_account_id)
        .bind(&notification.actor_username)
        .bind(&notification.actor_device_id)
        .bind(encrypted_notification)
        .bind(notification.state.as_str())
        .bind(i64::from(notification.read))
        .bind(notification.created_at_ms)
        .bind(notification.updated_at_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE sync_state SET envelope_cursor = ? WHERE singleton = 1")
            .bind(cursor as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_control(
        &self,
        vault: &VaultSession,
        profile: &RuntimeProfile,
        cursor: u64,
    ) -> Result<()> {
        let profile_blob = encode_profile(vault, profile)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO profile(singleton, encrypted_blob, updated_at_ms, encryption_version) VALUES(1, ?, ?, 2) ON CONFLICT(singleton) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at_ms=excluded.updated_at_ms, encryption_version=2")
            .bind(profile_blob).bind(now_ms()).execute(&mut *tx).await?;
        sqlx::query("UPDATE sync_state SET envelope_cursor = ? WHERE singleton = 1")
            .bind(cursor as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn upsert_contact(&self, bundle: &UserBundle) -> Result<Contact> {
        let old = self.contact_by_username(&bundle.username).await?;
        let identity_changed = old
            .as_ref()
            .is_some_and(|old| old.bundle.account_master_key != bundle.account_master_key);
        let verified = old.as_ref().is_some_and(|old| old.verified) && !identity_changed;
        sqlx::query("INSERT INTO contacts(account_id, username, bundle, verified, identity_changed, updated_at_ms) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET username=excluded.username, bundle=excluded.bundle, verified=excluded.verified, identity_changed=excluded.identity_changed, updated_at_ms=excluded.updated_at_ms")
            .bind(&bundle.account_id).bind(&bundle.username).bind(bundle.encode_to_vec()).bind(i64::from(verified))
            .bind(i64::from(identity_changed)).bind(now_ms()).execute(&self.pool).await?;
        self.contact_by_username(&bundle.username)
            .await?
            .ok_or_else(|| anyhow::anyhow!("contact disappeared after upsert"))
    }

    pub async fn contact_by_username(&self, username: &str) -> Result<Option<Contact>> {
        let row = sqlx::query("SELECT c.bundle, c.verified, c.identity_changed, COALESCE(s.last_activity_ms, 0) AS last_activity_ms, COALESCE(s.unread_count, 0) AS unread_count FROM contacts c LEFT JOIN conversation_summaries s ON s.peer_account_id = c.account_id WHERE c.username = ? COLLATE NOCASE")
            .bind(username).fetch_optional(&self.pool).await?;
        row.map(contact_from_row).transpose()
    }

    pub async fn contacts(&self) -> Result<Vec<Contact>> {
        let rows = sqlx::query(
            "SELECT c.bundle, c.verified, c.identity_changed, COALESCE(s.last_activity_ms, 0) AS last_activity_ms, COALESCE(s.unread_count, 0) AS unread_count FROM contacts c LEFT JOIN conversation_summaries s ON s.peer_account_id = c.account_id ORDER BY last_activity_ms DESC, c.username",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(contact_from_row).collect()
    }

    pub async fn delete_conversation(
        &self,
        peer_account_id: &str,
        conversation_id: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM outbox WHERE logical_message_id IN (
                SELECT logical_message_id FROM messages WHERE conversation_id = ?
             )",
        )
        .bind(conversation_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM messages WHERE conversation_id = ?")
            .bind(conversation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM drafts WHERE conversation_id = ?")
            .bind(conversation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM conversation_summaries WHERE conversation_id = ?")
            .bind(conversation_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM notifications
             WHERE actor_account_id = ? AND kind IN ('chat_request', 'chat_response')",
        )
        .bind(peer_account_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM contacts WHERE account_id = ?")
            .bind(peer_account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn export_contacts(&self) -> Result<Vec<TransferContact>> {
        let rows = sqlx::query("SELECT bundle, verified FROM contacts ORDER BY username")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| TransferContact {
                bundle: row.get("bundle"),
                verified: row.get::<i64, _>("verified") != 0,
            })
            .collect())
    }

    pub async fn import_contacts(&self, contacts: &[TransferContact]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for contact in contacts {
            let bundle = UserBundle::decode(contact.bundle.as_slice())?;
            sqlx::query("INSERT INTO contacts(account_id, username, bundle, verified, identity_changed, updated_at_ms) VALUES(?, ?, ?, ?, 0, ?) ON CONFLICT(account_id) DO UPDATE SET username=excluded.username, bundle=excluded.bundle, verified=excluded.verified, identity_changed=0, updated_at_ms=excluded.updated_at_ms")
                .bind(&bundle.account_id).bind(&bundle.username).bind(&contact.bundle).bind(i64::from(contact.verified)).bind(now_ms()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn export_messages(&self, vault: &VaultSession) -> Result<Vec<ChatMessage>> {
        let rows = sqlx::query("SELECT logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound FROM messages ORDER BY sent_at_ms")
            .fetch_all(&self.pool).await?;
        let mut messages = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("logical_message_id");
            let blob = decode_encrypted_blob(&row.get::<Vec<u8>, _>("encrypted_body"))?;
            messages.push(ChatMessage {
                id: id.clone(),
                conversation_id: row.get("conversation_id"),
                peer_account_id: row.get("peer_account_id"),
                sender_account_id: row.get("sender_account_id"),
                body: String::from_utf8(
                    vault.decrypt(format!("message/v1/{id}").as_bytes(), &blob)?,
                )?,
                sent_at_ms: row.get("sent_at_ms"),
                status: MessageStatus::try_from(row.get::<String, _>("status").as_str())?,
                inbound: row.get::<i64, _>("inbound") != 0,
            });
        }
        Ok(messages)
    }

    pub async fn import_messages(
        &self,
        vault: &VaultSession,
        messages: &[ChatMessage],
    ) -> Result<()> {
        for message in messages {
            self.save_message(vault, message).await?;
        }
        Ok(())
    }

    pub async fn verify_contact(&self, account_id: &str) -> Result<()> {
        sqlx::query("UPDATE contacts SET verified = 1, identity_changed = 0 WHERE account_id = ?")
            .bind(account_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn save_message(&self, vault: &VaultSession, message: &ChatMessage) -> Result<()> {
        let body = encode_message(vault, message)?;
        sqlx::query("INSERT OR IGNORE INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound, encryption_version) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 2)")
            .bind(&message.id).bind(&message.conversation_id).bind(&message.peer_account_id).bind(&message.sender_account_id)
            .bind(body).bind(message.sent_at_ms).bind(message.status.as_str()).bind(i64::from(message.inbound)).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn messages(
        &self,
        vault: &VaultSession,
        conversation: &str,
    ) -> Result<Vec<ChatMessage>> {
        let rows = sqlx::query("SELECT * FROM (SELECT logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound FROM messages WHERE conversation_id = ? ORDER BY sent_at_ms DESC, logical_message_id DESC LIMIT ?) ORDER BY sent_at_ms, logical_message_id")
            .bind(conversation)
            .bind(MESSAGE_PAGE_SIZE as i64)
            .fetch_all(&self.pool)
            .await?;
        Self::decode_messages(vault, rows)
    }

    pub async fn messages_before(
        &self,
        vault: &VaultSession,
        conversation: &str,
        sent_at_ms: i64,
        logical_message_id: &str,
    ) -> Result<Vec<ChatMessage>> {
        let rows = sqlx::query("SELECT * FROM (SELECT logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound FROM messages WHERE conversation_id = ? AND (sent_at_ms < ? OR (sent_at_ms = ? AND logical_message_id < ?)) ORDER BY sent_at_ms DESC, logical_message_id DESC LIMIT ?) ORDER BY sent_at_ms, logical_message_id")
            .bind(conversation)
            .bind(sent_at_ms)
            .bind(sent_at_ms)
            .bind(logical_message_id)
            .bind(MESSAGE_PAGE_SIZE as i64)
            .fetch_all(&self.pool)
            .await?;
        Self::decode_messages(vault, rows)
    }

    fn decode_messages(
        vault: &VaultSession,
        rows: Vec<sqlx::sqlite::SqliteRow>,
    ) -> Result<Vec<ChatMessage>> {
        let mut messages = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.get("logical_message_id");
            let blob = decode_encrypted_blob(&row.get::<Vec<u8>, _>("encrypted_body"))?;
            let body =
                String::from_utf8(vault.decrypt(format!("message/v1/{id}").as_bytes(), &blob)?)?;
            messages.push(ChatMessage {
                id,
                conversation_id: row.get("conversation_id"),
                peer_account_id: row.get("peer_account_id"),
                sender_account_id: row.get("sender_account_id"),
                body,
                sent_at_ms: row.get("sent_at_ms"),
                status: MessageStatus::try_from(row.get::<String, _>("status").as_str())?,
                inbound: row.get::<i64, _>("inbound") != 0,
            });
        }
        Ok(messages)
    }

    pub async fn save_draft(
        &self,
        vault: &VaultSession,
        conversation: &str,
        text: &str,
    ) -> Result<()> {
        if text.is_empty() {
            sqlx::query("DELETE FROM drafts WHERE conversation_id = ?")
                .bind(conversation)
                .execute(&self.pool)
                .await?;
            return Ok(());
        }
        let aad = format!("draft/v2/{conversation}");
        let blob = vault.encrypt(aad.as_bytes(), text.as_bytes())?;
        sqlx::query("INSERT INTO drafts(conversation_id, encrypted_body, updated_at_ms) VALUES(?, ?, ?) ON CONFLICT(conversation_id) DO UPDATE SET encrypted_body=excluded.encrypted_body, updated_at_ms=excluded.updated_at_ms")
            .bind(conversation)
            .bind(blob.to_bytes())
            .bind(now_ms())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn load_draft(&self, vault: &VaultSession, conversation: &str) -> Result<String> {
        let encoded = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT encrypted_body FROM drafts WHERE conversation_id = ?",
        )
        .bind(conversation)
        .fetch_optional(&self.pool)
        .await?;
        let Some(encoded) = encoded else {
            return Ok(String::new());
        };
        let blob = decode_encrypted_blob(&encoded)?;
        let aad = format!("draft/v2/{conversation}");
        Ok(String::from_utf8(vault.decrypt(aad.as_bytes(), &blob)?)?)
    }

    pub async fn update_status(&self, logical_id: &str, status: MessageStatus) -> Result<()> {
        sqlx::query(
            "UPDATE messages SET status = ? WHERE logical_message_id = ? AND \
             CASE status WHEN 'sending' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 WHEN 'read' THEN 3 ELSE 0 END < \
             CASE ? WHEN 'sending' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 WHEN 'read' THEN 3 ELSE 0 END",
        )
            .bind(status.as_str())
            .bind(logical_id)
            .bind(status.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_outbound_status_for_peer(
        &self,
        logical_id: &str,
        peer_account_id: &str,
        status: MessageStatus,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE messages SET status = ? WHERE logical_message_id = ? \
             AND peer_account_id = ? AND inbound = 0 AND \
             CASE status WHEN 'sending' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 WHEN 'read' THEN 3 ELSE 0 END < \
             CASE ? WHEN 'sending' THEN 0 WHEN 'sent' THEN 1 WHEN 'delivered' THEN 2 WHEN 'read' THEN 3 ELSE 0 END",
        )
        .bind(status.as_str())
        .bind(logical_id)
        .bind(peer_account_id)
        .bind(status.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn outbox(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let rows = sqlx::query(
            "SELECT logical_message_id, encoded_frame FROM outbox ORDER BY created_at_ms",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("logical_message_id"), row.get("encoded_frame")))
            .collect())
    }

    pub async fn remove_outbox(&self, logical_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM outbox WHERE logical_message_id = ?")
            .bind(logical_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn cursors(&self) -> Result<(u64, u64)> {
        let row = sqlx::query(
            "SELECT envelope_cursor, status_cursor FROM sync_state WHERE singleton = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get::<i64, _>("envelope_cursor") as u64,
            row.get::<i64, _>("status_cursor") as u64,
        ))
    }

    pub async fn set_cursors(&self, envelope: u64, status: u64) -> Result<()> {
        sqlx::query(
            "UPDATE sync_state SET envelope_cursor = ?, status_cursor = ? WHERE singleton = 1",
        )
        .bind(envelope as i64)
        .bind(status as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn notifications(&self, vault: &VaultSession) -> Result<Vec<Notification>> {
        let rows = sqlx::query(
            "SELECT id, kind, request_id, actor_account_id, actor_username, actor_device_id,
                    encrypted_payload, state, is_read, created_at_ms, updated_at_ms
             FROM notifications ORDER BY created_at_ms DESC, id DESC LIMIT 200",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| decode_notification(vault, row))
            .collect()
    }

    pub async fn notification_by_request_id(
        &self,
        vault: &VaultSession,
        request_id: &str,
    ) -> Result<Option<Notification>> {
        let row = sqlx::query(
            "SELECT id, kind, request_id, actor_account_id, actor_username, actor_device_id,
                    encrypted_payload, state, is_read, created_at_ms, updated_at_ms
             FROM notifications WHERE request_id = ?",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_notification(vault, row)).transpose()
    }

    pub async fn save_notification(
        &self,
        vault: &VaultSession,
        notification: &Notification,
    ) -> Result<()> {
        let payload = serde_json::to_vec(&notification.data)?;
        let aad = format!("notification/v1/{}", notification.id);
        let encrypted_payload = vault.encrypt(aad.as_bytes(), &payload)?.to_bytes();
        sqlx::query(
            "INSERT INTO notifications(
                id, kind, request_id, actor_account_id, actor_username, actor_device_id,
                encrypted_payload, state, is_read, created_at_ms, updated_at_ms
             ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(request_id) DO UPDATE SET
                id=excluded.id,
                kind=excluded.kind,
                actor_account_id=excluded.actor_account_id,
                actor_username=excluded.actor_username,
                actor_device_id=excluded.actor_device_id,
                encrypted_payload=excluded.encrypted_payload,
                state=excluded.state,
                is_read=excluded.is_read,
                updated_at_ms=excluded.updated_at_ms",
        )
        .bind(&notification.id)
        .bind(notification.kind.as_str())
        .bind(&notification.request_id)
        .bind(&notification.actor_account_id)
        .bind(&notification.actor_username)
        .bind(&notification.actor_device_id)
        .bind(encrypted_payload)
        .bind(notification.state.as_str())
        .bind(i64::from(notification.read))
        .bind(notification.created_at_ms)
        .bind(notification.updated_at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_notification_state(
        &self,
        id: &str,
        state: NotificationState,
        read: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE notifications SET state = ?, is_read = ?, updated_at_ms = ? WHERE id = ?",
        )
        .bind(state.as_str())
        .bind(i64::from(read))
        .bind(now_ms())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_notification_read(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE notifications SET is_read = 1, updated_at_ms = ? WHERE id = ?")
            .bind(now_ms())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_notification(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM notifications WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn pairing_event_processed(&self, server_event_id: u64) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM processed_pairing_events WHERE server_event_id = ?",
        )
        .bind(server_event_id as i64)
        .fetch_one(&self.pool)
        .await?
            > 0)
    }

    pub async fn mark_pairing_event_processed(&self, server_event_id: u64) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO processed_pairing_events(server_event_id, processed_at_ms) VALUES(?, ?)")
            .bind(server_event_id as i64)
            .bind(now_ms())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn contact_from_row(row: sqlx::sqlite::SqliteRow) -> Result<Contact> {
    Ok(Contact {
        bundle: UserBundle::decode(row.get::<Vec<u8>, _>("bundle").as_slice())?,
        verified: row.get::<i64, _>("verified") != 0,
        identity_changed: row.get::<i64, _>("identity_changed") != 0,
        unread_count: row.get::<i64, _>("unread_count") as u64,
        last_activity_ms: row.get("last_activity_ms"),
    })
}

fn decode_notification(vault: &VaultSession, row: sqlx::sqlite::SqliteRow) -> Result<Notification> {
    let id: String = row.get("id");
    let blob = decode_encrypted_blob(&row.get::<Vec<u8>, _>("encrypted_payload"))?;
    let aad = format!("notification/v1/{id}");
    let data = serde_json::from_slice(&vault.decrypt(aad.as_bytes(), &blob)?)?;
    Ok(Notification {
        id,
        kind: NotificationKind::try_from(row.get::<String, _>("kind").as_str())?,
        request_id: row.get("request_id"),
        actor_account_id: row.get("actor_account_id"),
        actor_username: row.get("actor_username"),
        actor_device_id: row.get("actor_device_id"),
        state: NotificationState::try_from(row.get::<String, _>("state").as_str())?,
        read: row.get::<i64, _>("is_read") != 0,
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        data,
    })
}

fn encode_profile(vault: &VaultSession, profile: &RuntimeProfile) -> Result<Vec<u8>> {
    let plain = StoredProfile {
        username: profile.username.clone(),
        account_id: profile.account_id.clone(),
        server_url: profile.server_url.clone(),
        identity: profile.identity.to_bytes()?,
        machine: profile.machine.to_bytes()?,
        pending: profile.pending,
        pairing_secret: profile.pairing_secret,
        account_master_public: profile.account_master_public.clone(),
        spki_pin: profile.spki_pin.clone(),
    };
    let mut encoded = b"TCP3".to_vec();
    encoded.extend(postcard::to_allocvec(&plain)?);
    Ok(vault.encrypt(b"profile/v1", &encoded)?.to_bytes())
}

fn decode_encrypted_blob(encoded: &[u8]) -> Result<EncryptedBlob> {
    if let Ok(blob) = EncryptedBlob::from_bytes(encoded) {
        return Ok(blob);
    }
    let nested: Vec<u8> = serde_json::from_slice(encoded)?;
    EncryptedBlob::from_bytes(&nested)
}

fn encode_message(vault: &VaultSession, message: &ChatMessage) -> Result<Vec<u8>> {
    let aad = format!("message/v1/{}", message.id);
    Ok(vault
        .encrypt(aad.as_bytes(), message.body.as_bytes())?
        .to_bytes())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(account_id: &str, username: &str) -> UserBundle {
        UserBundle {
            account_id: account_id.to_owned(),
            username: username.to_owned(),
            account_master_key: vec![7; 32],
            roster_revision: 1,
            devices: vec![],
        }
    }

    #[tokio::test]
    async fn message_status_never_regresses() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        sqlx::query("INSERT INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound) VALUES('message-1', 'conversation-1', 'peer-1', 'sender-1', X'00', 1, '已发送', 0)")
            .execute(&store.pool)
            .await?;

        store
            .update_status("message-1", MessageStatus::Read)
            .await?;
        store
            .update_status("message-1", MessageStatus::Delivered)
            .await?;

        let status: String = sqlx::query_scalar(
            "SELECT status FROM messages WHERE logical_message_id = 'message-1'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(status, "read");
        Ok(())
    }

    #[tokio::test]
    async fn notifications_are_encrypted_deduplicated_and_persisted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        let vault = store.unlock("test passphrase").await?;
        let notification = Notification {
            id: "notification-1".into(),
            kind: NotificationKind::ChatRequest,
            request_id: "request-1".into(),
            actor_account_id: "account-a".into(),
            actor_username: "alice".into(),
            actor_device_id: "device-a".into(),
            state: NotificationState::Pending,
            read: false,
            created_at_ms: 1,
            updated_at_ms: 1,
            data: NotificationData::ChatRequest {
                outgoing: false,
                request_id: "request-1".into(),
                sender_account_id: "account-a".into(),
                sender_username: "alice".into(),
                sender_device_id: "device-a".into(),
                sender_bundle: bundle("account-a", "alice").encode_to_vec(),
            },
        };
        store.save_notification(&vault, &notification).await?;
        let raw: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_payload FROM notifications WHERE request_id = 'request-1'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert!(!raw.windows(b"alice".len()).any(|window| window == b"alice"));
        store
            .update_notification_state("notification-1", NotificationState::Accepted, true)
            .await?;
        let notifications = store.notifications(&vault).await?;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].state, NotificationState::Accepted);
        assert!(notifications[0].read);

        let response = Notification {
            id: "notification-1".into(),
            kind: NotificationKind::ChatResponse,
            request_id: "request-1".into(),
            actor_account_id: "account-a".into(),
            actor_username: "alice".into(),
            actor_device_id: "device-a".into(),
            state: NotificationState::Rejected,
            read: true,
            created_at_ms: 1,
            updated_at_ms: 2,
            data: NotificationData::ChatResponse {
                request_id: "request-1".into(),
                accepted: false,
            },
        };
        store.save_notification(&vault, &response).await?;
        let notifications = store.notifications(&vault).await?;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].kind, NotificationKind::ChatResponse);
        assert_eq!(notifications[0].state, NotificationState::Rejected);
        assert!(matches!(
            notifications[0].data,
            NotificationData::ChatResponse {
                accepted: false,
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn notifications_keep_time_order_when_read_and_can_be_deleted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        let vault = store.unlock("test passphrase").await?;
        for (id, request_id, created_at_ms) in [
            ("notification-old", "request-old", 10),
            ("notification-new", "request-new", 20),
        ] {
            store
                .save_notification(
                    &vault,
                    &Notification {
                        id: id.into(),
                        kind: NotificationKind::ChatRequest,
                        request_id: request_id.into(),
                        actor_account_id: "account-a".into(),
                        actor_username: "alice".into(),
                        actor_device_id: "device-a".into(),
                        state: NotificationState::Pending,
                        read: false,
                        created_at_ms,
                        updated_at_ms: created_at_ms,
                        data: NotificationData::ChatRequest {
                            outgoing: false,
                            request_id: request_id.into(),
                            sender_account_id: "account-a".into(),
                            sender_username: "alice".into(),
                            sender_device_id: "device-a".into(),
                            sender_bundle: bundle("account-a", "alice").encode_to_vec(),
                        },
                    },
                )
                .await?;
        }

        store.mark_notification_read("notification-old").await?;
        let notifications = store.notifications(&vault).await?;
        assert_eq!(notifications[0].id, "notification-new");
        assert_eq!(notifications[1].id, "notification-old");

        store.delete_notification("notification-new").await?;
        let notifications = store.notifications(&vault).await?;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].id, "notification-old");
        Ok(())
    }

    #[tokio::test]
    async fn quarantined_message_notification_and_cursor_are_committed_together() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        let vault = store.unlock("test passphrase").await?;
        let identity = DeviceIdentity::new("account-local", "device-local", "test", true);
        let profile = RuntimeProfile {
            account_master_public: identity
                .master_public_key()
                .expect("first device has a master key")
                .to_vec(),
            username: "local-user".into(),
            account_id: "account-local".into(),
            server_url: "ws://127.0.0.1:8080/v1/ws".into(),
            identity,
            machine: OlmMachine::new(),
            pending: false,
            pairing_secret: None,
            spki_pin: None,
        };
        let peer = bundle("account-a", "alice");
        store.upsert_contact(&peer).await?;
        let message = ChatMessage {
            id: "message-1".into(),
            conversation_id: "conversation-1".into(),
            peer_account_id: "account-a".into(),
            sender_account_id: "account-a".into(),
            body: "quarantined secret".into(),
            sent_at_ms: 10,
            status: MessageStatus::Delivered,
            inbound: true,
        };
        let notification = Notification {
            id: "notification-1".into(),
            kind: NotificationKind::ChatRequest,
            request_id: "reauth-conversation-1".into(),
            actor_account_id: "account-a".into(),
            actor_username: "alice".into(),
            actor_device_id: "device-a".into(),
            state: NotificationState::Pending,
            read: false,
            created_at_ms: 10,
            updated_at_ms: 10,
            data: NotificationData::ChatRequest {
                outgoing: false,
                request_id: "reauth-conversation-1".into(),
                sender_account_id: "account-a".into(),
                sender_username: "alice".into(),
                sender_device_id: "device-a".into(),
                sender_bundle: peer.encode_to_vec(),
            },
        };

        store
            .commit_unverified_inbound(&vault, &profile, &message, &notification, 7)
            .await?;

        assert!(store.load_profile(&vault).await?.is_some());
        assert_eq!(
            store.messages(&vault, "conversation-1").await?[0].body,
            "quarantined secret"
        );
        assert_eq!(store.notifications(&vault).await?.len(), 1);
        assert_eq!(store.cursors().await?, (7, 0));

        store
            .update_notification_state("notification-1", NotificationState::Rejected, true)
            .await?;
        let mut retry_message = message.clone();
        retry_message.id = "message-2".into();
        let mut retry_notification = notification;
        retry_notification.state = NotificationState::Pending;
        retry_notification.read = false;
        retry_notification.updated_at_ms = 20;
        store
            .commit_unverified_inbound(&vault, &profile, &retry_message, &retry_notification, 8)
            .await?;
        let notifications = store.notifications(&vault).await?;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].state, NotificationState::Pending);
        assert!(!notifications[0].read);
        assert_eq!(store.messages(&vault, "conversation-1").await?.len(), 2);
        assert_eq!(store.cursors().await?, (8, 0));
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_conversation_removes_all_local_conversation_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        let vault = store.unlock("test passphrase").await?;
        let peer = bundle("account-a", "alice");
        store.upsert_contact(&peer).await?;
        store
            .save_message(
                &vault,
                &ChatMessage {
                    id: "message-1".into(),
                    conversation_id: "conversation-1".into(),
                    peer_account_id: "account-a".into(),
                    sender_account_id: "account-local".into(),
                    body: "secret".into(),
                    sent_at_ms: 1,
                    status: MessageStatus::Sending,
                    inbound: false,
                },
            )
            .await?;
        store
            .save_draft(&vault, "conversation-1", "unfinished")
            .await?;
        sqlx::query(
            "INSERT INTO outbox(logical_message_id, encoded_frame, created_at_ms)
             VALUES('message-1', X'01', 1)",
        )
        .execute(&store.pool)
        .await?;
        store
            .save_notification(
                &vault,
                &Notification {
                    id: "notification-1".into(),
                    kind: NotificationKind::ChatRequest,
                    request_id: "request-1".into(),
                    actor_account_id: "account-a".into(),
                    actor_username: "alice".into(),
                    actor_device_id: "device-a".into(),
                    state: NotificationState::Pending,
                    read: false,
                    created_at_ms: 1,
                    updated_at_ms: 1,
                    data: NotificationData::ChatRequest {
                        outgoing: false,
                        request_id: "request-1".into(),
                        sender_account_id: "account-a".into(),
                        sender_username: "alice".into(),
                        sender_device_id: "device-a".into(),
                        sender_bundle: peer.encode_to_vec(),
                    },
                },
            )
            .await?;

        store
            .delete_conversation("account-a", "conversation-1")
            .await?;

        assert!(store.contacts().await?.is_empty());
        assert!(store.messages(&vault, "conversation-1").await?.is_empty());
        assert_eq!(store.load_draft(&vault, "conversation-1").await?, "");
        assert!(store.notifications(&vault).await?.is_empty());
        for table in ["outbox", "conversation_summaries"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&store.pool)
                .await?;
            assert_eq!(count, 0, "{table} should be empty");
        }
        Ok(())
    }

    #[tokio::test]
    async fn drafts_are_encrypted_and_history_is_paginated() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = LocalStore::open(&directory.path().join("client.db")).await?;
        let vault = store.unlock("test passphrase").await?;

        let identity = DeviceIdentity::new("account-local", "device-local", "test", true);
        let account_master_public = identity
            .master_public_key()
            .expect("first device has a master key")
            .to_vec();
        let profile = RuntimeProfile {
            username: "local-user".into(),
            account_id: "account-local".into(),
            server_url: "ws://127.0.0.1:8080/v1/ws".into(),
            identity,
            machine: OlmMachine::new(),
            pending: false,
            pairing_secret: None,
            account_master_public,
            spki_pin: None,
        };
        store.save_profile(&vault, &profile).await?;
        let canonical: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_blob FROM profile WHERE singleton = 1")
                .fetch_one(&store.pool)
                .await?;
        assert!(canonical.starts_with(b"TCB"));

        let nested = serde_json::to_vec(&canonical)?;
        sqlx::query("UPDATE profile SET encrypted_blob = ? WHERE singleton = 1")
            .bind(nested)
            .execute(&store.pool)
            .await?;
        let recovered = store
            .load_profile(&vault)
            .await?
            .expect("nested legacy profile is recoverable");
        assert_eq!(recovered.username, "local-user");
        store.save_profile(&vault, &recovered).await?;
        let repaired: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_blob FROM profile WHERE singleton = 1")
                .fetch_one(&store.pool)
                .await?;
        assert!(repaired.starts_with(b"TCB"));

        store
            .save_draft(&vault, "conversation-1", "尚未发送的秘密")
            .await?;
        assert_eq!(
            store.load_draft(&vault, "conversation-1").await?,
            "尚未发送的秘密"
        );
        let raw: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_body FROM drafts WHERE conversation_id = 'conversation-1'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert!(
            !raw.windows("尚未发送的秘密".len())
                .any(|window| { window == "尚未发送的秘密".as_bytes() })
        );

        store.upsert_contact(&bundle("account-a", "alice")).await?;
        store.upsert_contact(&bundle("account-b", "bob")).await?;
        for index in 0..105 {
            store
                .save_message(
                    &vault,
                    &ChatMessage {
                        id: format!("message-{index:03}"),
                        conversation_id: "conversation-1".into(),
                        peer_account_id: "account-b".into(),
                        sender_account_id: "account-b".into(),
                        body: format!("body-{index}"),
                        sent_at_ms: index,
                        status: MessageStatus::Delivered,
                        inbound: true,
                    },
                )
                .await?;
        }
        let latest = store.messages(&vault, "conversation-1").await?;
        assert_eq!(latest.len(), MESSAGE_PAGE_SIZE);
        assert_eq!(
            latest.first().map(|message| message.id.as_str()),
            Some("message-005")
        );
        let older = store
            .messages_before(
                &vault,
                "conversation-1",
                latest[0].sent_at_ms,
                &latest[0].id,
            )
            .await?;
        assert_eq!(older.len(), 5);
        assert_eq!(older[0].id, "message-000");

        let contacts = store.contacts().await?;
        assert_eq!(contacts[0].bundle.username, "bob");
        assert_eq!(contacts[0].unread_count, 105);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_storage_is_backed_up_and_resumably_migrated() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("client.db");
        let store = LocalStore::open(&database).await?;
        let passphrase = "legacy passphrase";
        let profile = tui_chat_crypto::encrypt_blob(passphrase, b"profile/v1", b"legacy-profile")?;
        sqlx::query(
            "INSERT INTO profile(singleton, encrypted_blob, updated_at_ms) VALUES(1, ?, 1)",
        )
        .bind(serde_json::to_vec(&profile)?)
        .execute(&store.pool)
        .await?;
        let message = tui_chat_crypto::encrypt_blob(
            passphrase,
            b"message/v1/legacy-message",
            b"legacy body",
        )?;
        sqlx::query("INSERT INTO messages(logical_message_id, conversation_id, peer_account_id, sender_account_id, encrypted_body, sent_at_ms, status, inbound) VALUES('legacy-message', 'legacy-conversation', 'peer', 'sender', ?, 1, '已送达', 1)")
            .bind(serde_json::to_vec(&message)?)
            .execute(&store.pool)
            .await?;

        let vault = store.unlock(passphrase).await?;
        assert_eq!(store.migrate_legacy_messages(&vault).await?, 1);
        assert_eq!(store.migrate_legacy_messages(&vault).await?, 0);
        let loaded = store.messages(&vault, "legacy-conversation").await?;
        assert_eq!(loaded[0].body, "legacy body");
        let version: i64 = sqlx::query_scalar(
            "SELECT encryption_version FROM messages WHERE logical_message_id = 'legacy-message'",
        )
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(version, 2);

        let backup_exists = std::fs::read_dir(directory.path())?
            .filter_map(std::result::Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".pre-v2-"));
        assert!(backup_exists);
        Ok(())
    }
}
