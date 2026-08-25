use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, bail};
use serde::Serialize;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use tui_chat_protocol::v1::{
    DeliveryUpdate, DeviceBundle, EncryptedEnvelope, OneTimeKey, OwnDeviceInfo,
    StoredDeliveryUpdate, StoredEnvelope,
};

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct StorageLimits {
    pub max_account_ciphertext_bytes: u64,
    pub max_total_ciphertext_bytes: u64,
    pub min_free_disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StorageStatus {
    pub ciphertext_bytes: u64,
    pub account_limit_bytes: u64,
    pub total_limit_bytes: u64,
    pub free_disk_bytes: u64,
    pub minimum_free_disk_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct CleanupStats {
    pub envelopes: u64,
    pub ciphertext_bytes: u64,
    pub logical_messages: u64,
    pub delivery_updates: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageRejection {
    #[error("account ciphertext quota exceeded")]
    AccountQuota,
    #[error("server ciphertext quota exceeded")]
    TotalQuota,
    #[error("server disk free-space reserve reached")]
    DiskPressure,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub id: String,
    pub username: String,
    pub password_phc: String,
    pub state: String,
    pub require_password_change: bool,
    pub master_public_key: Option<Vec<u8>>,
    pub roster_revision: u64,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub auth_signing_key: Vec<u8>,
    pub pending: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct PendingPairingEvent {
    pub id: u64,
    pub pairing_id: String,
    pub sender_device_id: String,
    pub event_type: String,
    pub payload: Vec<u8>,
}

impl Db {
    pub async fn connect(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        harden_parent_permissions(path).await?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        let db = Self {
            pool,
            path: path.to_path_buf(),
        };
        db.harden_file_permissions().await?;
        Ok(db)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    #[cfg(unix)]
    async fn harden_file_permissions(&self) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
        for path in [
            self.path.clone(),
            PathBuf::from(format!("{}-wal", self.path.display())),
            PathBuf::from(format!("{}-shm", self.path.display())),
        ] {
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    async fn harden_file_permissions(&self) -> Result<()> {
        Ok(())
    }

    fn free_disk_bytes(&self) -> Result<u64> {
        let directory = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs4::available_space(directory).map_err(Into::into)
    }

    pub async fn account_by_username(&self, username: &str) -> Result<Option<Account>> {
        let row = sqlx::query("SELECT id, username, password_phc, state, require_password_change, master_public_key, roster_revision FROM accounts WHERE username = ? COLLATE NOCASE")
            .bind(username).fetch_optional(&self.pool).await?;
        Ok(row.map(account_from_row))
    }

    pub async fn device(&self, account_id: &str, device_id: &str) -> Result<Option<Device>> {
        let row = sqlx::query("SELECT auth_signing_key, pending, revoked FROM devices WHERE account_id = ? AND id = ?")
            .bind(account_id).bind(device_id).fetch_optional(&self.pool).await?;
        Ok(row.map(|row| Device {
            auth_signing_key: row.get("auth_signing_key"),
            pending: row.get::<i64, _>("pending") != 0,
            revoked: row.get::<i64, _>("revoked") != 0,
        }))
    }

    pub async fn has_active_devices(&self, account_id: &str) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM devices WHERE account_id = ? AND pending = 0 AND revoked = 0",
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    pub async fn device_counts(&self, account_id: &str) -> Result<(u64, u64)> {
        let row = sqlx::query(
            "SELECT \
             COALESCE(SUM(CASE WHEN pending = 0 AND revoked = 0 THEN 1 ELSE 0 END), 0) active, \
             COALESCE(SUM(CASE WHEN pending = 1 AND revoked = 0 THEN 1 ELSE 0 END), 0) pending \
             FROM devices WHERE account_id = ?",
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get::<i64, _>("active") as u64,
            row.get::<i64, _>("pending") as u64,
        ))
    }

    pub async fn device_bundles(
        &self,
        account_id: &str,
        include_pending: bool,
    ) -> Result<Vec<DeviceBundle>> {
        let sql = if include_pending {
            "SELECT id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, revoked FROM devices WHERE account_id = ?"
        } else {
            "SELECT id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, revoked FROM devices WHERE account_id = ? AND pending = 0"
        };
        let rows = sqlx::query(sql)
            .bind(account_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(device_bundle_from_row).collect())
    }

    pub async fn own_devices(&self, account_id: &str) -> Result<Vec<OwnDeviceInfo>> {
        let rows = sqlx::query(
            "SELECT id, name, pending, revoked, created_at_ms,
                    COALESCE(last_authenticated_at_ms, 0) AS last_authenticated_at_ms
             FROM devices WHERE account_id = ?
             ORDER BY revoked, pending, created_at_ms",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| OwnDeviceInfo {
                device_id: row.get("id"),
                device_name: row.get("name"),
                pending: row.get::<i64, _>("pending") != 0,
                revoked: row.get::<i64, _>("revoked") != 0,
                current: false,
                online: false,
                created_at_ms: row.get("created_at_ms"),
                last_authenticated_at_ms: row.get("last_authenticated_at_ms"),
            })
            .collect())
    }

    pub async fn revoke_own_device(&self, account_id: &str, device_id: &str) -> Result<bool> {
        let affected = sqlx::query(
            "UPDATE devices SET revoked = 1
             WHERE account_id = ? AND id = ? AND revoked = 0",
        )
        .bind(account_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 1 {
            self.cleanup_revoked_device(device_id).await?;
        }
        Ok(affected == 1)
    }

    pub async fn insert_device(
        &self,
        account_id: &str,
        bundle: &DeviceBundle,
        sas_public: &[u8],
        pending: bool,
        now: i64,
    ) -> Result<()> {
        sqlx::query("INSERT INTO devices(id, account_id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, sas_public_key, pending, created_at_ms) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&bundle.device_id).bind(account_id).bind(&bundle.device_name)
            .bind(&bundle.auth_signing_key).bind(&bundle.olm_ed25519_key)
            .bind(&bundle.olm_curve25519_key).bind(&bundle.certificate_signature)
            .bind(sas_public).bind(i64::from(pending)).bind(now)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn bootstrap_master(&self, account_id: &str, master: &[u8]) -> Result<()> {
        let result = sqlx::query("UPDATE accounts SET master_public_key = ?, roster_revision = 1 WHERE id = ? AND master_public_key IS NULL")
            .bind(master).bind(account_id).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            bail!("account is already bootstrapped");
        }
        Ok(())
    }

    pub async fn set_password(
        &self,
        account_id: &str,
        phc: &str,
        require_change: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE accounts SET password_phc = ?, require_password_change = ? WHERE id = ?",
        )
        .bind(phc)
        .bind(i64::from(require_change))
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_device_authentication(&self, device_id: &str, now: i64) -> Result<()> {
        sqlx::query("UPDATE devices SET last_authenticated_at_ms = ? WHERE id = ?")
            .bind(now)
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn publish_prekeys(
        &self,
        device_id: &str,
        keys: &[OneTimeKey],
        now: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for key in keys {
            sqlx::query("INSERT OR IGNORE INTO prekeys(device_id, key_id, curve25519_key, signature, created_at_ms) VALUES(?, ?, ?, ?, ?)")
                .bind(device_id).bind(&key.key_id).bind(&key.curve25519_key)
                .bind(&key.signature).bind(now).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn claim_prekey(
        &self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<(DeviceBundle, OneTimeKey)>> {
        let mut tx = self.pool.begin().await?;
        let device = sqlx::query("SELECT id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, revoked FROM devices WHERE account_id = ? AND id = ? AND pending = 0 AND revoked = 0")
            .bind(account_id).bind(device_id).fetch_optional(&mut *tx).await?;
        let Some(device) = device else {
            return Ok(None);
        };
        let key = sqlx::query("DELETE FROM prekeys WHERE rowid = (SELECT rowid FROM prekeys WHERE device_id = ? ORDER BY created_at_ms LIMIT 1) RETURNING key_id, curve25519_key, signature")
            .bind(device_id).fetch_optional(&mut *tx).await?;
        let Some(key) = key else {
            return Ok(None);
        };
        let bundle = device_bundle_from_row(device);
        let one_time_key = OneTimeKey {
            key_id: key.get("key_id"),
            curve25519_key: key.get("curve25519_key"),
            signature: key.get("signature"),
        };
        tx.commit().await?;
        Ok(Some((bundle, one_time_key)))
    }

    pub async fn lookup_user_bundle(
        &self,
        username: &str,
    ) -> Result<Option<(Account, Vec<DeviceBundle>)>> {
        let Some(account) = self.account_by_username(username).await? else {
            return Ok(None);
        };
        if account.state != "active" || account.master_public_key.is_none() {
            return Ok(None);
        }
        let devices = self.device_bundles(&account.id, false).await?;
        Ok(Some((account, devices)))
    }

    pub async fn device_account_any(&self, device_id: &str) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT account_id FROM devices WHERE id = ? AND revoked = 0")
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn store_envelopes(
        &self,
        sender_account: &str,
        sender_device: &str,
        envelopes: &[EncryptedEnvelope],
        now: i64,
        limits: StorageLimits,
    ) -> Result<Vec<(String, u64)>> {
        if envelopes.is_empty() || envelopes.len() > 16 {
            bail!("envelope batch must contain 1..=16 entries");
        }
        let logical = &envelopes[0].logical_message_id;
        if logical.is_empty() || envelopes.iter().any(|e| &e.logical_message_id != logical) {
            bail!("batch mixes logical messages");
        }
        let mut peers: BTreeSet<&str> = envelopes
            .iter()
            .filter(|e| e.recipient_account_id != sender_account)
            .map(|e| e.recipient_account_id.as_str())
            .collect();
        if peers.len() > 1 {
            bail!("v1 supports one peer per message");
        }
        let peer = peers.pop_first().unwrap_or(sender_account);
        let expected_conversation = tui_chat_protocol::conversation_id(sender_account, peer);
        if envelopes.iter().any(|e| {
            e.conversation_id != expected_conversation
                || e.ciphertext.is_empty()
                || e.ciphertext.len() > tui_chat_protocol::MAX_FRAME_BYTES
        }) {
            bail!("invalid conversation or ciphertext");
        }

        if self.free_disk_bytes()? < limits.min_free_disk_bytes {
            return Err(StorageRejection::DiskPressure.into());
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT OR IGNORE INTO logical_messages(logical_message_id, sender_account_id, sender_device_id, peer_account_id, conversation_id, client_sent_at_ms, accepted_at_ms) VALUES(?, ?, ?, ?, ?, ?, ?)")
            .bind(logical).bind(sender_account).bind(sender_device).bind(peer)
            .bind(&expected_conversation).bind(envelopes[0].client_sent_at_ms).bind(now)
            .execute(&mut *tx).await?;

        let metadata = sqlx::query(
            "SELECT sender_account_id, sender_device_id, peer_account_id, conversation_id, client_sent_at_ms FROM logical_messages WHERE logical_message_id = ?",
        )
        .bind(logical)
        .fetch_one(&mut *tx)
        .await?;
        if metadata.get::<String, _>("sender_account_id") != sender_account
            || metadata.get::<String, _>("sender_device_id") != sender_device
            || metadata.get::<String, _>("peer_account_id") != peer
            || metadata.get::<String, _>("conversation_id") != expected_conversation
            || metadata.get::<i64, _>("client_sent_at_ms") != envelopes[0].client_sent_at_ms
        {
            bail!("logical message id conflicts with immutable metadata");
        }

        let mut active_envelopes = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.account_id = ? AND d.id = ? AND d.pending = 0 AND d.revoked = 0 AND a.state = 'active'")
                .bind(&envelope.recipient_account_id).bind(&envelope.recipient_device_id)
                .fetch_one(&mut *tx).await?;
            if active == 1 {
                active_envelopes.push(envelope);
            }
        }
        if active_envelopes.is_empty()
            || (peer != sender_account
                && !active_envelopes
                    .iter()
                    .any(|envelope| envelope.recipient_account_id == peer))
        {
            bail!("recipient device is unavailable");
        }

        let mut additional_bytes = 0_u64;
        for envelope in &active_envelopes {
            let existing: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT ciphertext FROM envelopes WHERE envelope_id = ?")
                    .bind(&envelope.envelope_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            match existing {
                Some(ciphertext) if ciphertext == envelope.ciphertext => {}
                Some(_) => bail!("envelope id conflicts with immutable metadata"),
                None => {
                    additional_bytes = additional_bytes
                        .checked_add(envelope.ciphertext.len() as u64)
                        .ok_or_else(|| anyhow::anyhow!("ciphertext size overflow"))?;
                }
            }
        }
        let account_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(ciphertext_bytes, 0) FROM account_storage_usage WHERE account_id = ?",
        )
        .bind(sender_account)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(0);
        let total_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(ciphertext_bytes), 0) FROM account_storage_usage",
        )
        .fetch_one(&mut *tx)
        .await?;
        if (account_bytes.max(0) as u64).saturating_add(additional_bytes)
            > limits.max_account_ciphertext_bytes
        {
            return Err(StorageRejection::AccountQuota.into());
        }
        if (total_bytes.max(0) as u64).saturating_add(additional_bytes)
            > limits.max_total_ciphertext_bytes
        {
            return Err(StorageRejection::TotalQuota.into());
        }

        let mut stored = Vec::with_capacity(active_envelopes.len());
        for envelope in active_envelopes {
            sqlx::query("INSERT OR IGNORE INTO envelopes(envelope_id, logical_message_id, sender_account_id, sender_device_id, recipient_account_id, recipient_device_id, conversation_id, ciphertext, olm_message_type, client_sent_at_ms, accepted_at_ms) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&envelope.envelope_id).bind(&envelope.logical_message_id)
                .bind(sender_account).bind(sender_device).bind(&envelope.recipient_account_id)
                .bind(&envelope.recipient_device_id).bind(&envelope.conversation_id)
                .bind(&envelope.ciphertext).bind(i64::from(envelope.olm_message_type))
                .bind(envelope.client_sent_at_ms).bind(now).execute(&mut *tx).await?;
            let persisted = sqlx::query(
                "SELECT cursor, logical_message_id, sender_account_id, sender_device_id, \
                 recipient_account_id, recipient_device_id, conversation_id, ciphertext, \
                 olm_message_type, client_sent_at_ms FROM envelopes WHERE envelope_id = ?",
            )
            .bind(&envelope.envelope_id)
            .fetch_one(&mut *tx)
            .await?;
            if persisted.get::<String, _>("logical_message_id") != envelope.logical_message_id
                || persisted.get::<String, _>("sender_account_id") != sender_account
                || persisted.get::<String, _>("sender_device_id") != sender_device
                || persisted.get::<String, _>("recipient_account_id")
                    != envelope.recipient_account_id
                || persisted.get::<String, _>("recipient_device_id") != envelope.recipient_device_id
                || persisted.get::<String, _>("conversation_id") != envelope.conversation_id
                || persisted.get::<Vec<u8>, _>("ciphertext") != envelope.ciphertext
                || persisted.get::<i64, _>("olm_message_type")
                    != i64::from(envelope.olm_message_type)
                || persisted.get::<i64, _>("client_sent_at_ms") != envelope.client_sent_at_ms
            {
                bail!("envelope id conflicts with immutable metadata");
            }
            let cursor: i64 = persisted.get("cursor");
            stored.push((envelope.recipient_device_id.clone(), cursor as u64));
        }
        tx.commit().await?;
        Ok(stored)
    }

    pub async fn storage_status(&self, limits: StorageLimits) -> Result<StorageStatus> {
        let ciphertext_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(ciphertext_bytes), 0) FROM account_storage_usage",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(StorageStatus {
            ciphertext_bytes: ciphertext_bytes.max(0) as u64,
            account_limit_bytes: limits.max_account_ciphertext_bytes,
            total_limit_bytes: limits.max_total_ciphertext_bytes,
            free_disk_bytes: self.free_disk_bytes()?,
            minimum_free_disk_bytes: limits.min_free_disk_bytes,
        })
    }

    pub async fn cleanup_delivered_envelopes(
        &self,
        delivered_before_ms: i64,
        limit: u32,
    ) -> Result<CleanupStats> {
        let limit = i64::from(limit.clamp(1, 10_000));
        let mut tx = self.pool.begin().await?;
        let removed = sqlx::query(
            "DELETE FROM envelopes WHERE cursor IN (
                SELECT cursor FROM envelopes
                WHERE delivered_at_ms IS NOT NULL AND delivered_at_ms < ?
                ORDER BY cursor LIMIT ?
             ) RETURNING length(ciphertext) AS ciphertext_bytes",
        )
        .bind(delivered_before_ms)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        let envelopes = removed.len() as u64;
        let ciphertext_bytes = removed
            .iter()
            .map(|row| row.get::<i64, _>("ciphertext_bytes").max(0) as u64)
            .sum();
        let delivery_updates = sqlx::query(
            "DELETE FROM delivery_updates
             WHERE NOT EXISTS (
                SELECT 1 FROM envelopes e
                WHERE e.logical_message_id = delivery_updates.logical_message_id
             )",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let logical_messages = sqlx::query(
            "DELETE FROM logical_messages
             WHERE NOT EXISTS (
                SELECT 1 FROM envelopes e
                WHERE e.logical_message_id = logical_messages.logical_message_id
             )",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(CleanupStats {
            envelopes,
            ciphertext_bytes,
            logical_messages,
            delivery_updates,
        })
    }

    pub async fn cleanup_revoked_device(&self, device_id: &str) -> Result<CleanupStats> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM prekeys WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        let removed = sqlx::query(
            "DELETE FROM envelopes WHERE recipient_device_id = ?
             RETURNING length(ciphertext) AS ciphertext_bytes",
        )
        .bind(device_id)
        .fetch_all(&mut *tx)
        .await?;
        let envelopes = removed.len() as u64;
        let ciphertext_bytes = removed
            .iter()
            .map(|row| row.get::<i64, _>("ciphertext_bytes").max(0) as u64)
            .sum();
        let delivery_updates = sqlx::query(
            "DELETE FROM delivery_updates
             WHERE NOT EXISTS (
                SELECT 1 FROM envelopes e
                WHERE e.logical_message_id = delivery_updates.logical_message_id
             )",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let logical_messages = sqlx::query(
            "DELETE FROM logical_messages
             WHERE NOT EXISTS (
                SELECT 1 FROM envelopes e
                WHERE e.logical_message_id = logical_messages.logical_message_id
             )",
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(CleanupStats {
            envelopes,
            ciphertext_bytes,
            logical_messages,
            delivery_updates,
        })
    }

    pub async fn stored_envelope(&self, envelope_id: &str) -> Result<Option<StoredEnvelope>> {
        let row = sqlx::query("SELECT e.cursor, e.sender_account_id, e.sender_device_id, e.envelope_id, e.logical_message_id, e.conversation_id, e.recipient_account_id, e.recipient_device_id, e.ciphertext, e.olm_message_type, e.client_sent_at_ms, e.accepted_at_ms, a.username AS sender_username FROM envelopes e JOIN accounts a ON a.id = e.sender_account_id WHERE e.envelope_id = ?")
            .bind(envelope_id).fetch_optional(&self.pool).await?;
        Ok(row.map(stored_envelope_from_row))
    }

    pub async fn sync(
        &self,
        account_id: &str,
        device_id: &str,
        after: u64,
        status_after: u64,
        limit: u32,
    ) -> Result<(Vec<StoredEnvelope>, Vec<StoredDeliveryUpdate>, bool)> {
        let limit = limit.clamp(1, 200) as i64;
        let rows = sqlx::query("SELECT e.cursor, e.sender_account_id, e.sender_device_id, e.envelope_id, e.logical_message_id, e.conversation_id, e.recipient_account_id, e.recipient_device_id, e.ciphertext, e.olm_message_type, e.client_sent_at_ms, e.accepted_at_ms, a.username AS sender_username FROM envelopes e JOIN accounts a ON a.id = e.sender_account_id WHERE e.recipient_device_id = ? AND e.cursor > ? ORDER BY e.cursor LIMIT ?")
            .bind(device_id).bind(after as i64).bind(limit + 1).fetch_all(&self.pool).await?;
        let has_more = rows.len() as i64 > limit;
        let envelopes = rows
            .into_iter()
            .take(limit as usize)
            .map(stored_envelope_from_row)
            .collect();
        let status_rows = sqlx::query("SELECT cursor, logical_message_id, delivered_at_ms FROM delivery_updates WHERE account_id = ? AND cursor > ? ORDER BY cursor LIMIT 200")
            .bind(account_id).bind(status_after as i64).fetch_all(&self.pool).await?;
        let statuses = status_rows
            .into_iter()
            .map(|row| StoredDeliveryUpdate {
                cursor: row.get::<i64, _>("cursor") as u64,
                update: Some(DeliveryUpdate {
                    logical_message_id: row.get("logical_message_id"),
                    delivered_at_ms: row.get("delivered_at_ms"),
                }),
            })
            .collect();
        Ok((envelopes, statuses, has_more))
    }

    pub async fn ack(
        &self,
        device_id: &str,
        envelope_id: &str,
        now: i64,
    ) -> Result<Option<(String, String)>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE envelopes SET delivered_at_ms = COALESCE(delivered_at_ms, ?) WHERE envelope_id = ? AND recipient_device_id = ? RETURNING logical_message_id, sender_account_id")
            .bind(now).bind(envelope_id).bind(device_id).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let logical: String = row.get("logical_message_id");
        let sender: String = row.get("sender_account_id");
        sqlx::query("UPDATE logical_messages SET delivered_at_ms = COALESCE(delivered_at_ms, ?) WHERE logical_message_id = ?")
            .bind(now).bind(&logical).execute(&mut *tx).await?;
        sqlx::query("INSERT OR IGNORE INTO delivery_updates(account_id, logical_message_id, delivered_at_ms) VALUES(?, ?, ?)")
            .bind(&sender).bind(&logical).bind(now).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some((sender, logical)))
    }

    pub async fn insert_pairing_event(
        &self,
        pairing_id: &str,
        sender: &str,
        target: &str,
        event_type: &str,
        payload: &[u8],
        lifetime: (i64, i64),
    ) -> Result<u64> {
        let (now, expires_at_ms) = lifetime;
        let result = sqlx::query("INSERT INTO pairing_events(pairing_id, sender_device_id, target_device_id, event_type, payload, created_at_ms, expires_at_ms) VALUES(?, ?, ?, ?, ?, ?, ?)")
            .bind(pairing_id).bind(sender).bind(target).bind(event_type).bind(payload).bind(now)
            .bind(expires_at_ms).execute(&self.pool).await?;
        Ok(result.last_insert_rowid() as u64)
    }

    pub async fn pending_pairing_events(
        &self,
        target: &str,
        now: i64,
    ) -> Result<Vec<PendingPairingEvent>> {
        let rows = sqlx::query("SELECT id, pairing_id, sender_device_id, event_type, payload FROM pairing_events WHERE target_device_id = ? AND consumed_at_ms IS NULL AND expires_at_ms > ? ORDER BY id LIMIT 200")
            .bind(target).bind(now).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| PendingPairingEvent {
                id: row.get::<i64, _>("id") as u64,
                pairing_id: row.get("pairing_id"),
                sender_device_id: row.get("sender_device_id"),
                event_type: row.get("event_type"),
                payload: row.get("payload"),
            })
            .collect())
    }

    pub async fn ack_pairing_event(&self, target: &str, event_id: u64) -> Result<bool> {
        let affected =
            sqlx::query("DELETE FROM pairing_events WHERE id = ? AND target_device_id = ?")
                .bind(event_id as i64)
                .bind(target)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(affected == 1)
    }

    pub async fn cleanup_expired_pairing_events(&self, now: i64) -> Result<u64> {
        Ok(
            sqlx::query("DELETE FROM pairing_events WHERE expires_at_ms <= ?")
                .bind(now)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    pub async fn audit(
        &self,
        category: &str,
        actor: &str,
        action: &str,
        target: &str,
        result: &str,
        context: (Option<&str>, &str),
    ) -> Result<()> {
        let (source_ip, details) = context;
        sqlx::query("INSERT INTO audit_events(occurred_at_ms, category, actor, action, target, result, source_ip, details) VALUES(?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(chrono::Utc::now().timestamp_millis())
            .bind(category).bind(actor).bind(action).bind(target).bind(result)
            .bind(source_ip).bind(details).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn cleanup_audit(&self, before_ms: i64) -> Result<u64> {
        Ok(
            sqlx::query("DELETE FROM audit_events WHERE occurred_at_ms < ?")
                .bind(before_ms)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    pub async fn activate_device(
        &self,
        account_id: &str,
        device_id: &str,
        revision: u64,
        certificate_signature: &[u8],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let current: i64 = sqlx::query_scalar("SELECT roster_revision FROM accounts WHERE id = ?")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await?;
        if revision != current as u64 + 1 {
            bail!("roster revision conflict");
        }
        let affected = sqlx::query("UPDATE devices SET pending = 0, certificate_signature = ? WHERE account_id = ? AND id = ? AND pending = 1")
            .bind(certificate_signature).bind(account_id).bind(device_id)
            .execute(&mut *tx).await?.rows_affected();
        if affected != 1 {
            bail!("pending device not found");
        }
        sqlx::query("UPDATE accounts SET roster_revision = ? WHERE id = ?")
            .bind(revision as i64)
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn pending_devices(&self, account_id: &str) -> Result<Vec<(DeviceBundle, Vec<u8>)>> {
        let rows = sqlx::query("SELECT id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, revoked, sas_public_key FROM devices WHERE account_id = ? AND pending = 1 AND revoked = 0")
            .bind(account_id).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let sas = row.get("sas_public_key");
                (device_bundle_from_row(row), sas)
            })
            .collect())
    }
}

#[cfg(unix)]
async fn harden_parent_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn harden_parent_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn account_from_row(row: sqlx::sqlite::SqliteRow) -> Account {
    Account {
        id: row.get("id"),
        username: row.get("username"),
        password_phc: row.get("password_phc"),
        state: row.get("state"),
        require_password_change: row.get::<i64, _>("require_password_change") != 0,
        master_public_key: row.get("master_public_key"),
        roster_revision: row.get::<i64, _>("roster_revision") as u64,
    }
}

fn device_bundle_from_row(row: sqlx::sqlite::SqliteRow) -> DeviceBundle {
    DeviceBundle {
        device_id: row.get("id"),
        device_name: row.get("name"),
        auth_signing_key: row.get("auth_signing_key"),
        olm_ed25519_key: row.get("olm_ed25519_key"),
        olm_curve25519_key: row.get("olm_curve25519_key"),
        certificate_signature: row.get("certificate_signature"),
        revoked: row.get::<i64, _>("revoked") != 0,
    }
}

fn stored_envelope_from_row(row: sqlx::sqlite::SqliteRow) -> StoredEnvelope {
    StoredEnvelope {
        cursor: row.get::<i64, _>("cursor") as u64,
        sender_account_id: row.get("sender_account_id"),
        sender_device_id: row.get("sender_device_id"),
        envelope: Some(EncryptedEnvelope {
            envelope_id: row.get("envelope_id"),
            logical_message_id: row.get("logical_message_id"),
            conversation_id: row.get("conversation_id"),
            recipient_account_id: row.get("recipient_account_id"),
            recipient_device_id: row.get("recipient_device_id"),
            ciphertext: row.get("ciphertext"),
            olm_message_type: row.get::<i64, _>("olm_message_type") as u32,
            client_sent_at_ms: row.get("client_sent_at_ms"),
        }),
        accepted_at_ms: row.get("accepted_at_ms"),
        sender_username: row.get("sender_username"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};
    use tui_chat_protocol::v1::EncryptedEnvelope;

    fn unlimited_storage() -> StorageLimits {
        StorageLimits {
            max_account_ciphertext_bytes: u64::MAX,
            max_total_ciphertext_bytes: u64::MAX,
            min_free_disk_bytes: 0,
        }
    }

    async fn populated_db() -> Result<(TempDir, Db, i64)> {
        let directory = tempdir()?;
        let db = Db::connect(&directory.path().join("server.db")).await?;
        let now = 1_700_000_000_000_i64;
        for (id, username) in [("account-a", "alice"), ("account-b", "bob")] {
            sqlx::query("INSERT INTO accounts(id, username, password_phc, master_public_key, created_at_ms) VALUES(?, ?, 'hash', ?, ?)")
                .bind(id).bind(username).bind(vec![1_u8; 32]).bind(now).execute(db.pool()).await?;
        }
        for (id, account) in [("device-a", "account-a"), ("device-b", "account-b")] {
            sqlx::query("INSERT INTO devices(id, account_id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, created_at_ms) VALUES(?, ?, 'test', ?, ?, ?, ?, ?)")
                .bind(id).bind(account).bind(vec![2_u8; 32]).bind(vec![3_u8; 32]).bind(vec![4_u8; 32]).bind(vec![5_u8; 64]).bind(now).execute(db.pool()).await?;
        }
        Ok((directory, db, now))
    }

    fn envelope(id: &str, logical_id: &str, ciphertext: Vec<u8>, now: i64) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_id: id.to_owned(),
            logical_message_id: logical_id.to_owned(),
            conversation_id: tui_chat_protocol::conversation_id("account-a", "account-b"),
            recipient_account_id: "account-b".into(),
            recipient_device_id: "device-b".into(),
            ciphertext,
            olm_message_type: 0,
            client_sent_at_ms: now,
        }
    }

    #[tokio::test]
    async fn envelopes_are_durable_idempotent_and_acknowledged() -> Result<()> {
        let (_directory, db, now) = populated_db().await?;
        let envelope = envelope("envelope-1", "message-1", vec![9, 8, 7], now);
        db.store_envelopes(
            "account-a",
            "device-a",
            std::slice::from_ref(&envelope),
            now,
            unlimited_storage(),
        )
        .await?;
        db.store_envelopes(
            "account-a",
            "device-a",
            std::slice::from_ref(&envelope),
            now + 1,
            unlimited_storage(),
        )
        .await?;
        let mut conflicting = envelope.clone();
        conflicting.ciphertext = vec![1, 2, 3];
        assert!(
            db.store_envelopes(
                "account-a",
                "device-a",
                std::slice::from_ref(&conflicting),
                now + 2,
                unlimited_storage(),
            )
            .await
            .is_err()
        );
        let (stored, _, more) = db.sync("account-b", "device-b", 0, 0, 100).await?;
        assert_eq!(stored.len(), 1);
        assert!(!more);
        db.ack("device-b", "envelope-1", now + 2).await?;
        let (_, updates, _) = db.sync("account-a", "device-a", 0, 0, 100).await?;
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0]
                .update
                .as_ref()
                .map(|update| update.logical_message_id.as_str()),
            Some("message-1")
        );
        Ok(())
    }

    #[tokio::test]
    async fn ciphertext_quota_is_transactional_and_idempotent() -> Result<()> {
        let (_directory, db, now) = populated_db().await?;
        let limits = StorageLimits {
            max_account_ciphertext_bytes: 3,
            max_total_ciphertext_bytes: 100,
            min_free_disk_bytes: 0,
        };
        let first = envelope("envelope-1", "message-1", vec![1, 2, 3], now);
        db.store_envelopes(
            "account-a",
            "device-a",
            std::slice::from_ref(&first),
            now,
            limits,
        )
        .await?;
        db.store_envelopes(
            "account-a",
            "device-a",
            std::slice::from_ref(&first),
            now + 1,
            limits,
        )
        .await?;

        let second = envelope("envelope-2", "message-2", vec![4], now + 2);
        let error = db
            .store_envelopes(
                "account-a",
                "device-a",
                std::slice::from_ref(&second),
                now + 2,
                limits,
            )
            .await
            .expect_err("the account quota must reject additional ciphertext");
        assert!(matches!(
            error.downcast_ref::<StorageRejection>(),
            Some(StorageRejection::AccountQuota)
        ));
        assert_eq!(db.storage_status(limits).await?.ciphertext_bytes, 3);
        assert!(db.stored_envelope("envelope-2").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_delivered_ciphertext() -> Result<()> {
        let (_directory, db, now) = populated_db().await?;
        let delivered = envelope("envelope-1", "message-1", vec![1, 2, 3], now);
        let pending = envelope("envelope-2", "message-2", vec![4, 5], now + 1);
        for item in [&delivered, &pending] {
            db.store_envelopes(
                "account-a",
                "device-a",
                std::slice::from_ref(item),
                now,
                unlimited_storage(),
            )
            .await?;
        }
        db.ack("device-b", "envelope-1", now + 2).await?;

        let stats = db.cleanup_delivered_envelopes(now + 3, 100).await?;
        assert_eq!(stats.envelopes, 1);
        assert_eq!(stats.ciphertext_bytes, 3);
        assert!(db.stored_envelope("envelope-1").await?.is_none());
        assert!(db.stored_envelope("envelope-2").await?.is_some());
        assert_eq!(
            db.storage_status(unlimited_storage())
                .await?
                .ciphertext_bytes,
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn self_service_revoke_is_account_scoped_and_cleans_queued_data() -> Result<()> {
        let (_directory, db, now) = populated_db().await?;
        let queued = envelope("envelope-1", "message-1", vec![1, 2, 3], now);
        db.store_envelopes(
            "account-a",
            "device-a",
            std::slice::from_ref(&queued),
            now,
            unlimited_storage(),
        )
        .await?;

        assert!(!db.revoke_own_device("account-a", "device-b").await?);
        assert!(db.revoke_own_device("account-b", "device-b").await?);
        assert!(db.stored_envelope("envelope-1").await?.is_none());
        let devices = db.own_devices("account-b").await?;
        assert_eq!(devices.len(), 1);
        assert!(devices[0].revoked);
        assert_eq!(
            db.storage_status(unlimited_storage())
                .await?
                .ciphertext_bytes,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoked_device_copies_do_not_block_an_active_peer() -> Result<()> {
        let (_directory, db, now) = populated_db().await?;
        sqlx::query("INSERT INTO devices(id, account_id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, revoked, created_at_ms) VALUES('device-old', 'account-a', 'old', ?, ?, ?, ?, 1, ?)")
            .bind(vec![2_u8; 32]).bind(vec![3_u8; 32]).bind(vec![4_u8; 32])
            .bind(vec![5_u8; 64]).bind(now).execute(db.pool()).await?;
        let peer = envelope("envelope-peer", "message-1", vec![1, 2, 3], now);
        let mut stale_self_copy = envelope("envelope-old", "message-1", vec![4, 5], now);
        stale_self_copy.recipient_account_id = "account-a".into();
        stale_self_copy.recipient_device_id = "device-old".into();

        let stored = db
            .store_envelopes(
                "account-a",
                "device-a",
                &[peer, stale_self_copy],
                now,
                unlimited_storage(),
            )
            .await?;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "device-b");
        assert!(db.stored_envelope("envelope-old").await?.is_none());

        assert!(db.revoke_own_device("account-b", "device-b").await?);
        let mut self_only = envelope("envelope-self", "message-2", vec![9], now + 1);
        self_only.recipient_account_id = "account-a".into();
        self_only.recipient_device_id = "device-a".into();
        let stale_peer = envelope("envelope-stale-peer", "message-2", vec![8], now + 1);
        assert!(
            db.store_envelopes(
                "account-a",
                "device-a",
                &[self_only, stale_peer],
                now + 1,
                unlimited_storage(),
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn empty_accounts_have_zero_device_counts() -> Result<()> {
        let directory = tempdir()?;
        let db = Db::connect(&directory.path().join("server.db")).await?;
        assert_eq!(db.device_counts("missing-account").await?, (0, 0));
        Ok(())
    }
}
