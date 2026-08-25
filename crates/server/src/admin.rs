use std::{io::Write as _, path::Path};

use anyhow::{Context, Result, bail};
use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use rand::{Rng, distributions::Alphanumeric};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    control::{AdminRequest, AdminSnapshot, request as control_request},
    db::Db,
};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Table => formatter.write_str("table"),
            Self::Json => formatter.write_str("json"),
        }
    }
}

pub fn normalize_username(username: &str) -> Result<String> {
    let username = username.to_ascii_lowercase();
    if !(3..=32).contains(&username.len())
        || !username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
    {
        bail!("username must be 3-32 ASCII characters: a-z, 0-9, _, ., -");
    }
    Ok(username)
}

pub fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < 12 || password.len() > 1024 {
        bail!("password must contain 12-1024 characters");
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    validate_password(password)?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .to_string())
}

pub async fn add_user(db: &Db, username: &str, generate: bool) -> Result<()> {
    let username = normalize_username(username)?;
    let password = if generate {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect()
    } else {
        let first = rpassword::prompt_password("Initial password: ")?;
        let second = rpassword::prompt_password("Repeat password: ")?;
        if first != second {
            bail!("passwords do not match");
        }
        first
    };
    let phc = hash_password(&password)?;
    sqlx::query(
        "INSERT INTO accounts(id, username, password_phc, created_at_ms) VALUES(?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&username)
    .bind(phc)
    .bind(chrono::Utc::now().timestamp_millis())
    .execute(db.pool())
    .await
    .context("failed to create account")?;
    db.audit(
        "admin",
        "local-admin",
        "user_add",
        &username,
        "success",
        (None, ""),
    )
    .await?;
    println!("created account {username}");
    if generate {
        println!("one-time password: {password}");
    }
    Ok(())
}

pub async fn list_users(db: &Db, output: OutputFormat) -> Result<()> {
    let rows = sqlx::query("SELECT username, state, require_password_change, identity_generation, roster_revision FROM accounts ORDER BY username")
        .fetch_all(db.pool()).await?;
    if matches!(output, OutputFormat::Json) {
        let values: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "username": row.get::<String, _>("username"),
                    "state": row.get::<String, _>("state"),
                    "password_change_required": row.get::<i64, _>("require_password_change") != 0,
                    "identity_generation": row.get::<i64, _>("identity_generation"),
                    "roster_revision": row.get::<i64, _>("roster_revision"),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&values)?);
        return Ok(());
    }
    for row in rows {
        println!(
            "{}\t{}\tpassword_change={}\tidentity={}\troster={}",
            row.get::<String, _>("username"),
            row.get::<String, _>("state"),
            row.get::<i64, _>("require_password_change") != 0,
            row.get::<i64, _>("identity_generation"),
            row.get::<i64, _>("roster_revision")
        );
    }
    Ok(())
}

pub async fn set_user_state(db: &Db, username: &str, state: &str) -> Result<()> {
    let username = normalize_username(username)?;
    let affected = sqlx::query("UPDATE accounts SET state = ? WHERE username = ? COLLATE NOCASE")
        .bind(state)
        .bind(&username)
        .execute(db.pool())
        .await?
        .rows_affected();
    if affected != 1 {
        bail!("account not found");
    }
    db.audit(
        "admin",
        "local-admin",
        "user_state",
        &username,
        "success",
        (None, state),
    )
    .await?;
    println!("{username}: {state}");
    Ok(())
}

pub async fn reset_password(db: &Db, username: &str, generate: bool) -> Result<()> {
    let username = normalize_username(username)?;
    let password = if generate {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect()
    } else {
        let first = rpassword::prompt_password("New password: ")?;
        let second = rpassword::prompt_password("Repeat password: ")?;
        if first != second {
            bail!("passwords do not match");
        }
        first
    };
    let phc = hash_password(&password)?;
    let affected = sqlx::query("UPDATE accounts SET password_phc = ?, require_password_change = 1 WHERE username = ? COLLATE NOCASE")
        .bind(phc).bind(&username).execute(db.pool()).await?.rows_affected();
    if affected != 1 {
        bail!("account not found");
    }
    db.audit(
        "admin",
        "local-admin",
        "password_reset",
        &username,
        "success",
        (None, ""),
    )
    .await?;
    println!("reset password for {username}; encrypted history and device keys were not changed");
    if generate {
        println!("one-time password: {password}");
    }
    Ok(())
}

pub async fn reset_devices(db: &Db, username: &str) -> Result<()> {
    let username = normalize_username(username)?;
    let mut tx = db.pool().begin().await?;
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE username = ? COLLATE NOCASE")
            .bind(&username)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(account_id) = account_id else {
        bail!("account not found");
    };
    sqlx::query("UPDATE devices SET revoked = 1 WHERE account_id = ?")
        .bind(&account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM prekeys WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?)",
    )
    .bind(&account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE accounts SET master_public_key = NULL, identity_generation = identity_generation + 1, roster_revision = 0 WHERE id = ?")
        .bind(&account_id).execute(&mut *tx).await?;
    tx.commit().await?;
    db.audit(
        "admin",
        "local-admin",
        "device_generation_reset",
        &username,
        "success",
        (None, ""),
    )
    .await?;
    println!("reset encrypted identity for {username}; old history is intentionally unrecoverable");
    Ok(())
}

pub async fn list_devices(db: &Db, username: &str, output: OutputFormat) -> Result<()> {
    let Some(account) = db.account_by_username(username).await? else {
        bail!("account not found");
    };
    let rows = sqlx::query("SELECT id, name, pending, revoked, created_at_ms FROM devices WHERE account_id = ? ORDER BY created_at_ms")
        .bind(account.id).fetch_all(db.pool()).await?;
    if matches!(output, OutputFormat::Json) {
        let values: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "device_id": row.get::<String, _>("id"),
                    "name": row.get::<String, _>("name"),
                    "pending": row.get::<i64, _>("pending") != 0,
                    "revoked": row.get::<i64, _>("revoked") != 0,
                    "created_at_ms": row.get::<i64, _>("created_at_ms"),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&values)?);
        return Ok(());
    }
    for row in rows {
        println!(
            "{}\t{}\tpending={}\trevoked={}\tcreated={}",
            row.get::<String, _>("id"),
            row.get::<String, _>("name"),
            row.get::<i64, _>("pending") != 0,
            row.get::<i64, _>("revoked") != 0,
            row.get::<i64, _>("created_at_ms")
        );
    }
    Ok(())
}

pub async fn revoke_device(db: &Db, username: &str, device_id: &str) -> Result<()> {
    let Some(account) = db.account_by_username(username).await? else {
        bail!("account not found");
    };
    let affected = sqlx::query("UPDATE devices SET revoked = 1 WHERE account_id = ? AND id = ?")
        .bind(account.id)
        .bind(device_id)
        .execute(db.pool())
        .await?
        .rows_affected();
    if affected != 1 {
        bail!("device not found");
    }
    db.audit(
        "admin",
        "local-admin",
        "device_revoke",
        device_id,
        "success",
        (None, &account.username),
    )
    .await?;
    println!("revoked {device_id}; clients will reject it on their next roster refresh");
    Ok(())
}

pub async fn backup(db: &Db, path: &Path) -> Result<()> {
    if path.exists() {
        bail!("backup target already exists: {}", path.display());
    }
    let escaped = path.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{escaped}'"))
        .execute(db.pool())
        .await?;
    db.audit(
        "admin",
        "local-admin",
        "database_backup",
        &path.display().to_string(),
        "success",
        (None, ""),
    )
    .await?;
    println!("wrote consistent SQLite backup to {}", path.display());
    Ok(())
}

pub async fn check(db: &Db) -> Result<()> {
    let result: String = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_one(db.pool())
        .await?;
    if result != "ok" {
        bail!("database check failed: {result}");
    }
    println!("database check: ok");
    Ok(())
}

pub async fn checkpoint(db: &Db) -> Result<()> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(db.pool())
        .await?;
    println!("database WAL checkpoint completed");
    Ok(())
}

async fn snapshot(socket: &Path) -> Result<AdminSnapshot> {
    let response = control_request(socket, &AdminRequest::Snapshot).await?;
    if !response.ok {
        bail!(response.message);
    }
    response
        .snapshot
        .ok_or_else(|| anyhow::anyhow!("admin server returned no snapshot"))
}

pub async fn list_sessions(socket: &Path, output: OutputFormat) -> Result<()> {
    let sessions = snapshot(socket).await?.sessions;
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }
    for session in sessions {
        println!(
            "{}\t{}\t{}\t{}\tpending={}\tconnected={}\tlast_seen={}",
            session.session_id,
            session.username,
            session.device_id,
            session.source_ip,
            session.pending,
            session.connected_at_ms,
            session.last_seen_at_ms
        );
    }
    Ok(())
}

pub async fn kick_session(socket: &Path, session_id: Uuid) -> Result<()> {
    let response = control_request(socket, &AdminRequest::KickSession { session_id }).await?;
    if !response.ok {
        bail!(response.message);
    }
    println!("{}", response.message);
    Ok(())
}

pub async fn disconnect_user_if_online(
    db: &Db,
    socket: &Path,
    username: &str,
    reason: &str,
) -> Result<()> {
    let Some(account) = db.account_by_username(username).await? else {
        return Ok(());
    };
    if tokio::fs::try_exists(socket).await.unwrap_or(false) {
        let _ = control_request(
            socket,
            &AdminRequest::KickAccount {
                account_id: account.id,
                reason: reason.to_owned(),
            },
        )
        .await;
    }
    Ok(())
}

pub async fn disconnect_device_if_online(socket: &Path, device_id: &str) {
    if tokio::fs::try_exists(socket).await.unwrap_or(false) {
        let _ = control_request(
            socket,
            &AdminRequest::KickDevice {
                device_id: device_id.to_owned(),
                reason: "access_revoked".to_owned(),
            },
        )
        .await;
    }
}

pub async fn list_conversations(socket: &Path, output: OutputFormat) -> Result<()> {
    let conversations = snapshot(socket).await?.conversations;
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&conversations)?);
        return Ok(());
    }
    for conversation in conversations {
        println!(
            "{}\t{} <-> {}\tmessages={}\tenvelopes={}\tbytes={}\tundelivered={}",
            conversation.conversation_id,
            conversation.first_username,
            conversation.second_username,
            conversation.logical_messages,
            conversation.envelopes,
            conversation.ciphertext_bytes,
            conversation.undelivered_envelopes
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct PrunePreview {
    logical_messages: u64,
    envelopes: u64,
    ciphertext_bytes: u64,
}

pub async fn prune_conversation(
    db: &Db,
    conversation_id: &str,
    before_ms: Option<i64>,
    delivered_only: bool,
    yes: bool,
) -> Result<()> {
    if conversation_id.len() != 64 || !conversation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("conversation id must contain 64 hexadecimal characters");
    }
    let cutoff = before_ms.unwrap_or(i64::MAX);
    let delivered = i64::from(delivered_only);
    let row = sqlx::query(
        "SELECT COUNT(DISTINCT lm.logical_message_id) logical_messages, COUNT(e.envelope_id) envelopes, COALESCE(SUM(length(e.ciphertext)), 0) ciphertext_bytes \
         FROM logical_messages lm LEFT JOIN envelopes e ON e.logical_message_id = lm.logical_message_id \
         WHERE lm.conversation_id = ? AND lm.accepted_at_ms < ? AND \
         (? = 0 OR NOT EXISTS (SELECT 1 FROM envelopes pending WHERE pending.logical_message_id = lm.logical_message_id AND pending.delivered_at_ms IS NULL))",
    )
    .bind(conversation_id)
    .bind(cutoff)
    .bind(delivered)
    .fetch_one(db.pool())
    .await?;
    let preview = PrunePreview {
        logical_messages: row.get::<i64, _>("logical_messages") as u64,
        envelopes: row.get::<i64, _>("envelopes") as u64,
        ciphertext_bytes: row.get::<i64, _>("ciphertext_bytes") as u64,
    };
    println!("{}", serde_json::to_string_pretty(&preview)?);
    if !yes {
        println!("dry-run only; repeat with --yes to delete these records");
        return Ok(());
    }
    let mut tx = db.pool().begin().await?;
    sqlx::query("DELETE FROM delivery_updates WHERE logical_message_id IN (SELECT lm.logical_message_id FROM logical_messages lm WHERE lm.conversation_id = ? AND lm.accepted_at_ms < ? AND (? = 0 OR NOT EXISTS (SELECT 1 FROM envelopes pending WHERE pending.logical_message_id = lm.logical_message_id AND pending.delivered_at_ms IS NULL)))")
        .bind(conversation_id).bind(cutoff).bind(delivered).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM envelopes WHERE logical_message_id IN (SELECT lm.logical_message_id FROM logical_messages lm WHERE lm.conversation_id = ? AND lm.accepted_at_ms < ? AND (? = 0 OR NOT EXISTS (SELECT 1 FROM envelopes pending WHERE pending.logical_message_id = lm.logical_message_id AND pending.delivered_at_ms IS NULL)))")
        .bind(conversation_id).bind(cutoff).bind(delivered).execute(&mut *tx).await?;
    sqlx::query(
        "DELETE FROM logical_messages WHERE conversation_id = ? AND accepted_at_ms < ? \
         AND NOT EXISTS (SELECT 1 FROM envelopes e WHERE e.logical_message_id = logical_messages.logical_message_id)",
    )
    .bind(conversation_id)
    .bind(cutoff)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    db.audit(
        "admin",
        "local-admin",
        "prune_conversation",
        conversation_id,
        "success",
        (None, &serde_json::to_string(&preview)?),
    )
    .await?;
    println!("conversation ciphertext pruned");
    Ok(())
}

pub async fn list_audit(db: &Db, limit: u32, output: OutputFormat) -> Result<()> {
    let limit = limit.clamp(1, 1000) as i64;
    let rows = sqlx::query("SELECT id, occurred_at_ms, category, actor, action, target, result, source_ip, details FROM audit_events ORDER BY id DESC LIMIT ?")
        .bind(limit).fetch_all(db.pool()).await?;
    let values: Vec<_> = rows.iter().map(|row| serde_json::json!({
        "id": row.get::<i64, _>("id"), "occurred_at_ms": row.get::<i64, _>("occurred_at_ms"),
        "category": row.get::<String, _>("category"), "actor": row.get::<String, _>("actor"),
        "action": row.get::<String, _>("action"), "target": row.get::<String, _>("target"),
        "result": row.get::<String, _>("result"), "source_ip": row.get::<Option<String>, _>("source_ip"),
        "details": row.get::<String, _>("details")
    })).collect();
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&values)?);
    } else {
        for value in values {
            println!("{}", serde_json::to_string(&value)?);
        }
    }
    Ok(())
}

pub async fn delete_user(
    db: &Db,
    admin_socket: &Path,
    username: &str,
    backup: &Path,
    yes: bool,
) -> Result<()> {
    let username = normalize_username(username)?;
    if !backup.is_file() {
        bail!("an existing database backup file is required before deletion");
    }
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE username = ? COLLATE NOCASE")
            .bind(&username)
            .fetch_optional(db.pool())
            .await?;
    let Some(account_id) = account_id else {
        bail!("account not found");
    };
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE account_id = ?")
        .bind(&account_id)
        .fetch_one(db.pool())
        .await?;
    let messages: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM logical_messages WHERE sender_account_id = ? OR peer_account_id = ?",
    )
    .bind(&account_id)
    .bind(&account_id)
    .fetch_one(db.pool())
    .await?;
    println!("delete preview: user={username} devices={devices} logical_messages={messages}");
    if !yes {
        println!("dry-run only; repeat with --yes and type the username to confirm");
        return Ok(());
    }
    print!("Type {username} to permanently delete this account: ");
    std::io::stdout().flush()?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != username {
        bail!("delete confirmation did not match");
    }
    disconnect_user_if_online(db, admin_socket, &username, "account_deleted").await?;
    delete_user_records(db, &account_id).await?;
    db.audit(
        "admin",
        "local-admin",
        "user_delete",
        &username,
        "success",
        (
            None,
            &format!("devices={devices},logical_messages={messages}"),
        ),
    )
    .await?;
    println!("deleted account {username}");
    Ok(())
}

async fn delete_user_records(db: &Db, account_id: &str) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    sqlx::query(
        "DELETE FROM pairing_events
         WHERE sender_device_id IN (SELECT id FROM devices WHERE account_id = ?)
            OR target_device_id IN (SELECT id FROM devices WHERE account_id = ?)",
    )
    .bind(account_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM delivery_updates
         WHERE account_id = ?
            OR logical_message_id IN (
                SELECT logical_message_id FROM logical_messages
                WHERE sender_account_id = ? OR peer_account_id = ?
            )",
    )
    .bind(account_id)
    .bind(account_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM envelopes
         WHERE sender_account_id = ? OR recipient_account_id = ?
            OR logical_message_id IN (
                SELECT logical_message_id FROM logical_messages
                WHERE sender_account_id = ? OR peer_account_id = ?
            )",
    )
    .bind(account_id)
    .bind(account_id)
    .bind(account_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM logical_messages WHERE sender_account_id = ? OR peer_account_id = ?")
        .bind(account_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM prekeys WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?)",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM devices WHERE account_id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deleting_user_removes_related_data_but_keeps_other_account() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = Db::connect(&directory.path().join("server.db")).await?;
        for (id, username) in [("account-a", "alice"), ("account-b", "bob")] {
            sqlx::query("INSERT INTO accounts(id, username, password_phc, created_at_ms) VALUES(?, ?, 'hash', 1)")
                .bind(id)
                .bind(username)
                .execute(db.pool())
                .await?;
        }
        for (id, account_id) in [("device-a", "account-a"), ("device-b", "account-b")] {
            sqlx::query("INSERT INTO devices(id, account_id, name, auth_signing_key, olm_ed25519_key, olm_curve25519_key, certificate_signature, created_at_ms) VALUES(?, ?, 'test', X'01', X'02', X'03', X'04', 1)")
                .bind(id)
                .bind(account_id)
                .execute(db.pool())
                .await?;
        }
        sqlx::query("INSERT INTO prekeys(device_id, key_id, curve25519_key, signature, created_at_ms) VALUES('device-a', 'key-a', X'05', X'06', 1)")
            .execute(db.pool())
            .await?;
        sqlx::query("INSERT INTO logical_messages(logical_message_id, sender_account_id, sender_device_id, peer_account_id, conversation_id, client_sent_at_ms, accepted_at_ms) VALUES('message-a', 'account-a', 'device-a', 'account-b', 'conversation-a-b', 1, 1)")
            .execute(db.pool())
            .await?;
        sqlx::query("INSERT INTO envelopes(envelope_id, logical_message_id, sender_account_id, sender_device_id, recipient_account_id, recipient_device_id, conversation_id, ciphertext, olm_message_type, client_sent_at_ms, accepted_at_ms) VALUES('envelope-a', 'message-a', 'account-a', 'device-a', 'account-b', 'device-b', 'conversation-a-b', X'07', 0, 1, 1)")
            .execute(db.pool())
            .await?;
        sqlx::query("INSERT INTO delivery_updates(account_id, logical_message_id, delivered_at_ms) VALUES('account-a', 'message-a', 1)")
            .execute(db.pool())
            .await?;
        sqlx::query("INSERT INTO pairing_events(pairing_id, sender_device_id, target_device_id, event_type, payload, created_at_ms) VALUES('pairing-a', 'device-a', 'device-b', 'request', X'08', 1)")
            .execute(db.pool())
            .await?;

        delete_user_records(&db, "account-a").await?;

        let alice: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = 'account-a'")
            .fetch_one(db.pool())
            .await?;
        let bob: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = 'account-b'")
            .fetch_one(db.pool())
            .await?;
        assert_eq!(alice, 0);
        assert_eq!(bob, 1);
        for table in [
            "devices",
            "prekeys",
            "logical_messages",
            "envelopes",
            "delivery_updates",
            "pairing_events",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(db.pool())
                .await?;
            if table == "devices" {
                assert_eq!(count, 1, "the other account's device should remain");
            } else {
                assert_eq!(
                    count, 0,
                    "{table} should no longer reference the deleted account"
                );
            }
        }
        Ok(())
    }
}
