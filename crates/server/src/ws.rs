use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use argon2::{PasswordHash, PasswordVerifier};
use axum::{
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, watch};
use tracing::debug;
use tui_chat_protocol::{
    CAPABILITY_OWN_DEVICES, CAPABILITY_STABLE_ERRORS, PROTOCOL_VERSION, auth_challenge_payload,
    decode_frame, device_certificate_payload, encode_frame, frame,
    v1::{
        self, AuthChallenge, Authenticated, DeliveryUpdate, DeviceBundle, Error as ErrorFrame,
        PairingEvent, PairingRequest, PreKeyBundle, SendAccepted, SyncBatch, UserBundle,
        frame::Body,
    },
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    admin::{
        hash_password, normalize_username, password_hasher, password_needs_rehash,
        validate_password,
    },
    config::Config,
    db::{Account, Db},
};

pub struct AppState {
    pub(crate) db: Db,
    domain: String,
    connections: RwLock<HashMap<String, LiveConnection>>,
    sessions: RwLock<HashMap<Uuid, LiveSession>>,
    admission: Mutex<Admission>,
    auth_buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    auth_account_buckets: Mutex<HashMap<String, TokenBucket>>,
    auth_hash_gate: Arc<Semaphore>,
    config: Config,
    dummy_password_phc: String,
}

#[derive(Clone)]
struct LiveConnection {
    token: Uuid,
    account_id: String,
    tx: mpsc::Sender<v1::Frame>,
    disconnect: watch::Sender<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LiveSession {
    pub id: Uuid,
    pub account_id: String,
    pub username: String,
    pub device_id: String,
    pub source_ip: IpAddr,
    pub connected_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub pending: bool,
    #[serde(skip)]
    disconnect: watch::Sender<Option<String>>,
}

#[derive(Default)]
struct Admission {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
    unauthenticated_by_ip: HashMap<IpAddr, usize>,
}

struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            updated: Instant::now(),
        }
    }

    fn take(&mut self, per_minute: u32, burst: u32) -> bool {
        self.take_rate(f64::from(per_minute) / 60.0, burst)
    }

    fn take_rate(&mut self, tokens_per_second: f64, burst: u32) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * tokens_per_second)
            .min(f64::from(burst));
        self.updated = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Result<Self> {
        let dummy_password_phc = hash_password("invalid-account-dummy-password")?;
        Ok(Self {
            db,
            domain: config.public_domain.clone(),
            connections: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            admission: Mutex::new(Admission::default()),
            auth_buckets: Mutex::new(HashMap::new()),
            auth_account_buckets: Mutex::new(HashMap::new()),
            auth_hash_gate: Arc::new(Semaphore::new(config.auth_hash_concurrency)),
            config,
            dummy_password_phc,
        })
    }

    async fn admit(&self, ip: IpAddr) -> bool {
        let mut admission = self.admission.lock().await;
        if admission.total >= self.config.max_connections
            || admission.by_ip.get(&ip).copied().unwrap_or(0) >= self.config.max_connections_per_ip
            || admission
                .unauthenticated_by_ip
                .get(&ip)
                .copied()
                .unwrap_or(0)
                >= self.config.max_unauthenticated_per_ip
        {
            return false;
        }
        admission.total += 1;
        *admission.by_ip.entry(ip).or_default() += 1;
        *admission.unauthenticated_by_ip.entry(ip).or_default() += 1;
        true
    }

    async fn mark_authenticated(&self, ip: IpAddr) {
        let mut admission = self.admission.lock().await;
        decrement_count(&mut admission.unauthenticated_by_ip, ip);
    }

    async fn release(&self, ip: IpAddr, still_unauthenticated: bool) {
        let mut admission = self.admission.lock().await;
        admission.total = admission.total.saturating_sub(1);
        decrement_count(&mut admission.by_ip, ip);
        if still_unauthenticated {
            decrement_count(&mut admission.unauthenticated_by_ip, ip);
        }
    }

    async fn register(
        &self,
        session: &Session,
        token: Uuid,
        tx: mpsc::Sender<v1::Frame>,
        disconnect: watch::Sender<Option<String>>,
        source_ip: IpAddr,
    ) {
        let live = LiveConnection {
            token,
            account_id: session.account.id.clone(),
            tx,
            disconnect: disconnect.clone(),
        };
        if let Some(previous) = self
            .connections
            .write()
            .await
            .insert(session.device_id.clone(), live)
        {
            let _ = previous
                .disconnect
                .send(Some("session_replaced".to_owned()));
        }
        self.sessions.write().await.insert(
            token,
            LiveSession {
                id: token,
                account_id: session.account.id.clone(),
                username: session.account.username.clone(),
                device_id: session.device_id.clone(),
                source_ip,
                connected_at_ms: now_ms(),
                last_seen_at_ms: now_ms(),
                pending: session.pending,
                disconnect,
            },
        );
    }

    async fn unregister(&self, device: &str, token: Uuid) {
        let mut connections = self.connections.write().await;
        if connections
            .get(device)
            .is_some_and(|connection| connection.token == token)
        {
            connections.remove(device);
        }
        self.sessions.write().await.remove(&token);
    }

    async fn touch_session(&self, token: Uuid) {
        if let Some(session) = self.sessions.write().await.get_mut(&token) {
            session.last_seen_at_ms = now_ms();
        }
    }

    pub(crate) async fn live_sessions(&self) -> Vec<LiveSession> {
        let mut sessions: Vec<_> = self.sessions.read().await.values().cloned().collect();
        sessions.sort_by_key(|session| session.connected_at_ms);
        sessions
    }

    async fn online_devices(&self, account_id: &str) -> Vec<String> {
        self.connections
            .read()
            .await
            .iter()
            .filter(|(_, connection)| connection.account_id == account_id)
            .map(|(device_id, _)| device_id.clone())
            .collect()
    }

    pub(crate) async fn kick_session(&self, id: Uuid, reason: &str) -> bool {
        self.sessions
            .read()
            .await
            .get(&id)
            .is_some_and(|session| session.disconnect.send(Some(reason.to_owned())).is_ok())
    }

    pub(crate) async fn kick_account(&self, account_id: &str, reason: &str) -> usize {
        let ids: Vec<_> = self
            .sessions
            .read()
            .await
            .values()
            .filter(|session| session.account_id == account_id)
            .map(|session| session.id)
            .collect();
        let mut kicked = 0;
        for id in ids {
            kicked += usize::from(self.kick_session(id, reason).await);
        }
        kicked
    }

    pub(crate) async fn kick_device(&self, device_id: &str, reason: &str) -> bool {
        let connection = self.connections.read().await.get(device_id).cloned();
        connection
            .is_some_and(|connection| connection.disconnect.send(Some(reason.to_owned())).is_ok())
    }

    pub(crate) async fn run_maintenance_once(&self) -> Result<()> {
        let now = now_ms();
        self.db.cleanup_expired_pairing_events(now).await?;
        let retention_ms = i64::from(self.config.audit_retention_days) * 24 * 60 * 60 * 1000;
        self.db.cleanup_audit(now - retention_ms).await?;
        let delivered_retention_ms =
            i64::from(self.config.delivered_retention_days) * 24 * 60 * 60 * 1000;
        let cleaned = self
            .db
            .cleanup_delivered_envelopes(now - delivered_retention_ms, 1000)
            .await?;
        if cleaned.envelopes > 0 {
            tracing::info!(
                envelopes = cleaned.envelopes,
                ciphertext_bytes = cleaned.ciphertext_bytes,
                "expired delivered ciphertext cleaned"
            );
        }
        Ok(())
    }

    pub(crate) async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(self.db.pool())
            .await
            .is_ok()
    }

    async fn push_device(&self, device: &str, message: v1::Frame) {
        let tx = self
            .connections
            .read()
            .await
            .get(device)
            .map(|live| live.tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send(message).await;
        }
    }

    async fn push_account(&self, account: &str, message: v1::Frame) {
        let senders: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .filter(|live| live.account_id == account)
            .map(|live| live.tx.clone())
            .collect();
        for tx in senders {
            let _ = tx.send(message.clone()).await;
        }
    }
}

pub async fn upgrade(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if state.config.reject_websocket_origins && headers.contains_key("origin") {
        return (
            StatusCode::FORBIDDEN,
            "browser WebSocket origins are not accepted\n",
        )
            .into_response();
    }
    let trusted_proxy = state.config.is_trusted_proxy(peer.ip());
    if state.config.trusted_proxy_tls && !trusted_proxy {
        return (
            StatusCode::FORBIDDEN,
            "connection did not come from a trusted proxy\n",
        )
            .into_response();
    }
    if trusted_proxy
        && headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            != Some("https")
    {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "secure reverse proxy connection required\n",
        )
            .into_response();
    }
    let source_ip = if trusted_proxy {
        forwarded_ip(&headers).unwrap_or(peer.ip())
    } else {
        peer.ip()
    };
    if !state.admit(source_ip).await {
        return (StatusCode::TOO_MANY_REQUESTS, "connection limit exceeded\n").into_response();
    }
    ws.max_message_size(tui_chat_protocol::MAX_FRAME_BYTES)
        .max_frame_size(tui_chat_protocol::MAX_FRAME_BYTES)
        .on_upgrade(move |socket| connection(socket, state, source_ip))
}

#[derive(Clone)]
struct Challenge {
    username: String,
    device_id: String,
    nonce: Vec<u8>,
    expires_at_ms: i64,
    capabilities: Vec<String>,
}

struct ConnectionContext {
    token: Uuid,
    source_ip: IpAddr,
    disconnect: watch::Sender<Option<String>>,
}

#[derive(Clone)]
struct Session {
    account: Account,
    device_id: String,
    pending: bool,
    password_change_required: bool,
    capabilities: Vec<String>,
}

async fn connection(socket: WebSocket, state: Arc<AppState>, source_ip: IpAddr) {
    let token = Uuid::new_v4();
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<v1::Frame>(128);
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink
                .send(Message::Binary(encode_frame(&frame)))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let (disconnect_tx, mut disconnect_rx) = watch::channel::<Option<String>>(None);
    let context = ConnectionContext {
        token,
        source_ip,
        disconnect: disconnect_tx,
    };

    let mut challenge = None;
    let mut session: Option<Session> = None;
    let mut admitted_as_unauthenticated = true;
    let mut request_bucket = TokenBucket::new(state.config.request_burst);
    loop {
        let message = tokio::select! {
            changed = disconnect_rx.changed() => {
                if changed.is_ok() {
                    let reason = disconnect_rx.borrow().clone().unwrap_or_else(|| "session_closed".to_owned());
                    send_error(&tx, "", &reason, "session closed by server", true).await;
                }
                break;
            }
            message = tokio::time::timeout(Duration::from_secs(60), stream.next()) => match message {
                Ok(Some(message)) => message,
                Ok(None) | Err(_) => break,
            }
        };
        let data = match message {
            Ok(Message::Binary(data)) => data,
            Ok(Message::Ping(data)) => {
                let _ = tx
                    .send(frame(
                        "",
                        Body::Pong(v1::Pong {
                            sent_at_ms: i64::from(data.first().copied().unwrap_or(0)),
                        }),
                    ))
                    .await;
                continue;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => continue,
        };
        let incoming = match decode_frame(&data) {
            Ok(frame) if frame.protocol_version == PROTOCOL_VERSION => frame,
            Ok(_) => {
                send_error(
                    &tx,
                    "",
                    "unsupported_version",
                    "client and server protocol versions differ",
                    false,
                )
                .await;
                continue;
            }
            Err(error) => {
                send_error(&tx, "", "invalid_frame", &error.to_string(), false).await;
                continue;
            }
        };
        let request_id = incoming.id.clone();
        if request_id.len() > 64 {
            send_error(&tx, "", "invalid_frame", "request id is too long", false).await;
            break;
        }
        if !request_bucket.take(state.config.requests_per_minute, state.config.request_burst) {
            send_error(
                &tx,
                &request_id,
                "rate_limited",
                "request rate limit exceeded",
                true,
            )
            .await;
            break;
        }
        if let Some(active) = session.as_ref().filter(|session| !session.pending) {
            let account_active = state
                .db
                .account_by_username(&active.account.username)
                .await
                .ok()
                .flatten()
                .is_some_and(|account| account.state == "active");
            let device_active = state
                .db
                .device(&active.account.id, &active.device_id)
                .await
                .ok()
                .flatten()
                .is_some_and(|device| !device.pending && !device.revoked);
            if !account_active || !device_active {
                send_error(
                    &tx,
                    &request_id,
                    "access_revoked",
                    "account or device access was revoked",
                    false,
                )
                .await;
                break;
            }
        }
        if let Err(error) = handle_frame(
            &state,
            &tx,
            &context,
            incoming,
            &mut challenge,
            &mut session,
        )
        .await
        {
            debug!(%error, "request rejected");
            let public = public_error(&error);
            send_error(
                &tx,
                &request_id,
                public.code,
                public.message,
                public.retryable,
            )
            .await;
        }
        if admitted_as_unauthenticated && session.is_some() {
            state.mark_authenticated(source_ip).await;
            admitted_as_unauthenticated = false;
        }
        state.touch_session(token).await;
    }
    if let Some(session) = session {
        state.unregister(&session.device_id, token).await;
    }
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
    state.release(source_ip, admitted_as_unauthenticated).await;
}

async fn handle_frame(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<v1::Frame>,
    context: &ConnectionContext,
    incoming: v1::Frame,
    challenge_slot: &mut Option<Challenge>,
    session_slot: &mut Option<Session>,
) -> Result<()> {
    let token = context.token;
    let source_ip = context.source_ip;
    let disconnect = &context.disconnect;
    let request_id = incoming.id;
    let body = incoming.body.ok_or_else(|| anyhow!("empty frame"))?;

    match body {
        Body::ClientHello(hello) => {
            if session_slot.is_some() {
                bail!("connection is already authenticated");
            }
            let username = normalize_username(&hello.username)?;
            if !valid_uuid(&hello.device_id) {
                bail!("invalid device id");
            }
            if hello.capabilities.len() > 32
                || hello
                    .capabilities
                    .iter()
                    .any(|capability| capability.is_empty() || capability.len() > 64)
            {
                bail!("invalid client capabilities");
            }
            let mut nonce = vec![0_u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let expires_at_ms = now_ms() + 30_000;
            *challenge_slot = Some(Challenge {
                username,
                device_id: hello.device_id,
                nonce: nonce.clone(),
                expires_at_ms,
                capabilities: hello.capabilities,
            });
            tx.send(frame(
                request_id,
                Body::AuthChallenge(AuthChallenge {
                    nonce,
                    expires_at_ms,
                }),
            ))
            .await?;
        }
        Body::DeviceAuth(auth) => {
            if session_slot.is_some() {
                bail!("connection is already authenticated");
            }
            let challenge = take_valid_challenge(challenge_slot, &auth.username, &auth.device_id)?;
            let account = state
                .db
                .account_by_username(&challenge.username)
                .await?
                .ok_or_else(|| anyhow!("invalid credentials"))?;
            if account.state != "active" {
                bail!("invalid credentials");
            }
            let device = state
                .db
                .device(&account.id, &auth.device_id)
                .await?
                .ok_or_else(|| anyhow!("invalid credentials"))?;
            if device.pending || device.revoked {
                bail!("device is not active");
            }
            let payload = auth_challenge_payload(
                &state.domain,
                &account.username,
                &auth.device_id,
                &challenge.nonce,
                challenge.expires_at_ms,
            );
            verify_signature(&device.auth_signing_key, &payload, &auth.signature)?;
            state
                .db
                .record_device_authentication(&auth.device_id, now_ms())
                .await?;
            let session = Session {
                account: account.clone(),
                device_id: auth.device_id,
                pending: false,
                password_change_required: account.require_password_change,
                capabilities: challenge.capabilities,
            };
            state
                .register(&session, token, tx.clone(), disconnect.clone(), source_ip)
                .await;
            send_authenticated(tx, &request_id, &session).await?;
            push_post_auth(state, tx, &session).await?;
            let _ = state
                .db
                .audit(
                    "auth",
                    &account.username,
                    "device_auth",
                    &session.device_id,
                    "success",
                    (Some(&source_ip.to_string()), ""),
                )
                .await;
            *session_slot = Some(session);
        }
        Body::PasswordAuth(mut auth) => {
            if session_slot.is_some() {
                bail!("connection is already authenticated");
            }
            let challenge = take_valid_challenge(challenge_slot, &auth.username, &auth.device_id)?;
            if auth.password.is_empty() || auth.password.len() > 1024 {
                auth.password.zeroize();
                bail!("invalid credentials");
            }
            if !allow_password_attempt(state, source_ip, &challenge.username).await {
                auth.password.zeroize();
                bail!("too many authentication attempts; retry later");
            }
            let account = state.db.account_by_username(&challenge.username).await?;
            let phc = account
                .as_ref()
                .map(|account| account.password_phc.clone())
                .unwrap_or_else(|| state.dummy_password_phc.clone());
            let _permit = state
                .auth_hash_gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| anyhow!("authentication service unavailable"))?;
            let verification = verify_password(phc, auth.password.clone()).await;
            auth.password.zeroize();
            let Some(mut account) =
                account.filter(|account| verification.valid && account.state == "active")
            else {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = state
                    .db
                    .audit(
                        "auth",
                        &challenge.username,
                        "password_auth",
                        &challenge.device_id,
                        "failure",
                        (Some(&source_ip.to_string()), ""),
                    )
                    .await;
                bail!("invalid credentials");
            };
            if let Some(replacement) = verification.replacement_phc {
                state
                    .db
                    .set_password(&account.id, &replacement, account.require_password_change)
                    .await?;
                account.password_phc = replacement;
            }
            let existing_pending =
                if let Some(device) = state.db.device(&account.id, &challenge.device_id).await? {
                    if !device.pending {
                        bail!("existing devices must use challenge signatures");
                    }
                    true
                } else {
                    false
                };
            let session = Session {
                account,
                device_id: challenge.device_id,
                pending: true,
                password_change_required: false,
                capabilities: challenge.capabilities,
            };
            send_authenticated(tx, &request_id, &session).await?;
            if existing_pending {
                state
                    .register(&session, token, tx.clone(), disconnect.clone(), source_ip)
                    .await;
                push_post_auth(state, tx, &session).await?;
            }
            let _ = state
                .db
                .audit(
                    "auth",
                    &session.account.username,
                    "password_auth",
                    &session.device_id,
                    "success",
                    (Some(&source_ip.to_string()), ""),
                )
                .await;
            *session_slot = Some(session);
        }
        Body::BootstrapDevice(bootstrap) => {
            let session = session_slot
                .as_mut()
                .ok_or_else(|| anyhow!("password authentication required"))?;
            if !session.pending || bootstrap.device_id != session.device_id {
                bail!("invalid bootstrap state");
            }
            if state
                .db
                .device(&session.account.id, &session.device_id)
                .await?
                .is_some()
            {
                bail!("device was already submitted");
            }
            if !valid_uuid(&bootstrap.device_id)
                || bootstrap.device_name.trim().is_empty()
                || bootstrap.device_name.chars().count() > 64
                || bootstrap.auth_signing_key.len() != 32
                || bootstrap.olm_ed25519_key.len() != 32
                || bootstrap.olm_curve25519_key.len() != 32
                || bootstrap.account_master_key.len() != 32
                || bootstrap.sas_public_key.len() != 32
                || bootstrap.one_time_keys.len() > 100
            {
                bail!("invalid public key length");
            }
            let bundle = DeviceBundle {
                device_id: bootstrap.device_id.clone(),
                device_name: bootstrap.device_name,
                auth_signing_key: bootstrap.auth_signing_key,
                olm_ed25519_key: bootstrap.olm_ed25519_key,
                olm_curve25519_key: bootstrap.olm_curve25519_key,
                certificate_signature: bootstrap.certificate_signature,
                revoked: false,
            };
            let has_devices = state.db.has_active_devices(&session.account.id).await?;
            let (active_devices, pending_devices) =
                state.db.device_counts(&session.account.id).await?;
            if !has_devices && session.account.master_public_key.is_none() {
                if active_devices != 0 || pending_devices != 0 {
                    bail!("account device state is inconsistent");
                }
                verify_device_certificate(
                    &bootstrap.account_master_key,
                    &session.account.id,
                    &bundle,
                )?;
                state
                    .db
                    .bootstrap_master(&session.account.id, &bootstrap.account_master_key)
                    .await?;
                state
                    .db
                    .insert_device(
                        &session.account.id,
                        &bundle,
                        &bootstrap.sas_public_key,
                        false,
                        now_ms(),
                    )
                    .await?;
                state
                    .db
                    .publish_prekeys(&session.device_id, &bootstrap.one_time_keys, now_ms())
                    .await?;
                session.account.master_public_key = Some(bootstrap.account_master_key);
                session.account.roster_revision = 1;
                session.pending = false;
                session.password_change_required = session.account.require_password_change;
                state
                    .register(session, token, tx.clone(), disconnect.clone(), source_ip)
                    .await;
                send_authenticated(tx, &request_id, session).await?;
            } else {
                if active_devices >= 8 || pending_devices >= 2 {
                    bail!("account device limit reached");
                }
                if session.account.master_public_key.as_deref()
                    != Some(bootstrap.account_master_key.as_slice())
                {
                    bail!("account identity mismatch");
                }
                if !bundle.certificate_signature.is_empty() {
                    bail!("pending device certificate must be issued by an existing device");
                }
                state
                    .db
                    .insert_device(
                        &session.account.id,
                        &bundle,
                        &bootstrap.sas_public_key,
                        true,
                        now_ms(),
                    )
                    .await?;
                state
                    .db
                    .publish_prekeys(&session.device_id, &bootstrap.one_time_keys, now_ms())
                    .await?;
                state
                    .register(session, token, tx.clone(), disconnect.clone(), source_ip)
                    .await;
                let pairing = PairingRequest {
                    pairing_id: session.device_id.clone(),
                    pending_device_id: session.device_id.clone(),
                    pending_device_name: bundle.device_name.clone(),
                    sas_public_key: bootstrap.sas_public_key,
                    pending_device: Some(bundle),
                };
                state
                    .push_account(
                        &session.account.id,
                        frame("", Body::PairingRequest(pairing)),
                    )
                    .await;
                send_authenticated(tx, &request_id, session).await?;
            }
        }
        Body::ChangePassword(mut change) => {
            let session = active_session(session_slot)?;
            if change.current_password.is_empty() || change.current_password.len() > 1024 {
                change.current_password.zeroize();
                change.new_password.zeroize();
                bail!("current password is incorrect");
            }
            if let Err(error) = validate_password(&change.new_password) {
                change.current_password.zeroize();
                change.new_password.zeroize();
                return Err(error);
            }
            let _permit = state
                .auth_hash_gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| anyhow!("authentication service unavailable"))?;
            let verification = verify_password(
                session.account.password_phc.clone(),
                change.current_password.clone(),
            )
            .await;
            change.current_password.zeroize();
            if !verification.valid {
                change.new_password.zeroize();
                bail!("current password is incorrect");
            }
            let mut new_password = change.new_password.clone();
            let phc = tokio::task::spawn_blocking(move || {
                let result = hash_password(&new_password);
                new_password.zeroize();
                result
            })
            .await??;
            change.new_password.zeroize();
            state
                .db
                .set_password(&session.account.id, &phc, false)
                .await?;
            session.account.password_phc = phc;
            session.account.require_password_change = false;
            session.password_change_required = false;
            state
                .db
                .audit(
                    "auth",
                    &session.account.username,
                    "password_change",
                    &session.device_id,
                    "success",
                    (Some(&source_ip.to_string()), ""),
                )
                .await?;
            send_authenticated(tx, &request_id, session).await?;
        }
        Body::LookupUser(lookup) => {
            let _session = usable_session(session_slot)?;
            let username = normalize_username(&lookup.exact_username)?;
            let Some((account, devices)) = state.db.lookup_user_bundle(&username).await? else {
                bail!("user not found");
            };
            tx.send(frame(
                request_id,
                Body::UserBundle(UserBundle {
                    account_id: account.id,
                    username: account.username,
                    account_master_key: account.master_public_key.unwrap_or_default(),
                    roster_revision: account.roster_revision,
                    devices,
                }),
            ))
            .await?;
        }
        Body::PublishPreKeys(keys) => {
            let session = usable_session(session_slot)?;
            if keys.keys.len() > 100 {
                bail!("too many prekeys");
            }
            let device = state
                .db
                .device(&session.account.id, &session.device_id)
                .await?
                .ok_or_else(|| anyhow!("device missing"))?;
            for key in &keys.keys {
                if key.key_id.is_empty()
                    || key.key_id.len() > 64
                    || key.curve25519_key.len() != 32
                    || key.signature.len() != 64
                {
                    bail!("invalid prekey fields");
                }
                verify_prekey(&device.auth_signing_key, key)?;
            }
            state
                .db
                .publish_prekeys(&session.device_id, &keys.keys, now_ms())
                .await?;
            tx.send(frame(request_id, Body::OperationOk(v1::OperationOk {})))
                .await?;
        }
        Body::ClaimPreKey(claim) => {
            let _session = usable_session(session_slot)?;
            if !valid_uuid(&claim.account_id) || !valid_uuid(&claim.device_id) {
                bail!("invalid prekey target");
            }
            let bundle = state
                .db
                .claim_prekey(&claim.account_id, &claim.device_id)
                .await?;
            let Some((device, one_time_key)) = bundle else {
                bail!("recipient has no available prekey");
            };
            tx.send(frame(
                request_id,
                Body::PreKeyBundle(PreKeyBundle {
                    device: Some(device),
                    one_time_key: Some(one_time_key),
                }),
            ))
            .await?;
        }
        Body::SendEnvelopes(send) => {
            let session = usable_session(session_slot)?;
            if session.password_change_required {
                bail!("password change is required before sending");
            }
            for envelope in &send.envelopes {
                if !valid_uuid(&envelope.envelope_id)
                    || !valid_uuid(&envelope.logical_message_id)
                    || !valid_uuid(&envelope.recipient_account_id)
                    || !valid_uuid(&envelope.recipient_device_id)
                    || envelope.conversation_id.len() != 64
                    || !envelope
                        .conversation_id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || envelope.client_sent_at_ms < 0
                    || envelope.client_sent_at_ms > now_ms() + 5 * 60 * 1000
                {
                    bail!("invalid encrypted envelope fields");
                }
            }
            let now = now_ms();
            let destinations = state
                .db
                .store_envelopes(
                    &session.account.id,
                    &session.device_id,
                    &send.envelopes,
                    now,
                    state.config.storage_limits(),
                )
                .await?;
            for (device, _) in destinations {
                if let Some(envelope) = send
                    .envelopes
                    .iter()
                    .find(|envelope| envelope.recipient_device_id == device)
                    && let Some(stored) = state.db.stored_envelope(&envelope.envelope_id).await?
                {
                    let next = stored.cursor;
                    state
                        .push_device(
                            &device,
                            frame(
                                "",
                                Body::SyncBatch(SyncBatch {
                                    envelopes: vec![stored],
                                    next_cursor: next,
                                    has_more: false,
                                    delivery_updates: vec![],
                                    next_status_cursor: 0,
                                }),
                            ),
                        )
                        .await;
                }
            }
            let logical = send
                .envelopes
                .first()
                .map(|e| e.logical_message_id.clone())
                .unwrap_or_default();
            tx.send(frame(
                request_id,
                Body::SendAccepted(SendAccepted {
                    logical_message_id: logical,
                    accepted_at_ms: now,
                }),
            ))
            .await?;
        }
        Body::SyncRequest(sync) => {
            let session = usable_session(session_slot)?;
            let (envelopes, statuses, has_more) = state
                .db
                .sync(
                    &session.account.id,
                    &session.device_id,
                    sync.after_cursor,
                    sync.after_status_cursor,
                    sync.limit,
                )
                .await?;
            let next_cursor = envelopes
                .last()
                .map(|e| e.cursor)
                .unwrap_or(sync.after_cursor);
            let next_status_cursor = statuses
                .last()
                .map(|e| e.cursor)
                .unwrap_or(sync.after_status_cursor);
            tx.send(frame(
                request_id,
                Body::SyncBatch(SyncBatch {
                    envelopes,
                    next_cursor,
                    has_more,
                    delivery_updates: statuses,
                    next_status_cursor,
                }),
            ))
            .await?;
        }
        Body::AckEnvelope(ack) => {
            let session = usable_session(session_slot)?;
            if !valid_uuid(&ack.envelope_id) {
                bail!("invalid envelope acknowledgement");
            }
            if let Some((sender_account, logical)) = state
                .db
                .ack(&session.device_id, &ack.envelope_id, now_ms())
                .await?
            {
                state
                    .push_account(
                        &sender_account,
                        frame(
                            "",
                            Body::DeliveryUpdate(DeliveryUpdate {
                                logical_message_id: logical,
                                delivered_at_ms: now_ms(),
                            }),
                        ),
                    )
                    .await;
            }
            if !request_id.is_empty() {
                tx.send(frame(request_id, Body::OperationOk(v1::OperationOk {})))
                    .await?;
            }
        }
        Body::PairingEvent(event) => {
            let session = session_slot
                .as_ref()
                .ok_or_else(|| anyhow!("authentication required"))?;
            if event.server_event_id != 0
                || !valid_uuid(&event.pairing_id)
                || !valid_uuid(&event.target_device_id)
                || event.payload.len() > 192 * 1024
                || !matches!(
                    event.event_type.as_str(),
                    "sas_public"
                        | "sas_confirmed"
                        | "bootstrap"
                        | "history_chunk"
                        | "history_complete"
                )
            {
                bail!("invalid pairing event");
            }
            let target_account = state
                .db
                .device_account_any(&event.target_device_id)
                .await?
                .ok_or_else(|| anyhow!("target device not found"))?;
            if target_account != session.account.id {
                bail!("pairing is restricted to the same account");
            }
            if !state
                .db
                .device(&session.account.id, &event.pairing_id)
                .await?
                .is_some_and(|device| device.pending && !device.revoked)
            {
                bail!("pairing request is not active");
            }
            if session.device_id != event.pairing_id && event.target_device_id != event.pairing_id {
                bail!("pairing event is not bound to the pending device");
            }
            let event_id = state
                .db
                .insert_pairing_event(
                    &event.pairing_id,
                    &session.device_id,
                    &event.target_device_id,
                    &event.event_type,
                    &event.payload,
                    (
                        now_ms(),
                        now_ms() + state.config.pairing_ttl_seconds as i64 * 1000,
                    ),
                )
                .await?;
            let target = event.target_device_id.clone();
            let sender_device_name = state
                .db
                .device_bundles(&session.account.id, true)
                .await?
                .into_iter()
                .find(|device| device.device_id == session.device_id)
                .map(|device| device.device_name)
                .ok_or_else(|| anyhow!("sender device not found"))?;
            let mut forwarded = event;
            forwarded.sender_device_id = session.device_id.clone();
            forwarded.sender_device_name = sender_device_name;
            forwarded.server_event_id = event_id;
            state
                .push_device(&target, frame("", Body::PairingEvent(forwarded)))
                .await;
            if !request_id.is_empty() {
                tx.send(frame(request_id, Body::OperationOk(v1::OperationOk {})))
                    .await?;
            }
        }
        Body::AckPairingEvent(ack) => {
            let session = session_slot
                .as_ref()
                .ok_or_else(|| anyhow!("authentication required"))?;
            if ack.server_event_id == 0
                || !state
                    .db
                    .ack_pairing_event(&session.device_id, ack.server_event_id)
                    .await?
            {
                bail!("pairing event not found");
            }
            if !request_id.is_empty() {
                tx.send(frame(request_id, Body::OperationOk(v1::OperationOk {})))
                    .await?;
            }
        }
        Body::ActivateDevice(activate) => {
            let session = usable_session(session_slot)?;
            let bundle = activate
                .device
                .ok_or_else(|| anyhow!("missing device bundle"))?;
            if !valid_uuid(&activate.pairing_id)
                || !valid_uuid(&bundle.device_id)
                || activate.pairing_id != bundle.device_id
                || bundle.device_name.chars().count() > 64
                || bundle.auth_signing_key.len() != 32
                || bundle.olm_ed25519_key.len() != 32
                || bundle.olm_curve25519_key.len() != 32
                || bundle.certificate_signature.len() != 64
                || activate.roster_signature.len() != 64
            {
                bail!("invalid device activation fields");
            }
            let pending = state
                .db
                .device_bundles(&session.account.id, true)
                .await?
                .into_iter()
                .find(|item| item.device_id == bundle.device_id)
                .ok_or_else(|| anyhow!("pending device not found"))?;
            if pending.auth_signing_key != bundle.auth_signing_key
                || pending.olm_ed25519_key != bundle.olm_ed25519_key
                || pending.olm_curve25519_key != bundle.olm_curve25519_key
            {
                bail!("pending device keys changed");
            }
            let master = session
                .account
                .master_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("account is not bootstrapped"))?;
            verify_device_certificate(master, &session.account.id, &bundle)?;
            verify_roster_signature(
                master,
                &session.account.id,
                activate.roster_revision,
                &bundle.device_id,
                &activate.roster_signature,
            )?;
            state
                .db
                .activate_device(
                    &session.account.id,
                    &bundle.device_id,
                    activate.roster_revision,
                    &bundle.certificate_signature,
                )
                .await?;
            let target = bundle.device_id.clone();
            state
                .push_device(
                    &target,
                    frame(
                        "",
                        Body::PairingEvent(PairingEvent {
                            pairing_id: activate.pairing_id,
                            target_device_id: target.clone(),
                            event_type: "device_activated".to_owned(),
                            payload: vec![],
                            sender_device_id: session.device_id.clone(),
                            server_event_id: 0,
                            sender_device_name: String::new(),
                        }),
                    ),
                )
                .await;
            tx.send(frame(request_id, Body::OperationOk(v1::OperationOk {})))
                .await?;
        }
        Body::ListOwnDevices(_) => {
            let session = usable_session(session_slot)?;
            if !session
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_OWN_DEVICES)
            {
                bail!("client did not negotiate own device management");
            }
            let devices = own_device_list(state, &session.account.id, &session.device_id).await?;
            tx.send(frame(request_id, Body::OwnDeviceList(devices)))
                .await?;
        }
        Body::RevokeOwnDevice(revoke) => {
            let session = usable_session(session_slot)?;
            if !session
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_OWN_DEVICES)
            {
                bail!("client did not negotiate own device management");
            }
            if !valid_uuid(&revoke.device_id) {
                bail!("invalid device id");
            }
            if revoke.device_id == session.device_id {
                bail!("cannot revoke the current device");
            }
            if !state
                .db
                .revoke_own_device(&session.account.id, &revoke.device_id)
                .await?
            {
                bail!("device is not active or does not belong to this account");
            }
            state.kick_device(&revoke.device_id, "access_revoked").await;
            state
                .db
                .audit(
                    "device",
                    &session.account.username,
                    "self_service_revoke",
                    &revoke.device_id,
                    "success",
                    (Some(&source_ip.to_string()), &session.device_id),
                )
                .await?;
            let devices = own_device_list(state, &session.account.id, &session.device_id).await?;
            tx.send(frame(request_id, Body::OwnDeviceList(devices)))
                .await?;
        }
        Body::Ping(ping) => {
            tx.send(frame(
                request_id,
                Body::Pong(v1::Pong {
                    sent_at_ms: ping.sent_at_ms,
                }),
            ))
            .await?;
        }
        Body::Pong(_) => {}
        _ => bail!("frame type is not valid in this direction"),
    }
    Ok(())
}

fn take_valid_challenge(
    slot: &mut Option<Challenge>,
    username: &str,
    device_id: &str,
) -> Result<Challenge> {
    let challenge = slot
        .take()
        .ok_or_else(|| anyhow!("send ClientHello first"))?;
    if challenge.username != normalize_username(username)?
        || challenge.device_id != device_id
        || challenge.expires_at_ms < now_ms()
    {
        bail!("authentication challenge is invalid or expired");
    }
    Ok(challenge)
}

fn active_session(slot: &mut Option<Session>) -> Result<&mut Session> {
    let session = slot
        .as_mut()
        .ok_or_else(|| anyhow!("authentication required"))?;
    if session.pending {
        bail!("device approval is pending");
    }
    Ok(session)
}

fn usable_session(slot: &mut Option<Session>) -> Result<&mut Session> {
    active_session(slot)
}

async fn send_authenticated(
    tx: &mpsc::Sender<v1::Frame>,
    id: &str,
    session: &Session,
) -> Result<()> {
    let bootstrap_mode = if !session.pending {
        v1::BootstrapMode::None
    } else if session.account.master_public_key.is_none() {
        v1::BootstrapMode::FirstDevice
    } else {
        v1::BootstrapMode::PendingDevice
    };
    tx.send(frame(
        id,
        Body::Authenticated(Authenticated {
            account_id: session.account.id.clone(),
            username: session.account.username.clone(),
            device_id: session.device_id.clone(),
            password_change_required: session.password_change_required,
            pending_device: session.pending,
            account_master_key: session
                .account
                .master_public_key
                .clone()
                .unwrap_or_default(),
            roster_revision: session.account.roster_revision,
            bootstrap_mode: bootstrap_mode as i32,
            capabilities: vec![
                CAPABILITY_OWN_DEVICES.to_owned(),
                CAPABILITY_STABLE_ERRORS.to_owned(),
            ],
        }),
    ))
    .await?;
    Ok(())
}

async fn push_post_auth(
    state: &AppState,
    tx: &mpsc::Sender<v1::Frame>,
    session: &Session,
) -> Result<()> {
    let device_names: HashMap<_, _> = state
        .db
        .device_bundles(&session.account.id, true)
        .await?
        .into_iter()
        .map(|device| (device.device_id, device.device_name))
        .collect();
    for event in state
        .db
        .pending_pairing_events(&session.device_id, now_ms())
        .await?
    {
        tx.send(frame(
            "",
            Body::PairingEvent(PairingEvent {
                pairing_id: event.pairing_id,
                target_device_id: session.device_id.clone(),
                event_type: event.event_type,
                payload: event.payload,
                sender_device_name: device_names
                    .get(&event.sender_device_id)
                    .cloned()
                    .unwrap_or_else(|| "未知设备".to_owned()),
                sender_device_id: event.sender_device_id,
                server_event_id: event.id,
            }),
        ))
        .await?;
    }
    for (device, sas) in state.db.pending_devices(&session.account.id).await? {
        if device.device_id != session.device_id {
            tx.send(frame(
                "",
                Body::PairingRequest(PairingRequest {
                    pairing_id: device.device_id.clone(),
                    pending_device_id: device.device_id.clone(),
                    pending_device_name: device.device_name.clone(),
                    sas_public_key: sas,
                    pending_device: Some(device),
                }),
            ))
            .await?;
        }
    }
    Ok(())
}

async fn own_device_list(
    state: &AppState,
    account_id: &str,
    current_device_id: &str,
) -> Result<v1::OwnDeviceList> {
    let online = state.online_devices(account_id).await;
    let mut devices = state.db.own_devices(account_id).await?;
    for device in &mut devices {
        device.current = device.device_id == current_device_id;
        device.online = online
            .iter()
            .any(|online_id| online_id == &device.device_id);
    }
    devices.sort_by_key(|device| {
        (
            !device.current,
            device.revoked,
            device.pending,
            device.created_at_ms,
        )
    });
    Ok(v1::OwnDeviceList { devices })
}

async fn send_error(
    tx: &mpsc::Sender<v1::Frame>,
    id: &str,
    code: &str,
    message: &str,
    retryable: bool,
) {
    let sanitized = message.chars().take(240).collect();
    let _ = tx
        .send(frame(
            id,
            Body::Error(ErrorFrame {
                code: code.to_owned(),
                message: sanitized,
                retryable,
            }),
        ))
        .await;
}

struct PasswordVerification {
    valid: bool,
    replacement_phc: Option<String>,
}

async fn verify_password(phc: String, mut password: String) -> PasswordVerification {
    tokio::task::spawn_blocking(move || {
        let verified = PasswordHash::new(&phc).ok().is_some_and(|hash| {
            password_hasher()
                .is_ok_and(|hasher| hasher.verify_password(password.as_bytes(), &hash).is_ok())
        });
        let replacement_phc = if verified && password_needs_rehash(&phc) {
            hash_password(&password).ok()
        } else {
            None
        };
        password.zeroize();
        PasswordVerification {
            valid: verified,
            replacement_phc,
        }
    })
    .await
    .unwrap_or(PasswordVerification {
        valid: false,
        replacement_phc: None,
    })
}

async fn allow_password_attempt(state: &AppState, source_ip: IpAddr, username: &str) -> bool {
    {
        let mut buckets = state.auth_buckets.lock().await;
        if buckets.len() >= 10_000 && !buckets.contains_key(&source_ip) {
            buckets.retain(|_, bucket| bucket.updated.elapsed() < Duration::from_secs(600));
            if buckets.len() >= 10_000 {
                return false;
            }
        }
        if !buckets
            .entry(source_ip)
            .or_insert_with(|| TokenBucket::new(state.config.auth_attempt_burst))
            .take(
                state.config.auth_attempts_per_minute,
                state.config.auth_attempt_burst,
            )
        {
            return false;
        }
    }

    let mut buckets = state.auth_account_buckets.lock().await;
    if buckets.len() >= 10_000 && !buckets.contains_key(username) {
        buckets.retain(|_, bucket| bucket.updated.elapsed() < Duration::from_secs(60 * 60));
        if buckets.len() >= 10_000 {
            return false;
        }
    }
    buckets
        .entry(username.to_owned())
        .or_insert_with(|| TokenBucket::new(10))
        .take_rate(
            f64::from(state.config.auth_attempts_per_account_per_hour) / 3600.0,
            10,
        )
}

fn decrement_count(counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
    if let Some(count) = counts.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&ip);
        }
    }
}

fn forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

struct PublicError {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

fn public_error(error: &anyhow::Error) -> PublicError {
    if let Some(rejection) = error.downcast_ref::<crate::db::StorageRejection>() {
        return match rejection {
            crate::db::StorageRejection::AccountQuota | crate::db::StorageRejection::TotalQuota => {
                PublicError {
                    code: "storage_quota_exceeded",
                    message: "server ciphertext storage quota exceeded",
                    retryable: false,
                }
            }
            crate::db::StorageRejection::DiskPressure => PublicError {
                code: "storage_pressure",
                message: "server disk reserve reached; retry after storage cleanup",
                retryable: true,
            },
        };
    }
    let message = error.to_string();
    if message.contains("too many authentication attempts") {
        PublicError {
            code: "rate_limited",
            message: "too many authentication attempts; retry later",
            retryable: true,
        }
    } else if message.contains("password must contain") {
        PublicError {
            code: "password_policy",
            message: "password does not meet the server policy",
            retryable: false,
        }
    } else if message.contains("invalid credentials") {
        PublicError {
            code: "invalid_credentials",
            message: "invalid credentials",
            retryable: false,
        }
    } else if message.contains("password change is required") {
        PublicError {
            code: "password_change_required",
            message: "password change is required",
            retryable: false,
        }
    } else if message.contains("recipient device is unavailable") {
        PublicError {
            code: "recipient_roster_changed",
            message: "recipient device roster changed; refresh and retry",
            retryable: true,
        }
    } else if message.contains("cannot revoke the current device") {
        PublicError {
            code: "device_revoke_forbidden",
            message: "the current device cannot revoke itself",
            retryable: false,
        }
    } else if message.contains("user not found") {
        PublicError {
            code: "user_not_found",
            message: "user not found",
            retryable: false,
        }
    } else {
        PublicError {
            code: "request_rejected",
            message: "request rejected",
            retryable: false,
        }
    }
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36 && Uuid::parse_str(value).is_ok()
}

fn verify_signature(public: &[u8], payload: &[u8], signature: &[u8]) -> Result<()> {
    let key: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow!("invalid signing key"))?;
    let signature = Signature::from_slice(signature).map_err(|_| anyhow!("invalid signature"))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| anyhow!("invalid signing key"))?
        .verify_strict(payload, &signature)
        .map_err(|_| anyhow!("signature verification failed"))
}

fn verify_device_certificate(master: &[u8], account_id: &str, bundle: &DeviceBundle) -> Result<()> {
    verify_signature(
        master,
        &device_certificate_payload(
            account_id,
            &bundle.device_id,
            &bundle.auth_signing_key,
            &bundle.olm_ed25519_key,
            &bundle.olm_curve25519_key,
        ),
        &bundle.certificate_signature,
    )
}

fn verify_prekey(auth_key: &[u8], key: &v1::OneTimeKey) -> Result<()> {
    let mut payload = b"tui-chat-prekey-v1\0".to_vec();
    payload.extend_from_slice(key.key_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&key.curve25519_key);
    verify_signature(auth_key, &payload, &key.signature)
}

fn verify_roster_signature(
    master: &[u8],
    account: &str,
    revision: u64,
    device: &str,
    signature: &[u8],
) -> Result<()> {
    let mut payload = b"tui-chat-roster-v1\0".to_vec();
    payload.extend_from_slice(account.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&revision.to_be_bytes());
    payload.extend_from_slice(device.as_bytes());
    verify_signature(master, &payload, signature)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
