#![forbid(unsafe_code)]

mod admin;
mod admin_ui;
mod config;
mod control;
mod db;
mod ws;

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use config::Config;
use db::Db;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "tui-chat-server", version, about = "Encrypted TUI chat relay")]
struct Args {
    #[arg(long, default_value = "server.toml", global = true)]
    config: PathBuf,
    #[arg(long, value_enum, default_value_t = admin::OutputFormat::Table, global = true)]
    output: admin::OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Healthcheck,
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Conversation {
        #[command(subcommand)]
        command: ConversationCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Admin,
}

#[derive(Subcommand)]
enum UserCommand {
    Add {
        username: String,
        #[arg(long)]
        generate_password: bool,
    },
    List,
    Disable {
        username: String,
    },
    Enable {
        username: String,
    },
    ResetPassword {
        username: String,
        #[arg(long)]
        generate_password: bool,
    },
    ResetDevices {
        username: String,
    },
    /// Permanently delete an account and all server-side data associated with it.
    Delete {
        username: String,
        /// Path to an existing database backup created before deletion.
        #[arg(long)]
        backup: PathBuf,
        /// Execute the deletion after showing its impact (still requires typed confirmation).
        #[arg(long)]
        yes: bool,
    },
    /// Backwards-compatible alias for `user delete`.
    #[command(hide = true)]
    Purge {
        username: String,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    List { username: String },
    Revoke { username: String, device_id: String },
}

#[derive(Subcommand)]
enum DbCommand {
    Backup { path: PathBuf },
    Check,
    Checkpoint,
}

#[derive(Subcommand)]
enum SessionCommand {
    List,
    Kick { session_id: Uuid },
}

#[derive(Subcommand)]
enum ConversationCommand {
    List,
    Prune {
        conversation_id: String,
        #[arg(long)]
        before_ms: Option<i64>,
        #[arg(long)]
        delivered_only: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let output = args.output;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_filter)),
        )
        .init();
    if matches!(&args.command, Command::Healthcheck) {
        return healthcheck(config.bind.port()).await;
    }
    let db = Db::connect(&config.database_path).await?;
    match args.command {
        Command::Serve => serve(config, db).await,
        Command::Healthcheck => healthcheck(config.bind.port()).await,
        Command::User { command } => match command {
            UserCommand::Add {
                username,
                generate_password,
            } => admin::add_user(&db, &username, generate_password).await,
            UserCommand::List => admin::list_users(&db, output).await,
            UserCommand::Disable { username } => {
                admin::set_user_state(&db, &username, "disabled").await?;
                admin::disconnect_user_if_online(
                    &db,
                    &config.admin_socket_path,
                    &username,
                    "access_revoked",
                )
                .await
            }
            UserCommand::Enable { username } => {
                admin::set_user_state(&db, &username, "active").await
            }
            UserCommand::ResetPassword {
                username,
                generate_password,
            } => admin::reset_password(&db, &username, generate_password).await,
            UserCommand::ResetDevices { username } => {
                admin::reset_devices(&db, &username).await?;
                admin::disconnect_user_if_online(
                    &db,
                    &config.admin_socket_path,
                    &username,
                    "access_revoked",
                )
                .await
            }
            UserCommand::Delete {
                username,
                backup,
                yes,
            }
            | UserCommand::Purge {
                username,
                backup,
                yes,
            } => admin::delete_user(&db, &config.admin_socket_path, &username, &backup, yes).await,
        },
        Command::Device { command } => match command {
            DeviceCommand::List { username } => admin::list_devices(&db, &username, output).await,
            DeviceCommand::Revoke {
                username,
                device_id,
            } => {
                admin::revoke_device(&db, &username, &device_id).await?;
                admin::disconnect_device_if_online(&config.admin_socket_path, &device_id).await;
                Ok(())
            }
        },
        Command::Db { command } => match command {
            DbCommand::Backup { path } => admin::backup(&db, &path).await,
            DbCommand::Check => admin::check(&db).await,
            DbCommand::Checkpoint => admin::checkpoint(&db).await,
        },
        Command::Session { command } => match command {
            SessionCommand::List => admin::list_sessions(&config.admin_socket_path, output).await,
            SessionCommand::Kick { session_id } => {
                admin::kick_session(&config.admin_socket_path, session_id).await
            }
        },
        Command::Conversation { command } => match command {
            ConversationCommand::List => {
                admin::list_conversations(&config.admin_socket_path, output).await
            }
            ConversationCommand::Prune {
                conversation_id,
                before_ms,
                delivered_only,
                yes,
            } => {
                admin::prune_conversation(&db, &conversation_id, before_ms, delivered_only, yes)
                    .await
            }
        },
        Command::Audit {
            command: AuditCommand::List { limit },
        } => admin::list_audit(&db, limit, output).await,
        Command::Admin => admin_ui::run(&config.admin_socket_path).await,
    }
}

async fn healthcheck(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = [0_u8; 64];
    let read = stream.read(&mut response).await?;
    if !response[..read].starts_with(b"HTTP/1.1 200") {
        anyhow::bail!("health endpoint did not return HTTP 200");
    }
    Ok(())
}

async fn serve(config: Config, db: Db) -> Result<()> {
    let bind = config.bind;
    let state = Arc::new(ws::AppState::new(db, config.clone())?);
    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v2/ws", get(ws::upgrade))
        .route(
            "/v1/ws",
            get(|| async {
                (
                    axum::http::StatusCode::UPGRADE_REQUIRED,
                    "protocol v1 is no longer supported; use /v2/ws\n",
                )
            }),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let admin_socket = config.admin_socket_path.clone();
    let admin_path = admin_socket.clone();
    let admin_state = state.clone();
    let admin_task = tokio::spawn(async move { control::serve(&admin_path, admin_state).await });
    let maintenance_state = state.clone();
    let maintenance_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(error) = maintenance_state.run_maintenance_once().await {
                tracing::warn!(%error, "server maintenance failed");
            }
        }
    });
    info!(%bind, "server listening; expose it only through a TLS reverse proxy");
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await;
    admin_task.abort();
    maintenance_task.abort();
    #[cfg(unix)]
    if tokio::fs::try_exists(&admin_socket).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&admin_socket).await;
    }
    result.map_err(Into::into)
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
