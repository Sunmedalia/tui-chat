use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_path: PathBuf,
    pub admin_socket_path: PathBuf,
    pub public_domain: String,
    pub log_filter: String,
    pub trusted_proxy_tls: bool,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_unauthenticated_per_ip: usize,
    pub auth_attempts_per_minute: u32,
    pub auth_attempt_burst: u32,
    pub auth_hash_concurrency: usize,
    pub requests_per_minute: u32,
    pub request_burst: u32,
    pub audit_retention_days: u32,
    pub pairing_ttl_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080"
                .parse()
                .expect("valid default bind address"),
            database_path: PathBuf::from("data/server.db"),
            admin_socket_path: PathBuf::from("data/admin.sock"),
            public_domain: "localhost".to_owned(),
            log_filter: "tui_chat_server=info".to_owned(),
            trusted_proxy_tls: false,
            max_connections: 512,
            max_connections_per_ip: 32,
            max_unauthenticated_per_ip: 4,
            auth_attempts_per_minute: 10,
            auth_attempt_burst: 5,
            auth_hash_concurrency: 4,
            requests_per_minute: 120,
            request_burst: 30,
            audit_retention_days: 90,
            pairing_ttl_seconds: 24 * 60 * 60,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?
        } else {
            Self::default()
        };
        if let Ok(value) = std::env::var("TUI_CHAT_BIND") {
            config.bind = value.parse().context("invalid TUI_CHAT_BIND")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_DATABASE_PATH") {
            config.database_path = value.into();
        }
        if let Ok(value) = std::env::var("TUI_CHAT_ADMIN_SOCKET_PATH") {
            config.admin_socket_path = value.into();
        }
        if let Ok(value) = std::env::var("TUI_CHAT_PUBLIC_DOMAIN") {
            config.public_domain = value;
        }
        if let Ok(value) = std::env::var("RUST_LOG") {
            config.log_filter = value;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_TRUSTED_PROXY_TLS") {
            config.trusted_proxy_tls = parse_bool(&value, "TUI_CHAT_TRUSTED_PROXY_TLS")?;
        }
        config.public_domain = config.public_domain.trim().to_ascii_lowercase();
        if config.public_domain.is_empty()
            || config.public_domain.contains("://")
            || config.public_domain.contains('/')
            || config.public_domain.chars().any(char::is_whitespace)
        {
            anyhow::bail!(
                "public_domain must be a hostname or IP address without a scheme or path"
            );
        }
        if !config.bind.ip().is_loopback() && !config.trusted_proxy_tls {
            anyhow::bail!(
                "non-loopback bind requires trusted_proxy_tls=true and a private TLS reverse-proxy network"
            );
        }
        if config.max_connections == 0
            || config.max_connections_per_ip == 0
            || config.max_unauthenticated_per_ip == 0
            || config.auth_hash_concurrency == 0
            || config.auth_attempts_per_minute == 0
            || config.auth_attempt_burst == 0
            || config.requests_per_minute == 0
            || config.request_burst == 0
        {
            anyhow::bail!("connection and rate limits must be greater than zero");
        }
        Ok(config)
    }
}

fn parse_bool(value: &str, name: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("invalid {name}; expected true or false"),
    }
}
