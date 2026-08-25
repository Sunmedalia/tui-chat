use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
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
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub reject_websocket_origins: bool,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_unauthenticated_per_ip: usize,
    pub auth_attempts_per_minute: u32,
    pub auth_attempt_burst: u32,
    pub auth_attempts_per_account_per_hour: u32,
    pub auth_hash_concurrency: usize,
    pub requests_per_minute: u32,
    pub request_burst: u32,
    pub audit_retention_days: u32,
    pub pairing_ttl_seconds: u64,
    pub delivered_retention_days: u32,
    pub max_account_ciphertext_bytes: u64,
    pub max_total_ciphertext_bytes: u64,
    pub min_free_disk_bytes: u64,
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
            trusted_proxy_cidrs: vec![
                "127.0.0.1/32".parse().expect("valid loopback CIDR"),
                "::1/128".parse().expect("valid loopback CIDR"),
            ],
            reject_websocket_origins: true,
            max_connections: 512,
            max_connections_per_ip: 32,
            max_unauthenticated_per_ip: 4,
            auth_attempts_per_minute: 10,
            auth_attempt_burst: 5,
            auth_attempts_per_account_per_hour: 30,
            auth_hash_concurrency: 4,
            requests_per_minute: 120,
            request_burst: 30,
            audit_retention_days: 90,
            pairing_ttl_seconds: 24 * 60 * 60,
            delivered_retention_days: 90,
            max_account_ciphertext_bytes: 512 * 1024 * 1024,
            max_total_ciphertext_bytes: 10 * 1024 * 1024 * 1024,
            min_free_disk_bytes: 1024 * 1024 * 1024,
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
        if let Ok(value) = std::env::var("TUI_CHAT_TRUSTED_PROXY_CIDRS") {
            config.trusted_proxy_cidrs = value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .parse()
                        .context("invalid TUI_CHAT_TRUSTED_PROXY_CIDRS")
                })
                .collect::<Result<Vec<_>>>()?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_REJECT_WEBSOCKET_ORIGINS") {
            config.reject_websocket_origins =
                parse_bool(&value, "TUI_CHAT_REJECT_WEBSOCKET_ORIGINS")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_AUTH_ATTEMPTS_PER_ACCOUNT_PER_HOUR") {
            config.auth_attempts_per_account_per_hour = value
                .parse()
                .context("invalid TUI_CHAT_AUTH_ATTEMPTS_PER_ACCOUNT_PER_HOUR")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_DELIVERED_RETENTION_DAYS") {
            config.delivered_retention_days = value
                .parse()
                .context("invalid TUI_CHAT_DELIVERED_RETENTION_DAYS")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_MAX_ACCOUNT_CIPHERTEXT_BYTES") {
            config.max_account_ciphertext_bytes = value
                .parse()
                .context("invalid TUI_CHAT_MAX_ACCOUNT_CIPHERTEXT_BYTES")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_MAX_TOTAL_CIPHERTEXT_BYTES") {
            config.max_total_ciphertext_bytes = value
                .parse()
                .context("invalid TUI_CHAT_MAX_TOTAL_CIPHERTEXT_BYTES")?;
        }
        if let Ok(value) = std::env::var("TUI_CHAT_MIN_FREE_DISK_BYTES") {
            config.min_free_disk_bytes = value
                .parse()
                .context("invalid TUI_CHAT_MIN_FREE_DISK_BYTES")?;
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
        if config.trusted_proxy_tls && config.trusted_proxy_cidrs.is_empty() {
            anyhow::bail!("trusted_proxy_tls=true requires at least one trusted_proxy_cidrs entry");
        }
        if config.max_connections == 0
            || config.max_connections_per_ip == 0
            || config.max_unauthenticated_per_ip == 0
            || config.auth_hash_concurrency == 0
            || config.auth_attempts_per_minute == 0
            || config.auth_attempt_burst == 0
            || config.auth_attempts_per_account_per_hour == 0
            || config.requests_per_minute == 0
            || config.request_burst == 0
            || config.delivered_retention_days == 0
            || config.max_account_ciphertext_bytes == 0
            || config.max_total_ciphertext_bytes == 0
        {
            anyhow::bail!(
                "connection, rate, retention, and storage limits must be greater than zero"
            );
        }
        if config.max_account_ciphertext_bytes > config.max_total_ciphertext_bytes {
            anyhow::bail!("max_account_ciphertext_bytes cannot exceed max_total_ciphertext_bytes");
        }
        Ok(config)
    }

    pub fn is_trusted_proxy(&self, address: std::net::IpAddr) -> bool {
        self.trusted_proxy_tls
            && self
                .trusted_proxy_cidrs
                .iter()
                .any(|network| network.contains(&address))
    }

    pub fn storage_limits(&self) -> crate::db::StorageLimits {
        crate::db::StorageLimits {
            max_account_ciphertext_bytes: self.max_account_ciphertext_bytes,
            max_total_ciphertext_bytes: self.max_total_ciphertext_bytes,
            min_free_disk_bytes: self.min_free_disk_bytes,
        }
    }
}

fn parse_bool(value: &str, name: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("invalid {name}; expected true or false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_headers_are_trusted_only_from_configured_networks() {
        let config = Config {
            trusted_proxy_tls: true,
            trusted_proxy_cidrs: vec!["172.31.250.2/32".parse().expect("valid CIDR")],
            ..Config::default()
        };
        assert!(config.is_trusted_proxy("172.31.250.2".parse().expect("valid IP")));
        assert!(!config.is_trusted_proxy("172.31.250.3".parse().expect("valid IP")));
        assert!(!config.is_trusted_proxy("127.0.0.1".parse().expect("valid IP")));
    }

    #[test]
    fn storage_defaults_leave_a_disk_reserve() {
        let config = Config::default();
        assert!(config.reject_websocket_origins);
        assert!(config.min_free_disk_bytes > 0);
        assert!(config.max_total_ciphertext_bytes >= config.max_account_ciphertext_bytes);
        assert!(config.delivered_retention_days > 0);
    }
}
