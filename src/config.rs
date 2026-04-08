use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

/// Authentication configuration.
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// No authentication required.
    None,
    /// Username/password pairs.
    Password(Vec<(String, String)>),
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Authentication configuration.
    pub auth: AuthConfig,

    /// Address to listen on for SOCKS connections.
    pub listen_addr: SocketAddr,

    /// Maximum concurrent connections.
    pub max_connections: usize,

    /// Maximum connections per source IP.
    pub max_connections_per_ip: usize,

    /// Timeout for SOCKS handshake (greeting + auth).
    pub handshake_timeout: Duration,

    /// Timeout for connecting to the target host.
    pub connect_timeout: Duration,

    /// Timeout for DNS resolution.
    pub dns_timeout: Duration,

    /// Idle timeout for relay (no data in either direction).
    pub idle_timeout: Duration,

    /// Timeout for graceful shutdown drain.
    pub drain_timeout: Duration,

    /// TCP keepalive idle time before first probe.
    pub tcp_keepalive_idle: Duration,

    /// TCP keepalive interval between probes.
    pub tcp_keepalive_interval: Duration,

    /// TCP keepalive probe count before declaring dead.
    pub tcp_keepalive_probes: u32,

    /// Monitor dashboard HTTP address. None = disabled.
    pub monitor_addr: Option<std::net::SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: AuthConfig::None,
            listen_addr: "127.0.0.1:1080".parse().unwrap(),
            max_connections: 50_000,
            max_connections_per_ip: 10_000,
            handshake_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
            drain_timeout: Duration::from_secs(30),
            tcp_keepalive_idle: Duration::from_secs(30),
            tcp_keepalive_interval: Duration::from_secs(10),
            tcp_keepalive_probes: 3,
            monitor_addr: None,
        }
    }
}

// ── TOML file schema ──

#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    pub listen: Option<String>,
    pub max_connections: Option<usize>,
    pub max_connections_per_ip: Option<usize>,
    pub handshake_timeout: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub dns_timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub drain_timeout: Option<u64>,

    pub auth: Option<FileAuthConfig>,
    pub tunnel: Option<FileTunnelConfig>,
    pub keepalive: Option<FileKeepaliveConfig>,
}

#[derive(Debug, Deserialize)]
pub struct FileAuthConfig {
    pub users: Option<Vec<FileUser>>,
}

#[derive(Debug, Deserialize)]
pub struct FileUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct FileTunnelConfig {
    pub listen: Option<String>,
    pub secret: Option<String>,
    pub server_addr: Option<String>,
    pub client_id: Option<String>,
    pub pool_size: Option<u16>,
    pub reconnect_interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct FileKeepaliveConfig {
    pub idle: Option<u64>,
    pub interval: Option<u64>,
    pub probes: Option<u32>,
}

impl FileConfig {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file: {e}"))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse config file: {e}"))
    }

    /// Apply file config values onto a Config, overriding only what's set.
    pub fn apply_to(&self, config: &mut Config) {
        if let Some(ref listen) = self.listen
            && let Ok(addr) = listen.parse() {
                config.listen_addr = addr;
            }
        if let Some(v) = self.max_connections {
            config.max_connections = v;
        }
        if let Some(v) = self.max_connections_per_ip {
            config.max_connections_per_ip = v;
        }
        if let Some(v) = self.handshake_timeout {
            config.handshake_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.connect_timeout {
            config.connect_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.dns_timeout {
            config.dns_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.idle_timeout {
            config.idle_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.drain_timeout {
            config.drain_timeout = Duration::from_secs(v);
        }

        if let Some(ref auth) = self.auth
            && let Some(ref users) = auth.users
                && !users.is_empty() {
                    config.auth = AuthConfig::Password(
                        users
                            .iter()
                            .map(|u| (u.username.clone(), u.password.clone()))
                            .collect(),
                    );
                }

        if let Some(ref ka) = self.keepalive {
            if let Some(v) = ka.idle {
                config.tcp_keepalive_idle = Duration::from_secs(v);
            }
            if let Some(v) = ka.interval {
                config.tcp_keepalive_interval = Duration::from_secs(v);
            }
            if let Some(v) = ka.probes {
                config.tcp_keepalive_probes = v;
            }
        }
    }
}
