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

    /// Tunnel mode: per-session yamux stream limit.
    pub tunnel_max_streams: usize,

    /// Tunnel mode: per-session yamux receive window (MiB).
    pub tunnel_recv_window_mb: usize,
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
            tcp_keepalive_idle: crate::net::KeepaliveParams::PROXY_DEFAULT.idle,
            tcp_keepalive_interval: crate::net::KeepaliveParams::PROXY_DEFAULT.interval,
            tcp_keepalive_probes: crate::net::KeepaliveParams::PROXY_DEFAULT.probes,
            monitor_addr: None,
            tunnel_max_streams: 256,
            // See `src/tunnel/session.rs::yamux_config` for why this must stay
            // well above `tunnel_max_streams × 256 KiB`: smaller values leave
            // zero headroom for yamux per-stream BDP auto-tuning, capping
            // single-stream throughput at ~256 KiB / RTT.
            tunnel_recv_window_mb: 256,
        }
    }
}

impl Config {
    /// Keepalive parameters for proxied sockets (SOCKS clients and targets).
    pub fn keepalive(&self) -> crate::net::KeepaliveParams {
        crate::net::KeepaliveParams {
            idle: self.tcp_keepalive_idle,
            interval: self.tcp_keepalive_interval,
            probes: self.tcp_keepalive_probes,
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
    /// Number of concurrent yamux sessions (client side).
    pub tunnel_sessions: Option<u16>,
    /// Per-session yamux stream limit (both sides).
    pub max_streams_per_session: Option<usize>,
    /// Per-session yamux receive window in MiB (both sides).
    pub recv_window_mb: Option<usize>,
    /// Reconnect backoff base, seconds.
    pub reconnect_interval: Option<u64>,
    /// Reconnect backoff cap, seconds.
    pub reconnect_max: Option<u64>,
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
    ///
    /// An unparsable value is an error, not something to skip silently — a
    /// proxy quietly listening on the default address instead of the
    /// configured one is a misconfiguration nobody notices.
    pub fn apply_to(&self, config: &mut Config) -> Result<(), String> {
        if let Some(ref listen) = self.listen {
            config.listen_addr = listen
                .parse()
                .map_err(|e| format!("config: invalid listen address '{listen}': {e}"))?;
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
            // 0 = 「停用」表達意圖不明,而 relay 層收到 Duration::ZERO
            // 會立刻 idle 收工 —— 一律當作 misconfig 並警告,維持預設值。
            if v == 0 {
                tracing::warn!(
                    "config: idle_timeout = 0 is invalid (would close every relay instantly), \
                     keeping default {}s",
                    config.idle_timeout.as_secs()
                );
            } else {
                config.idle_timeout = Duration::from_secs(v);
            }
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

        // Server-side tunnel yamux settings.
        if let Some(ref tunnel) = self.tunnel {
            if let Some(v) = tunnel.max_streams_per_session {
                config.tunnel_max_streams = v;
            }
            if let Some(v) = tunnel.recv_window_mb {
                config.tunnel_recv_window_mb = v;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_values_apply_and_bad_listen_is_an_error() {
        let fc: FileConfig = toml::from_str(
            "listen = \"0.0.0.0:2080\"\nmax_connections = 7\nidle_timeout = 42\n",
        )
        .unwrap();
        let mut config = Config::default();
        fc.apply_to(&mut config).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:2080".parse().unwrap());
        assert_eq!(config.max_connections, 7);
        assert_eq!(config.idle_timeout, Duration::from_secs(42));

        let bad: FileConfig = toml::from_str("listen = \"not-an-address\"\n").unwrap();
        assert!(bad.apply_to(&mut Config::default()).is_err());
    }
}
