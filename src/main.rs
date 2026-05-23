use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use sox::client::{ClientConfig, run_client};
use sox::config::{AuthConfig, Config, FileConfig};
use sox::server;
use sox::signal;

#[derive(Parser)]
#[command(
    name = "sox",
    version,
    about = "High-performance SOCKS proxy with reverse tunnel support",
    long_about = "sox is a cross-platform SOCKS4/4a/5 proxy server with:\n\
    - Reverse tunnel support (NAT traversal)\n\
    - Noise Protocol encrypted tunnels\n\
    - Username/password authentication\n\
    - TCP keepalive & connection limits\n\
    - Graceful shutdown with connection draining"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a standalone SOCKS proxy (direct connections)
    Standalone {
        /// Listen address
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,

        /// Configuration file (TOML)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Maximum concurrent connections
        #[arg(long, default_value_t = 10_000)]
        max_connections: usize,

        /// Maximum connections per source IP
        #[arg(long, default_value_t = 100)]
        max_per_ip: usize,

        /// Relay idle timeout in seconds
        #[arg(long, default_value_t = 300)]
        idle_timeout: u64,

        /// Add user credentials (format: user:pass, repeatable)
        #[arg(short, long = "user")]
        users: Vec<String>,

        /// Enable monitor dashboard on this address (e.g. 0.0.0.0:8080)
        #[arg(short, long)]
        monitor: Option<SocketAddr>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(short, long, default_value = "info")]
        verbosity: String,
    },

    /// Run as a tunnel server (public network, accepts tunnel clients)
    Server {
        /// SOCKS service listen address
        #[arg(short = 's', long, default_value = "0.0.0.0:1080")]
        socks_listen: SocketAddr,

        /// Tunnel listen address (for client connections)
        #[arg(short = 't', long, default_value = "0.0.0.0:9090")]
        tunnel_listen: String,

        /// Configuration file (TOML)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Shared secret for Noise Protocol (or set [tunnel] secret in config)
        #[arg(long)]
        secret: Option<String>,

        /// Add user credentials for SOCKS auth (format: user:pass, repeatable)
        #[arg(short, long = "user")]
        users: Vec<String>,

        /// Maximum concurrent connections
        #[arg(long, default_value_t = 10_000)]
        max_connections: usize,

        /// Enable monitor dashboard on this address
        #[arg(short, long)]
        monitor: Option<SocketAddr>,

        /// Log level
        #[arg(short, long, default_value = "info")]
        verbosity: String,
    },

    /// Run as a tunnel client (internal network, connects to server)
    Client {
        /// Tunnel server address (host:port)
        #[arg(short = 's', long)]
        server_addr: String,

        /// Configuration file (TOML)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Shared secret, must match server (or set [tunnel] secret in config)
        #[arg(long)]
        secret: Option<String>,

        /// Unique client identifier
        #[arg(long, default_value = "default")]
        client_id: String,

        /// Number of concurrent yamux sessions
        #[arg(long, default_value_t = 8)]
        tunnel_sessions: u16,

        /// Reconnect interval in seconds
        #[arg(long, default_value_t = 5)]
        reconnect_interval: u64,

        /// Log level
        #[arg(short, long, default_value = "info")]
        verbosity: String,
    },
}

fn parse_user_credentials(users: &[String]) -> Result<AuthConfig, String> {
    if users.is_empty() {
        return Ok(AuthConfig::None);
    }
    let mut creds = Vec::new();
    for entry in users {
        let (user, pass) = entry
            .split_once(':')
            .ok_or_else(|| format!("invalid user format '{entry}', expected user:pass"))?;
        creds.push((user.to_string(), pass.to_string()));
    }
    Ok(AuthConfig::Password(creds))
}

fn init_tracing(verbosity: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(verbosity)),
        )
        .init();
}

fn load_file_config(path: &Option<PathBuf>) -> Result<Option<FileConfig>, String> {
    match path {
        Some(p) => FileConfig::load(p).map(Some),
        None => Ok(None),
    }
}

/// Resolve the tunnel secret from the CLI flag, falling back to `[tunnel] secret`
/// in the config file.
fn resolve_secret(cli: Option<String>, fc: Option<&FileConfig>) -> Result<String, String> {
    if let Some(s) = cli {
        return Ok(s);
    }
    if let Some(fc) = fc
        && let Some(ref tunnel) = fc.tunnel
        && let Some(ref s) = tunnel.secret
    {
        return Ok(s.clone());
    }
    Err("secret required: pass --secret or set [tunnel] secret in the config file".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Standalone {
            listen,
            config: config_path,
            max_connections,
            max_per_ip,
            idle_timeout,
            users,
            monitor,
            verbosity,
        } => {
            init_tracing(&verbosity);

            let mut config = Config::default();

            // Layer 1: TOML file
            if let Some(file_config) = load_file_config(&config_path)? {
                file_config.apply_to(&mut config);
            }

            // Layer 2: CLI args (override file)
            config.listen_addr = listen;
            config.max_connections = max_connections;
            config.max_connections_per_ip = max_per_ip;
            if idle_timeout == 0 {
                eprintln!(
                    "error: --idle-timeout=0 is invalid (would close every relay instantly)"
                );
                std::process::exit(1);
            }
            config.idle_timeout = std::time::Duration::from_secs(idle_timeout);

            let auth = parse_user_credentials(&users)?;
            if !matches!(auth, AuthConfig::None) {
                config.auth = auth;
            }
            config.monitor_addr = monitor;

            let shutdown = CancellationToken::new();
            tokio::spawn(signal::shutdown_signal(shutdown.clone()));
            server::run_standalone(config, shutdown).await?;
        }

        Commands::Server {
            socks_listen,
            tunnel_listen,
            config: config_path,
            secret,
            users,
            max_connections,
            monitor,
            verbosity,
        } => {
            init_tracing(&verbosity);

            let mut config = Config::default();
            let file_config = load_file_config(&config_path)?;
            if let Some(ref fc) = file_config {
                fc.apply_to(&mut config);
            }
            let secret = resolve_secret(secret, file_config.as_ref())?;

            config.listen_addr = socks_listen;
            config.max_connections = max_connections;
            config.monitor_addr = monitor;

            let auth = parse_user_credentials(&users)?;
            if !matches!(auth, AuthConfig::None) {
                config.auth = auth;
            }

            let shutdown = CancellationToken::new();
            tokio::spawn(signal::shutdown_signal(shutdown.clone()));
            server::run_server(config, tunnel_listen, secret, shutdown).await?;
        }

        Commands::Client {
            server_addr,
            config: config_path,
            secret,
            client_id,
            tunnel_sessions,
            reconnect_interval,
            verbosity,
        } => {
            init_tracing(&verbosity);

            // Validate server_addr has a port
            if !server_addr.contains(':') || server_addr.ends_with(':') {
                eprintln!("error: --server-addr must include a port, e.g. 192.168.1.1:9090");
                std::process::exit(1);
            }

            let file_config = load_file_config(&config_path)?;
            let secret = resolve_secret(secret, file_config.as_ref())?;

            let mut cfg = ClientConfig {
                server_addr,
                secret,
                client_id,
                tunnel_sessions,
                max_streams: 256,
                // 必須遠大於 `max_streams × 256 KiB`（= 64 MiB at 256 streams），
                // 否則 yamux 的 per-stream BDP auto-tuning 拿不到 headroom，
                // 單一 stream 永遠卡在 256 KiB initial credit → 在 RTT~10ms 的
                // 跨網路情境會被夾到約 200 Mbps。256 MiB 留 192 MiB 餘裕，
                // 足以讓單流長到 BDP×2（1 Gbps × 60ms ≈ 15 MiB×2）。
                // A/B-verified 2026-05-23: at 10ms RTT this lifts single-stream
                // throughput from ~170 Mbps to ~1.38 Gbps (8× improvement).
                recv_window_mb: 256,
                reconnect_interval: std::time::Duration::from_secs(reconnect_interval),
                reconnect_max: std::time::Duration::from_secs(60),
                connect_timeout: std::time::Duration::from_secs(10),
                idle_timeout: std::time::Duration::from_secs(300),
            };

            // Override from TOML if present.
            if let Some(ref fc) = file_config
                && let Some(ref tunnel) = fc.tunnel
            {
                if let Some(ref addr) = tunnel.server_addr {
                    cfg.server_addr = addr.clone();
                }
                if let Some(ref id) = tunnel.client_id {
                    cfg.client_id = id.clone();
                }
                if let Some(v) = tunnel.tunnel_sessions {
                    cfg.tunnel_sessions = v;
                }
                if let Some(v) = tunnel.max_streams_per_session {
                    cfg.max_streams = v;
                }
                if let Some(v) = tunnel.recv_window_mb {
                    cfg.recv_window_mb = v;
                }
                if let Some(v) = tunnel.reconnect_interval {
                    cfg.reconnect_interval = std::time::Duration::from_secs(v);
                }
                if let Some(v) = tunnel.reconnect_max {
                    cfg.reconnect_max = std::time::Duration::from_secs(v);
                }
            }

            let shutdown = CancellationToken::new();
            tokio::spawn(signal::shutdown_signal(shutdown.clone()));
            run_client(cfg, shutdown).await;
        }
    }

    Ok(())
}
