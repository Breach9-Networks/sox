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
    // Options that also exist in the TOML file are `Option`s with no clap
    // default: precedence is CLI flag > config file > built-in default, and a
    // clap default would be indistinguishable from an explicit flag — it would
    // silently override the file.
    /// Run as a standalone SOCKS proxy (direct connections)
    Standalone {
        /// Listen address [default: 127.0.0.1:1080]
        #[arg(short, long)]
        listen: Option<SocketAddr>,

        /// Configuration file (TOML)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Maximum concurrent connections [default: 10000]
        #[arg(long)]
        max_connections: Option<usize>,

        /// Maximum connections per source IP [default: 100]
        #[arg(long)]
        max_per_ip: Option<usize>,

        /// Relay idle timeout in seconds [default: 300]
        #[arg(long)]
        idle_timeout: Option<u64>,

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
        /// SOCKS service listen address [default: 0.0.0.0:1080]
        #[arg(short = 's', long)]
        socks_listen: Option<SocketAddr>,

        /// Tunnel listen address, for client connections [default: 0.0.0.0:9090]
        #[arg(short = 't', long)]
        tunnel_listen: Option<String>,

        /// Configuration file (TOML)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Shared secret for Noise Protocol (or set [tunnel] secret in config)
        #[arg(long)]
        secret: Option<String>,

        /// Add user credentials for SOCKS auth (format: user:pass, repeatable)
        #[arg(short, long = "user")]
        users: Vec<String>,

        /// Maximum concurrent connections [default: 10000]
        #[arg(long)]
        max_connections: Option<usize>,

        /// Enable monitor dashboard on this address
        #[arg(short, long)]
        monitor: Option<SocketAddr>,

        /// Log level
        #[arg(short, long, default_value = "info")]
        verbosity: String,
    },

    /// Run as a tunnel client (internal network, connects to server)
    Client {
        /// Tunnel server address, host:port (or set [tunnel] server_addr in config)
        #[arg(short = 's', long)]
        server_addr: Option<String>,

        /// Configuration file (TOML)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Shared secret, must match server (or set [tunnel] secret in config)
        #[arg(long)]
        secret: Option<String>,

        /// Unique client identifier [default: default]
        #[arg(long)]
        client_id: Option<String>,

        /// Number of concurrent yamux sessions [default: 8]
        #[arg(long)]
        tunnel_sessions: Option<u16>,

        /// Reconnect interval in seconds [default: 5]
        #[arg(long)]
        reconnect_interval: Option<u64>,

        /// Log level
        #[arg(short, long, default_value = "info")]
        verbosity: String,
    },
}

/// Built-in defaults of the CLI front end. They differ from `Config::default()`
/// (a library-level default) on purpose: a proxy started from the command line
/// gets conservative limits unless told otherwise.
const DEFAULT_MAX_CONNECTIONS: usize = 10_000;
const DEFAULT_MAX_PER_IP: usize = 100;

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

/// Seconds → `Duration` for a relay idle timeout; 0 is rejected — it would
/// close every relay before any data flows.
fn idle_timeout_from_secs(secs: u64) -> Result<std::time::Duration, String> {
    if secs == 0 {
        return Err("--idle-timeout=0 is invalid (would close every relay instantly)".into());
    }
    Ok(std::time::Duration::from_secs(secs))
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

            // Layer 0: built-in defaults.
            let mut config = Config {
                max_connections: DEFAULT_MAX_CONNECTIONS,
                max_connections_per_ip: DEFAULT_MAX_PER_IP,
                ..Config::default()
            };

            // Layer 1: TOML file.
            if let Some(file_config) = load_file_config(&config_path)? {
                file_config.apply_to(&mut config)?;
            }

            // Layer 2: CLI args — only the ones actually given.
            if let Some(v) = listen {
                config.listen_addr = v;
            }
            if let Some(v) = max_connections {
                config.max_connections = v;
            }
            if let Some(v) = max_per_ip {
                config.max_connections_per_ip = v;
            }
            if let Some(v) = idle_timeout {
                config.idle_timeout = idle_timeout_from_secs(v)?;
            }
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

            let mut config = Config {
                listen_addr: "0.0.0.0:1080".parse().unwrap(),
                max_connections: DEFAULT_MAX_CONNECTIONS,
                ..Config::default()
            };
            let file_config = load_file_config(&config_path)?;
            if let Some(ref fc) = file_config {
                fc.apply_to(&mut config)?;
            }
            let secret = resolve_secret(secret, file_config.as_ref())?;
            let file_tunnel = file_config.as_ref().and_then(|fc| fc.tunnel.as_ref());

            if let Some(v) = socks_listen {
                config.listen_addr = v;
            }
            if let Some(v) = max_connections {
                config.max_connections = v;
            }
            let tunnel_listen = tunnel_listen
                .or_else(|| file_tunnel.and_then(|t| t.listen.clone()))
                .unwrap_or_else(|| "0.0.0.0:9090".into());
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

            let file_config = load_file_config(&config_path)?;
            let secret = resolve_secret(secret, file_config.as_ref())?;
            let file_tunnel = file_config.as_ref().and_then(|fc| fc.tunnel.as_ref());

            // The general timeouts ([top-level] connect/idle/dns/drain) apply
            // to the client's side of each proxied flow as well.
            let mut base = Config::default();
            if let Some(ref fc) = file_config {
                fc.apply_to(&mut base)?;
            }

            let server_addr = server_addr
                .or_else(|| file_tunnel.and_then(|t| t.server_addr.clone()))
                .ok_or("server address required: pass --server-addr or set [tunnel] server_addr")?;
            if !server_addr.contains(':') || server_addr.ends_with(':') {
                return Err("server address must include a port, e.g. 192.168.1.1:9090".into());
            }
            let tunnel_sessions = tunnel_sessions
                .or_else(|| file_tunnel.and_then(|t| t.tunnel_sessions))
                .unwrap_or(8);
            if tunnel_sessions == 0 {
                return Err("tunnel_sessions must be at least 1".into());
            }

            // Same precedence as the other modes: CLI > file > default.
            let secs = std::time::Duration::from_secs;
            let cfg = ClientConfig {
                server_addr,
                secret,
                client_id: client_id
                    .or_else(|| file_tunnel.and_then(|t| t.client_id.clone()))
                    .unwrap_or_else(|| "default".into()),
                tunnel_sessions,
                max_streams: file_tunnel
                    .and_then(|t| t.max_streams_per_session)
                    .unwrap_or(base.tunnel_max_streams),
                // Must stay well above `max_streams × 256 KiB` — see
                // `Config::tunnel_recv_window_mb` and tasks/lessons.md.
                recv_window_mb: file_tunnel
                    .and_then(|t| t.recv_window_mb)
                    .unwrap_or(base.tunnel_recv_window_mb),
                // Degenerate values (0, absurdly large) are clamped by `Backoff`.
                reconnect_interval: secs(
                    reconnect_interval
                        .or_else(|| file_tunnel.and_then(|t| t.reconnect_interval))
                        .unwrap_or(5),
                ),
                reconnect_max: secs(file_tunnel.and_then(|t| t.reconnect_max).unwrap_or(60)),
                connect_timeout: base.connect_timeout,
                idle_timeout: base.idle_timeout,
                dns_timeout: base.dns_timeout,
                drain_timeout: base.drain_timeout,
            };

            let shutdown = CancellationToken::new();
            tokio::spawn(signal::shutdown_signal(shutdown.clone()));
            run_client(cfg, shutdown).await;
        }
    }

    Ok(())
}
