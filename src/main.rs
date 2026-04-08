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

        /// Shared secret for Noise Protocol encryption
        #[arg(long)]
        secret: String,

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

        /// Shared secret (must match server)
        #[arg(long)]
        secret: String,

        /// Unique client identifier
        #[arg(long, default_value = "default")]
        client_id: String,

        /// Number of pre-established data connections
        #[arg(long, default_value_t = 200)]
        pool_size: u16,

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

            if let Some(file_config) = load_file_config(&config_path)? {
                file_config.apply_to(&mut config);
            }

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
            pool_size,
            reconnect_interval,
            verbosity,
        } => {
            init_tracing(&verbosity);

            // Validate server_addr has a port
            if !server_addr.contains(':') || server_addr.ends_with(':') {
                eprintln!("error: --server-addr must include a port, e.g. 192.168.1.1:9090");
                std::process::exit(1);
            }

            // Load file config for tunnel settings
            let file_config = load_file_config(&config_path)?;

            let mut cfg = ClientConfig {
                server_addr,
                secret,
                client_id,
                pool_size,
                reconnect_interval: std::time::Duration::from_secs(reconnect_interval),
            };

            // Override from TOML if present
            if let Some(fc) = file_config
                && let Some(ref tunnel) = fc.tunnel {
                    if let Some(ref addr) = tunnel.server_addr {
                        cfg.server_addr = addr.clone();
                    }
                    if let Some(ref id) = tunnel.client_id {
                        cfg.client_id = id.clone();
                    }
                    if let Some(ps) = tunnel.pool_size {
                        cfg.pool_size = ps;
                    }
                    if let Some(ri) = tunnel.reconnect_interval {
                        cfg.reconnect_interval = std::time::Duration::from_secs(ri);
                    }
                }

            let shutdown = CancellationToken::new();
            tokio::spawn(signal::shutdown_signal(shutdown.clone()));
            run_client(cfg, shutdown).await;
        }
    }

    Ok(())
}
