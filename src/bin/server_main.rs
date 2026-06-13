use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qsshd", version = env!("GIT_VERSION"), about = "qsshd - SFTP/SSH server over QUIC")]
struct Args {
    /// Listen address (can be specified multiple times; defaults to [::]:1022 and 0.0.0.0:1022)
    #[arg(short, long)]
    listen: Vec<SocketAddr>,

    /// TLS certificate file (auto-generated if not provided)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key file (auto-generated if not provided)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Disable authentication (for testing only)
    #[arg(long)]
    no_auth: bool,

    /// Wire transport: "quic" (default, interoperable) or "veil" (obfuscated,
    /// indistinguishable-from-random UDP — use when a middlebox filters QUIC).
    #[arg(long, default_value = "quic")]
    protocol: qsftp::transport::Protocol,

    /// Shared passphrase for the VEIL transport (required when --protocol veil).
    /// Both server and client must use the same value. Can be set via QSSH_PROTOCOL_KEY.
    #[arg(long, env = "QSSH_PROTOCOL_KEY", hide_env_values = true)]
    protocol_key: Option<String>,

    /// Verbose/debug output
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let default_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();

    let listen_addrs = if args.listen.is_empty() {
        vec![
            "[::]:1022".parse().unwrap(),
            "0.0.0.0:1022".parse().unwrap(),
        ]
    } else {
        args.listen
    };

    let home = dirs_or_default();
    let cert_path = args
        .cert
        .unwrap_or_else(|| home.join(".qsftp").join("server.crt"));
    let key_path = args
        .key
        .unwrap_or_else(|| home.join(".qsftp").join("server.key"));

    let (certs, key) = qsftp::cert::load_or_generate_certs(&cert_path, &key_path)?;
    let server_config = qsftp::cert::build_server_config(certs, key)?;

    qsftp::server::run_server_proto(
        &listen_addrs,
        server_config,
        args.no_auth,
        args.protocol,
        args.protocol_key.as_deref(),
    )
    .await
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}
