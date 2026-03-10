use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qsftp-server", about = "QSFTP server - SFTP over QUIC")]
struct Args {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:1022")]
    listen: SocketAddr,

    /// TLS certificate file (auto-generated if not provided)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key file (auto-generated if not provided)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Disable authentication (for testing only)
    #[arg(long)]
    no_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let home = dirs_or_default();
    let cert_path = args
        .cert
        .unwrap_or_else(|| home.join(".qsftp").join("server.crt"));
    let key_path = args
        .key
        .unwrap_or_else(|| home.join(".qsftp").join("server.key"));

    let (certs, key) = qsftp::cert::load_or_generate_certs(&cert_path, &key_path)?;
    let server_config = qsftp::cert::build_server_config(certs, key)?;

    qsftp::server::run_server(args.listen, server_config, args.no_auth).await
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}
