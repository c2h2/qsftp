use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[derive(Parser)]
#[command(name = "qscp", about = "SCP-style file copy over QUIC")]
struct Args {
    /// Source: [user@host:]path
    source: String,

    /// Destination: [user@host:]path
    dest: String,

    /// Recursive copy
    #[arg(short, long)]
    recursive: bool,

    /// Port number
    #[arg(short = 'P', long, default_value = "1022")]
    port: u16,

    /// Identity file (SSH private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Password (optional, prompts if not given)
    #[arg(long, env = "QSFTP_PASSWORD", hide = true)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();

    let src = parse_path_spec(&args.source);
    let dst = parse_path_spec(&args.dest);

    match (&src, &dst) {
        (PathSpec::Remote { user, host, path }, PathSpec::Local { path: local_path }) => {
            // Download
            let addr: SocketAddr = format!("{}:{}", host, args.port).parse()?;
            let client = connect_and_auth(addr, user, host, args.identity.as_deref(), &args.password).await?;

            let local = PathBuf::from(local_path);
            if args.recursive {
                download_recursive(&client, path, &local).await?;
            } else {
                eprintln!("Downloading {} -> {}", path, local.display());
                client.download(path, &local).await?;
            }
        }
        (PathSpec::Local { path: local_path }, PathSpec::Remote { user, host, path }) => {
            // Upload
            let addr: SocketAddr = format!("{}:{}", host, args.port).parse()?;
            let client = connect_and_auth(addr, user, host, args.identity.as_deref(), &args.password).await?;

            let local = PathBuf::from(local_path);
            if args.recursive {
                upload_recursive(&client, &local, path).await?;
            } else {
                eprintln!("Uploading {} -> {}", local.display(), path);
                client.upload(&local, path).await?;
            }
        }
        _ => {
            anyhow::bail!("One of source or destination must be remote (user@host:path)");
        }
    }

    eprintln!("Done.");
    Ok(())
}

enum PathSpec {
    Local { path: String },
    Remote { user: String, host: String, path: String },
}

fn parse_path_spec(s: &str) -> PathSpec {
    // user@host:path
    if let Some(colon_pos) = s.find(':') {
        let before_colon = &s[..colon_pos];
        if let Some(at_pos) = before_colon.find('@') {
            let user = &before_colon[..at_pos];
            let host = &before_colon[at_pos + 1..];
            let path = &s[colon_pos + 1..];
            return PathSpec::Remote {
                user: user.to_string(),
                host: host.to_string(),
                path: if path.is_empty() {
                    ".".to_string()
                } else {
                    path.to_string()
                },
            };
        }
    }
    PathSpec::Local {
        path: s.to_string(),
    }
}

async fn download_recursive(client: &QsftpClient, remote_dir: &str, local_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(local_dir).await?;

    let resp = client
        .command(&Request::Ls {
            path: remote_dir.to_string(),
        })
        .await?;

    match resp {
        Response::DirListing { entries } => {
            for entry in entries {
                let remote_path = format!("{}/{}", remote_dir, entry.name);
                let local_path = local_dir.join(&entry.name);

                if entry.is_dir {
                    Box::pin(download_recursive(client, &remote_path, &local_path)).await?;
                } else {
                    eprintln!("Downloading {}", remote_path);
                    client.download(&remote_path, &local_path).await?;
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("Failed to list {}: {}", remote_dir, message);
        }
        _ => {
            anyhow::bail!("Unexpected response");
        }
    }

    Ok(())
}

async fn connect_and_auth(
    addr: SocketAddr,
    user: &str,
    host: &str,
    identity: Option<&Path>,
    password: &Option<String>,
) -> Result<QsftpClient> {
    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;

    // Try SSH key auth first
    if let Ok(private_key) = qsftp::ssh_auth::find_private_key(identity) {
        match QsftpClient::authenticate_key(connection.clone(), user, &private_key).await {
            Ok(client) => {
                eprintln!("Authenticated with SSH key.");
                return Ok(client);
            }
            Err(e) => {
                tracing::debug!("SSH key auth failed: {}", e);
            }
        }
    }

    // Fall back to password
    let pw = get_password(password, user, host)?;
    let (connection2, _endpoint2) = QsftpClient::connect(addr, "localhost").await?;
    QsftpClient::authenticate(connection2, user, &pw).await
}

fn get_password(provided: &Option<String>, user: &str, host: &str) -> Result<String> {
    if let Some(pw) = provided {
        return Ok(pw.clone());
    }
    rpassword::read_password_from_tty(Some(&format!("{}@{}'s password: ", user, host)))
        .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))
}

async fn upload_recursive(client: &QsftpClient, local_dir: &Path, remote_dir: &str) -> Result<()> {
    // Create remote directory
    let _ = client
        .command(&Request::Mkdir {
            path: remote_dir.to_string(),
        })
        .await?;

    let mut dir = tokio::fs::read_dir(local_dir).await?;
    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.metadata().await?;
        let name = entry.file_name().to_string_lossy().to_string();
        let remote_path = format!("{}/{}", remote_dir, name);
        let local_path = entry.path();

        if meta.is_dir() {
            Box::pin(upload_recursive(client, &local_path, &remote_path)).await?;
        } else {
            eprintln!("Uploading {}", local_path.display());
            client.upload(&local_path, &remote_path).await?;
        }
    }

    Ok(())
}
