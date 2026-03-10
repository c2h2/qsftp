use anyhow::Result;
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

use crate::auth;
use crate::protocol::*;

pub async fn run_server(
    listen_addr: SocketAddr,
    server_config: quinn::ServerConfig,
    no_auth: bool,
) -> Result<()> {
    let endpoint = Endpoint::server(server_config, listen_addr)?;
    info!("QSFTP server listening on {} (no_auth={})", listen_addr, no_auth);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, no_auth).await {
                error!("Connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming, no_auth: bool) -> Result<()> {
    let connection = incoming.await?;
    let remote = connection.remote_address();
    info!("New connection from {}", remote);

    // First bi-stream must be auth
    let (mut send, mut recv) = connection.accept_bi().await?;
    let req: Request = read_msg(&mut recv).await?;

    let user_info = match req {
        Request::Auth { username, password } => {
            info!("Auth attempt from {} for user '{}'", remote, username);
            if no_auth {
                // No-auth mode: accept any credentials, resolve user info
                let uname = username.clone();
                match tokio::task::spawn_blocking(move || auth::get_user_info_public(&uname)).await? {
                    Ok(info) => {
                        let resp = Response::AuthOk {
                            home_dir: info.home.clone(),
                        };
                        write_msg(&mut send, &resp).await?;
                        info!("User '{}' accepted (no-auth mode) from {}", info.username, remote);
                        info
                    }
                    Err(_) => {
                        // Fallback: use current user
                        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                        let resp = Response::AuthOk {
                            home_dir: home.clone(),
                        };
                        write_msg(&mut send, &resp).await?;
                        auth::UserInfo {
                            username,
                            uid: 0,
                            gid: 0,
                            home,
                        }
                    }
                }
            } else {
                match tokio::task::spawn_blocking(move || {
                    auth::authenticate_shadow(&username, &password)
                })
                .await?
                {
                    Ok(info) => {
                        let resp = Response::AuthOk {
                            home_dir: info.home.clone(),
                        };
                        write_msg(&mut send, &resp).await?;
                        info!("User '{}' authenticated from {}", info.username, remote);
                        info
                    }
                    Err(e) => {
                        let resp = Response::Error {
                            message: format!("Authentication failed: {}", e),
                        };
                        write_msg(&mut send, &resp).await?;
                        warn!("Auth failed from {}: {}", remote, e);
                        return Ok(());
                    }
                }
            }
        }
        Request::AuthPubKey { username, pub_key } => {
            info!("SSH key auth attempt from {} for user '{}'", remote, username);
            if no_auth {
                // No-auth mode: skip key verification, just generate challenge
                let challenge = crate::ssh_auth::generate_challenge();
                write_msg(&mut send, &Response::AuthChallenge { challenge: challenge.clone() }).await?;

                // Wait for signed response
                let sign_req: Request = read_msg(&mut recv).await?;
                match sign_req {
                    Request::AuthPubKeySign { signature } => {
                        // In no-auth mode, verify the signature anyway (proves client has the key)
                        let uname = username.clone();
                        let pk = pub_key.clone();
                        match tokio::task::spawn_blocking(move || {
                            crate::ssh_auth::verify_challenge(&pk, &challenge, &signature)
                        }).await? {
                            Ok(true) => {
                                let uname2 = uname.clone();
                                match tokio::task::spawn_blocking(move || auth::get_user_info_public(&uname2)).await? {
                                    Ok(info) => {
                                        write_msg(&mut send, &Response::AuthOk { home_dir: info.home.clone() }).await?;
                                        info!("User '{}' key-authenticated (no-auth mode) from {}", info.username, remote);
                                        info
                                    }
                                    Err(_) => {
                                        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                                        write_msg(&mut send, &Response::AuthOk { home_dir: home.clone() }).await?;
                                        auth::UserInfo { username: uname, uid: 0, gid: 0, home }
                                    }
                                }
                            }
                            _ => {
                                write_msg(&mut send, &Response::Error { message: "Signature verification failed".into() }).await?;
                                return Ok(());
                            }
                        }
                    }
                    _ => {
                        write_msg(&mut send, &Response::Error { message: "Expected AuthPubKeySign".into() }).await?;
                        return Ok(());
                    }
                }
            } else {
                // Real auth: check authorized_keys then challenge
                let uname = username.clone();
                let pk = pub_key.clone();
                let key_found = tokio::task::spawn_blocking(move || {
                    crate::ssh_auth::check_authorized_keys(&uname, &pk)
                }).await??;

                if !key_found {
                    write_msg(&mut send, &Response::Error { message: "Public key not authorized".into() }).await?;
                    warn!("Key not in authorized_keys for user '{}' from {}", username, remote);
                    return Ok(());
                }

                let challenge = crate::ssh_auth::generate_challenge();
                write_msg(&mut send, &Response::AuthChallenge { challenge: challenge.clone() }).await?;

                let sign_req: Request = read_msg(&mut recv).await?;
                match sign_req {
                    Request::AuthPubKeySign { signature } => {
                        let pk2 = pub_key.clone();
                        match tokio::task::spawn_blocking(move || {
                            crate::ssh_auth::verify_challenge(&pk2, &challenge, &signature)
                        }).await? {
                            Ok(true) => {
                                let uname = username.clone();
                                let info = tokio::task::spawn_blocking(move || auth::get_user_info_public(&uname)).await??;
                                write_msg(&mut send, &Response::AuthOk { home_dir: info.home.clone() }).await?;
                                info!("User '{}' key-authenticated from {}", info.username, remote);
                                info
                            }
                            _ => {
                                write_msg(&mut send, &Response::Error { message: "Signature verification failed".into() }).await?;
                                warn!("Signature verification failed for user '{}' from {}", username, remote);
                                return Ok(());
                            }
                        }
                    }
                    _ => {
                        write_msg(&mut send, &Response::Error { message: "Expected AuthPubKeySign".into() }).await?;
                        return Ok(());
                    }
                }
            }
        }
        _ => {
            let resp = Response::Error {
                message: "Must authenticate first".to_string(),
            };
            write_msg(&mut send, &resp).await?;
            return Ok(());
        }
    };

    // Close auth stream
    send.finish()?;
    drop(send);
    drop(recv);

    let cwd = PathBuf::from(&user_info.home);

    // Session state shared across stream handlers
    let session = std::sync::Arc::new(tokio::sync::Mutex::new(SessionState {
        _user: user_info,
        cwd,
    }));

    // Handle subsequent command streams
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("Connection closed by {}", remote);
                break;
            }
            Err(e) => {
                error!("Stream accept error from {}: {}", remote, e);
                break;
            }
        };

        let session = session.clone();
        let conn = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_command(send, recv, session, conn).await {
                error!("Command error: {}", e);
            }
        });
    }

    Ok(())
}

struct SessionState {
    _user: auth::UserInfo,
    cwd: PathBuf,
}

async fn handle_command(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: std::sync::Arc<tokio::sync::Mutex<SessionState>>,
    connection: Connection,
) -> Result<()> {
    let req: Request = read_msg(&mut recv).await?;

    match req {
        Request::Ls { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match list_dir(&resolved).await {
                Ok(entries) => write_msg(&mut send, &Response::DirListing { entries }).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Stat { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match stat_path(&resolved).await {
                Ok(stat) => write_msg(&mut send, &Response::FileStat { stat }).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Mkdir { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match tokio::fs::create_dir_all(&resolved).await {
                Ok(_) => write_msg(&mut send, &Response::Ok).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Rm { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            let result = if resolved.is_dir() {
                tokio::fs::remove_dir_all(&resolved).await
            } else {
                tokio::fs::remove_file(&resolved).await
            };
            match result {
                Ok(_) => write_msg(&mut send, &Response::Ok).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Rename { old_path, new_path } => {
            let (resolved_old, resolved_new) = {
                let sess = session.lock().await;
                (
                    resolve_path(&sess.cwd, &old_path),
                    resolve_path(&sess.cwd, &new_path),
                )
            };
            match tokio::fs::rename(&resolved_old, &resolved_new).await {
                Ok(_) => write_msg(&mut send, &Response::Ok).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Chmod { path, mode } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match set_permissions(&resolved, mode).await {
                Ok(_) => write_msg(&mut send, &Response::Ok).await?,
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?
                }
            }
        }
        Request::Pwd => {
            let path = {
                let sess = session.lock().await;
                sess.cwd.to_string_lossy().to_string()
            };
            write_msg(&mut send, &Response::Pwd { path }).await?;
        }
        Request::Cd { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            if resolved.is_dir() {
                let canonical = match tokio::fs::canonicalize(&resolved).await {
                    Ok(p) => p,
                    Err(e) => {
                        write_msg(
                            &mut send,
                            &Response::Error {
                                message: e.to_string(),
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                };
                {
                    let mut sess = session.lock().await;
                    sess.cwd = canonical;
                }
                write_msg(&mut send, &Response::Ok).await?;
            } else {
                write_msg(
                    &mut send,
                    &Response::Error {
                        message: format!("{}: Not a directory", resolved.display()),
                    },
                )
                .await?;
            }
        }
        Request::Get { path } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match tokio::fs::metadata(&resolved).await {
                Ok(meta) => {
                    let size = meta.len();
                    write_msg(&mut send, &Response::FileData { size }).await?;

                    // Send file data on a new uni stream
                    let mut uni_send = connection.open_uni().await?;

                    let mut file = tokio::io::BufReader::with_capacity(
                        CHUNK_SIZE,
                        tokio::fs::File::open(&resolved).await?,
                    );
                    let mut buf = vec![0u8; CHUNK_SIZE];
                    loop {
                        use tokio::io::AsyncReadExt;
                        let n = file.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        uni_send.write_all(&buf[..n]).await?;
                    }
                    uni_send.finish()?;
                }
                Err(e) => {
                    write_msg(
                        &mut send,
                        &Response::Error {
                            message: e.to_string(),
                        },
                    )
                    .await?;
                }
            }
        }
        Request::Put { path, size, mode } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };

            // Create parent directories if needed
            if let Some(parent) = resolved.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            write_msg(&mut send, &Response::Ok).await?;

            // Receive file data on a uni stream
            let mut uni_recv = connection.accept_uni().await?;
            let mut file = tokio::io::BufWriter::with_capacity(
                CHUNK_SIZE,
                tokio::fs::File::create(&resolved).await?,
            );
            let mut remaining = size;
            let mut buf = vec![0u8; CHUNK_SIZE];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, CHUNK_SIZE);
                match uni_recv.read(&mut buf[..to_read]).await? {
                    Some(n) => {
                        file.write_all(&buf[..n]).await?;
                        remaining -= n as u64;
                    }
                    None => break,
                }
            }
            file.flush().await?;
            drop(file);

            // Set permissions
            set_permissions(&resolved, mode).await?;

            // Send confirmation on the command stream
            write_msg(&mut send, &Response::Ok).await?;
        }
        Request::Auth { .. } | Request::AuthPubKey { .. } | Request::AuthPubKeySign { .. } => {
            write_msg(
                &mut send,
                &Response::Error {
                    message: "Already authenticated".to_string(),
                },
            )
            .await?;
        }
    }

    send.finish()?;
    Ok(())
}

fn resolve_path(cwd: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

async fn list_dir(path: &Path) -> Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut dir = tokio::fs::read_dir(path).await?;
    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.metadata().await?;
        entries.push(DirEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            size: meta.len(),
            mode: meta.mode(),
            mtime: meta
                .modified()
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64
                })
                .unwrap_or(0),
            is_dir: meta.is_dir(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

async fn stat_path(path: &Path) -> Result<FileStat> {
    let meta = tokio::fs::metadata(path).await?;
    Ok(FileStat {
        size: meta.len(),
        mode: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: meta
            .modified()
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            })
            .unwrap_or(0),
        is_dir: meta.is_dir(),
    })
}

async fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    tokio::fs::set_permissions(path, perms).await?;
    Ok(())
}
