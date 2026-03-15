use anyhow::Result;
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use crate::auth;
use crate::protocol::*;


/// Try to enlarge SO_SNDBUF / SO_RCVBUF on a UDP socket.
/// Failures are silently ignored — the OS will use whatever it allows.
fn set_socket_buf(sock: &std::net::UdpSocket, size: usize) {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let sz = size as libc::c_int;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    }
}

pub async fn run_server(
    listen_addrs: &[SocketAddr],
    server_config: quinn::ServerConfig,
    no_auth: bool,
) -> Result<()> {
    const SOCK_BUF: usize = 4 * 1024 * 1024; // 4 MiB

    let mut endpoints = Vec::new();
    for addr in listen_addrs {
        let udp_sock = match std::net::UdpSocket::bind(addr) {
            Ok(s) => s,
            Err(e) => { warn!("Failed to bind {}: {}", addr, e); continue; }
        };
        set_socket_buf(&udp_sock, SOCK_BUF);
        udp_sock.set_nonblocking(true)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime"))?;
        match Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config.clone()),
            udp_sock,
            runtime,
        ) {
            Ok(ep) => {
                info!("QSFTP server listening on {} (no_auth={})", addr, no_auth);
                endpoints.push(ep);
            }
            Err(e) => {
                warn!("Failed to create endpoint on {}: {}", addr, e);
            }
        }
    }

    if endpoints.is_empty() {
        anyhow::bail!("Failed to bind any listen address");
    }

    let mut set = tokio::task::JoinSet::new();
    for endpoint in endpoints {
        set.spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(incoming, no_auth).await {
                        error!("Connection error: {}", e);
                    }
                });
            }
        });
    }

    set.join_next().await;
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
    let home = user_info.home.clone();

    // Session state shared across stream handlers
    let session = std::sync::Arc::new(tokio::sync::Mutex::new(SessionState {
        _user: user_info,
        cwd,
        home,
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
    home: String,
}

async fn handle_command(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: std::sync::Arc<tokio::sync::Mutex<SessionState>>,
    connection: Connection,
) -> Result<()> {
    let req: Request = read_msg(&mut recv).await?;

    let user_home = {
        let sess = session.lock().await;
        sess.home.clone()
    };

    match req {
        Request::Caps => {
            let caps = crate::protocol::ServerCaps {
                zstd: true,
                version: env!("GIT_VERSION").to_string(),
            };
            write_msg(&mut send, &Response::CapsOk { caps }).await?;
        }
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
        Request::Get { path, compress } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };
            match tokio::fs::metadata(&resolved).await {
                Ok(meta) => {
                    let size = meta.len();
                    let chunk = crate::protocol::dynamic_chunk_size(size);
                    write_msg(&mut send, &Response::FileData { size, compress }).await?;

                    // Send file data on a new uni stream
                    let uni_send = connection.open_uni().await?;
                    let file = tokio::fs::File::open(&resolved).await?;

                    if compress {
                        let (_, _, mut uni_send) = crate::protocol::pipe_chunks_compress(file, uni_send, chunk, 8).await?;
                        uni_send.finish()?;
                    } else {
                        let (_, mut uni_send) = crate::protocol::pipe_chunks(file, uni_send, chunk, 8).await?;
                        uni_send.finish()?;
                    }
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
        Request::Put { path, size, mode, compress } => {
            let resolved = {
                let sess = session.lock().await;
                resolve_path(&sess.cwd, &path)
            };

            // Create parent directories if needed
            if let Some(parent) = resolved.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let chunk = crate::protocol::dynamic_chunk_size(size);
            write_msg(&mut send, &Response::Ok).await?;

            // Receive file data on a uni stream
            let uni_recv = connection.accept_uni().await?;
            let file = tokio::fs::File::create(&resolved).await?;

            if compress {
                crate::protocol::pipe_chunks_decompress(uni_recv, file, 8).await?;
            } else {
                crate::protocol::pipe_chunks(uni_recv, file, chunk, 8).await?;
            }

            // Set permissions
            set_permissions(&resolved, mode).await?;

            // Send confirmation on the command stream
            write_msg(&mut send, &Response::Ok).await?;
        }
        Request::Shell { term, cols, rows } => {
            handle_shell(send, recv, &user_home, &term, cols, rows).await?;
            return Ok(());
        }
        Request::Exec { command } => {
            handle_exec(send, recv, &user_home, &command).await?;
            return Ok(());
        }
        Request::TcpForward { host, port } => {
            handle_tcp_forward(send, recv, &host, port).await?;
            return Ok(());
        }
        Request::RemoteForwardBind { bind, port } => {
            handle_remote_forward_bind(send, connection.clone(), &bind, port).await?;
            return Ok(());
        }
        Request::WindowChange { .. } => {
            // Window changes arrive on the shell stream, not here
            write_msg(&mut send, &Response::Error { message: "WindowChange only valid inside shell session".into() }).await?;
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

// ── Shell session ────────────────────────────────────────────────────────────

async fn handle_shell(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    home: &str,
    term: &str,
    cols: u16,
    rows: u16,
) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    // Open a PTY pair
    let (master_fd, slave_fd) = open_pty(cols, rows)?;

    // Spawn shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut child = unsafe {
        let slave_raw = slave_fd;
        let mut cmd = tokio::process::Command::new(&shell);
        cmd.current_dir(home)
            .env("TERM", term)
            .env("HOME", home)
            .stdin(std::process::Stdio::from_raw_fd(slave_raw))
            .stdout(std::process::Stdio::from_raw_fd(slave_raw))
            .stderr(std::process::Stdio::from_raw_fd(slave_raw))
            .pre_exec(|| {
                // Make this process the session leader and controlling terminal
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0i32);
                Ok(())
            });
        cmd.spawn()?
    };

    write_msg(&mut send, &Response::SessionOk).await?;

    // Wrap master fd in async I/O
    let master_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let master_async = tokio::fs::File::from_std(master_file);
    let (mut pty_read, mut pty_write) = tokio::io::split(master_async);

    // Network → PTY (client keystrokes → shell)
    let net_to_pty = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut buf = [0u8; 4096];
        loop {
            let n = match recv.read(&mut buf).await {
                Ok(Some(n)) => n,
                _ => break,
            };
            if n == 0 { break; }
            if pty_write.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    // PTY → network (shell output → client)
    let pty_to_net = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 4096];
        loop {
            let n = match pty_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send.write_all(&buf[..n]).await.is_err() { break; }
        }
        let _ = send.finish();
    });

    let code = child.wait().await.map(|s| s.code().unwrap_or(0)).unwrap_or(1);
    net_to_pty.abort();
    pty_to_net.abort();

    info!("Shell exited with code {}", code);
    Ok(())
}

// ── Remote port forward (-R) server side ────────────────────────────────────

async fn handle_remote_forward_bind(
    mut send: quinn::SendStream,
    conn: Connection,
    bind: &str,
    port: u16,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match tokio::net::TcpListener::bind(format!("{}:{}", bind, port)).await {
        Ok(l) => l,
        Err(e) => {
            write_msg(&mut send, &Response::Error {
                message: format!("Cannot bind {}:{}: {}", bind, port, e),
            }).await?;
            send.finish()?;
            return Ok(());
        }
    };

    write_msg(&mut send, &Response::SessionOk).await?;
    // Keep ctrl send open so client knows we're alive; drop when we exit.
    info!("Remote forward: listening on {}:{}", bind, port);

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        tracing::debug!("Remote forward: inbound TCP from {}", peer);
        let conn2 = conn.clone();

        tokio::spawn(async move {
            let result: Result<()> = async {
                // Open a new bi-stream toward the client
                let (mut fwd_send, mut fwd_recv) = conn2.open_bi().await?;
                let (mut tcp_read, mut tcp_write) = tcp.into_split();

                let t2q = tokio::spawn(async move {
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = match tcp_read.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if fwd_send.write_all(&buf[..n]).await.is_err() { break; }
                    }
                    let _ = fwd_send.finish();
                });

                let q2t = tokio::spawn(async move {
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = match fwd_recv.read(&mut buf).await {
                            Ok(Some(n)) if n > 0 => n,
                            _ => break,
                        };
                        if tcp_write.write_all(&buf[..n]).await.is_err() { break; }
                    }
                });

                let _ = tokio::join!(t2q, q2t);
                Ok(())
            }.await;
            if let Err(e) = result {
                tracing::debug!("Remote forward session error: {}", e);
            }
        });
    }

    Ok(())
}

fn open_pty(cols: u16, rows: u16) -> Result<(i32, i32)> {
    unsafe {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let mut ws = libc::winsize {
            ws_col: cols,
            ws_row: rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        );
        if ret != 0 {
            anyhow::bail!("openpty failed: {}", std::io::Error::last_os_error());
        }
        Ok((master, slave))
    }
}

// ── Exec (non-interactive command) ──────────────────────────────────────────

async fn handle_exec(
    mut send: quinn::SendStream,
    mut _recv: quinn::RecvStream,
    home: &str,
    command: &str,
) -> Result<()> {
    let output = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .current_dir(home)
        .output()
        .await?;

    let code = output.status.code().unwrap_or(1);

    write_msg(&mut send, &Response::ExecData {
        stdout: output.stdout,
        stderr: output.stderr,
        done: true,
    }).await?;
    write_msg(&mut send, &Response::ExitStatus { code }).await?;
    send.finish()?;
    Ok(())
}

// ── TCP port forwarding ──────────────────────────────────────────────────────

async fn handle_tcp_forward(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    host: &str,
    port: u16,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = format!("{}:{}", host, port);
    let tcp = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            write_msg(&mut send, &Response::Error {
                message: format!("Cannot connect to {}: {}", target, e),
            }).await?;
            send.finish()?;
            return Ok(());
        }
    };

    write_msg(&mut send, &Response::SessionOk).await?;

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let net_to_tcp = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let n = match recv.read(&mut buf).await {
                Ok(Some(n)) if n > 0 => n,
                _ => break,
            };
            if tcp_write.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    let tcp_to_net = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let n = match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send.write_all(&buf[..n]).await.is_err() { break; }
        }
        let _ = send.finish();
    });

    let _ = tokio::join!(net_to_tcp, tcp_to_net);
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
