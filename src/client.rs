use anyhow::Result;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::path::Path;

use crate::protocol::*;

pub struct QsftpClient {
    pub connection: quinn::Connection,
    pub home_dir: String,
    pub remote_cwd: String,
    /// Whether the server supports (and we will use) zstd compression
    pub compress: bool,
    /// TLS cipher suite negotiated for this connection
    pub tls_cipher: String,
    /// Remote server version string; empty if server is too old to report it
    pub server_version: String,
    /// True if the server responded to the Caps request (i.e. is not an old server)
    pub caps_negotiated: bool,
}

/// Extract TLS info from a quinn connection.
/// QUIC mandates TLS 1.3; quinn with rustls uses AES-128-GCM-SHA256 or
/// CHACHA20-POLY1305-SHA256. We report what we can from handshake data.
fn tls_cipher_name(conn: &quinn::Connection) -> String {
    let alpn = conn.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    // QUIC always uses TLS 1.3; rustls defaults to AES-128-GCM-SHA256
    format!("TLS_AES_128_GCM_SHA256 (TLS 1.3, ALPN={})", alpn)
}

/// Query server capabilities after auth. Old servers that don't recognise
/// the Caps request will return an Error — we catch that and return default
/// (no) capabilities so the client degrades gracefully.
/// Returns `(caps, negotiated)` where `negotiated` is false for old servers.
async fn negotiate_caps(connection: &quinn::Connection) -> (crate::protocol::ServerCaps, bool) {
    let result: anyhow::Result<(crate::protocol::ServerCaps, bool)> = async {
        let (mut send, mut recv) = connection.open_bi().await?;
        write_msg(&mut send, &Request::Caps).await?;
        send.finish()?;
        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::CapsOk { caps } => Ok((caps, true)),
            // Old server returns Error — treat as no caps
            Response::Error { .. } => Ok((crate::protocol::ServerCaps::default(), false)),
            _ => Ok((crate::protocol::ServerCaps::default(), false)),
        }
    }.await;
    result.unwrap_or((crate::protocol::ServerCaps::default(), false))
}

impl QsftpClient {
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<(quinn::Connection, Endpoint)> {
        let client_config = crate::cert::build_client_config()?;

        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        };

        // Enlarge OS UDP socket buffers before handing the socket to Quinn.
        // macOS defaults to ~9 KB send buffer which causes ENOBUFS under load.
        // We request 4 MiB; the OS will silently cap it at the system maximum
        // (typically 4–7 MiB on macOS, up to kern.ipc.maxsockbuf).
        let udp_sock = std::net::UdpSocket::bind(bind_addr)?;
        const SOCK_BUF: usize = 4 * 1024 * 1024; // 4 MiB
        set_socket_buf(&udp_sock, SOCK_BUF);
        udp_sock.set_nonblocking(true)?;

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime"))?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp_sock,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config);

        tracing::debug!("Connecting to {} (SNI: {})...", server_addr, server_name);
        let connection = endpoint.connect(server_addr, server_name)?.await?;
        tracing::debug!("QUIC connection established to {}", server_addr);
        Ok((connection, endpoint))
    }

    /// Password-based authentication
    pub async fn authenticate(
        connection: quinn::Connection,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        tracing::debug!("Trying password authentication for user '{}'", username);
        let (mut send, mut recv) = connection.open_bi().await?;
        let req = Request::Auth {
            username: username.to_string(),
            password: password.to_string(),
        };
        write_msg(&mut send, &req).await?;
        let resp: Response = read_msg(&mut recv).await?;

        match resp {
            Response::AuthOk { home_dir } => {
                let remote_cwd = home_dir.clone();
                send.finish()?;
                let tls_cipher = tls_cipher_name(&connection);
                let (caps, caps_negotiated) = negotiate_caps(&connection).await;
                Ok(Self {
                    connection,
                    home_dir,
                    remote_cwd,
                    compress: caps.zstd,
                    tls_cipher,
                    server_version: caps.version,
                    caps_negotiated,
                })
            }
            Response::Error { message } => {
                anyhow::bail!("Authentication failed: {}", message);
            }
            _ => {
                anyhow::bail!("Unexpected response");
            }
        }
    }

    /// SSH key-based authentication (challenge-response)
    pub async fn authenticate_key(
        connection: quinn::Connection,
        username: &str,
        private_key: &ssh_key::PrivateKey,
    ) -> Result<Self> {
        tracing::debug!(
            "Trying SSH key authentication for user '{}' (key type: {})",
            username,
            private_key.algorithm()
        );
        let (mut send, mut recv) = connection.open_bi().await?;

        // Step 1: send username + public key
        let pub_key_str = crate::ssh_auth::public_key_openssh(private_key);
        tracing::debug!("Sending public key to server");
        let req = Request::AuthPubKey {
            username: username.to_string(),
            pub_key: pub_key_str,
        };
        write_msg(&mut send, &req).await?;
        let resp: Response = read_msg(&mut recv).await?;

        match resp {
            Response::AuthChallenge { challenge } => {
                tracing::debug!("Received auth challenge ({} bytes), signing...", challenge.len());
                // Step 2: sign the challenge
                let signature = crate::ssh_auth::sign_challenge(private_key, &challenge)?;
                tracing::debug!("Challenge signed, sending signature");
                let req = Request::AuthPubKeySign { signature };
                write_msg(&mut send, &req).await?;

                // Step 3: wait for result
                let resp: Response = read_msg(&mut recv).await?;
                match resp {
                    Response::AuthOk { home_dir } => {
                        let remote_cwd = home_dir.clone();
                        send.finish()?;
                        let tls_cipher = tls_cipher_name(&connection);
                        let (caps, caps_negotiated) = negotiate_caps(&connection).await;
                        Ok(Self {
                            connection,
                            home_dir,
                            remote_cwd,
                            compress: caps.zstd,
                            tls_cipher,
                            server_version: caps.version,
                            caps_negotiated,
                        })
                    }
                    Response::Error { message } => {
                        anyhow::bail!("Key authentication failed: {}", message);
                    }
                    _ => anyhow::bail!("Unexpected response after key sign"),
                }
            }
            Response::Error { message } => {
                anyhow::bail!("Key authentication failed: {}", message);
            }
            _ => {
                anyhow::bail!("Unexpected response to key auth request");
            }
        }
    }

    pub async fn command(&self, req: &Request) -> Result<Response> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_msg(&mut send, req).await?;
        send.finish()?;
        let resp: Response = read_msg(&mut recv).await?;
        Ok(resp)
    }

    pub async fn download(&self, remote_path: &str, local_path: &Path) -> Result<u64> {
        let compress = self.compress;
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let req = Request::Get {
            path: remote_path.to_string(),
            compress,
        };
        write_msg(&mut send, &req).await?;
        send.finish()?;

        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::FileData { size, compress: use_compress } => {
                // Receive data on uni stream with timeout
                let uni_recv = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    self.connection.accept_uni(),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for server to start file transfer"))??;

                if let Some(parent) = local_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }

                let chunk = crate::protocol::dynamic_chunk_size(size);
                let file = tokio::fs::File::create(local_path).await?;
                let start = std::time::Instant::now();

                let received = if use_compress {
                    let (n, _file) = crate::protocol::pipe_chunks_decompress(uni_recv, file, 8).await?;
                    n
                } else {
                    let (n, _file) = crate::protocol::pipe_chunks(uni_recv, file, chunk, 8).await?;
                    n
                };

                let elapsed = start.elapsed().as_secs_f64();
                let speed = received as f64 / elapsed / 1024.0 / 1024.0;
                eprintln!(
                    "\r  100% {} transferred in {:.1}s ({:.1} MiB/s)       ",
                    format_size(received),
                    elapsed,
                    speed
                );

                Ok(received)
            }
            Response::Error { message } => {
                anyhow::bail!("{}", message);
            }
            _ => {
                anyhow::bail!("Unexpected response");
            }
        }
    }

    pub async fn upload(&self, local_path: &Path, remote_path: &str) -> Result<u64> {
        let compress = self.compress;
        let meta = tokio::fs::metadata(local_path).await?;
        let size = meta.len();
        let mode = {
            use std::os::unix::fs::MetadataExt;
            meta.mode()
        };

        let (mut send, mut recv) = self.connection.open_bi().await?;
        let req = Request::Put {
            path: remote_path.to_string(),
            size,
            mode,
            compress,
        };
        write_msg(&mut send, &req).await?;

        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::Ok => {
                // Send file data on uni stream
                let uni_send = self.connection.open_uni().await?;

                let chunk = crate::protocol::dynamic_chunk_size(size);
                let file = tokio::fs::File::open(local_path).await?;
                let start = std::time::Instant::now();

                let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let progress2 = progress.clone();

                // Progress reporter task
                let progress_task = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
                    interval.tick().await; // skip immediate first tick
                    loop {
                        interval.tick().await;
                        let done = progress2.load(std::sync::atomic::Ordering::Relaxed);
                        if done == u64::MAX { break; }
                        let elapsed = start.elapsed().as_secs_f64();
                        let speed = if elapsed > 0.0 { done as f64 / elapsed / 1024.0 / 1024.0 } else { 0.0 };
                        let pct = if size > 0 { done * 100 / size } else { 0 };
                        eprint!("\r  {}% {} / {} ({:.1} MiB/s)    ",
                            pct, format_size(done), format_size(size), speed);
                    }
                });

                let (sent, mut uni_send) = if compress {
                    let (raw, _comp, w) = crate::protocol::pipe_chunks_compress_progress(file, uni_send, chunk, 8, progress).await?;
                    (raw, w)
                } else {
                    crate::protocol::pipe_chunks_progress(file, uni_send, chunk, 8, progress).await?
                };
                uni_send.finish()?;

                // Wait for server confirmation
                let resp: Response = read_msg(&mut recv).await?;
                match resp {
                    Response::Ok => {}
                    Response::Error { message } => {
                        anyhow::bail!("Upload failed: {}", message);
                    }
                    _ => {
                        anyhow::bail!("Unexpected response after upload");
                    }
                }

                let elapsed = start.elapsed().as_secs_f64();
                let speed = sent as f64 / elapsed / 1024.0 / 1024.0;
                // Signal progress task to stop, then print final line
                progress_task.abort();
                eprintln!(
                    "\r  100% {} in {:.1}s ({:.1} MiB/s)       ",
                    format_size(sent),
                    elapsed,
                    speed
                );

                send.finish()?;
                Ok(sent)
            }
            Response::Error { message } => {
                anyhow::bail!("{}", message);
            }
            _ => {
                anyhow::bail!("Unexpected response");
            }
        }
    }
}

/// Try to set SO_SNDBUF and SO_RCVBUF on a UDP socket.
/// Failures are ignored — the OS will just use whatever it allows.
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

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.1}G", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}
