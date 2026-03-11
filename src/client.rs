use anyhow::Result;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::*;

pub struct QsftpClient {
    pub connection: quinn::Connection,
    pub home_dir: String,
    pub remote_cwd: String,
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
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint.connect(server_addr, server_name)?.await?;
        tracing::info!("Connected to {}", server_addr);
        Ok((connection, endpoint))
    }

    /// Password-based authentication
    pub async fn authenticate(
        connection: quinn::Connection,
        username: &str,
        password: &str,
    ) -> Result<Self> {
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
                Ok(Self {
                    connection,
                    home_dir,
                    remote_cwd,
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
        let (mut send, mut recv) = connection.open_bi().await?;

        // Step 1: send username + public key
        let pub_key_str = crate::ssh_auth::public_key_openssh(private_key);
        let req = Request::AuthPubKey {
            username: username.to_string(),
            pub_key: pub_key_str,
        };
        write_msg(&mut send, &req).await?;
        let resp: Response = read_msg(&mut recv).await?;

        match resp {
            Response::AuthChallenge { challenge } => {
                // Step 2: sign the challenge
                let signature = crate::ssh_auth::sign_challenge(private_key, &challenge)?;
                let req = Request::AuthPubKeySign { signature };
                write_msg(&mut send, &req).await?;

                // Step 3: wait for result
                let resp: Response = read_msg(&mut recv).await?;
                match resp {
                    Response::AuthOk { home_dir } => {
                        let remote_cwd = home_dir.clone();
                        send.finish()?;
                        Ok(Self {
                            connection,
                            home_dir,
                            remote_cwd,
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
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let req = Request::Get {
            path: remote_path.to_string(),
        };
        write_msg(&mut send, &req).await?;
        send.finish()?;

        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::FileData { size } => {
                // Receive data on uni stream with timeout
                let mut uni_recv = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    self.connection.accept_uni(),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for server to start file transfer"))??;

                if let Some(parent) = local_path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }

                let mut file = tokio::io::BufWriter::with_capacity(
                    CHUNK_SIZE,
                    tokio::fs::File::create(local_path).await?,
                );
                let mut received = 0u64;
                let mut buf = vec![0u8; CHUNK_SIZE];
                let start = std::time::Instant::now();
                let mut last_report = start;

                while received < size {
                    let to_read = std::cmp::min((size - received) as usize, CHUNK_SIZE);
                    let n = match uni_recv.read(&mut buf[..to_read]).await? {
                        Some(n) => n,
                        None => break,
                    };
                    file.write_all(&buf[..n]).await?;
                    received += n as u64;

                    let now = std::time::Instant::now();
                    if now.duration_since(last_report).as_millis() > 500 {
                        let elapsed = now.duration_since(start).as_secs_f64();
                        let speed = received as f64 / elapsed / 1024.0 / 1024.0;
                        let pct = (received as f64 / size as f64 * 100.0) as u32;
                        eprint!(
                            "\r  {}% ({}/{} bytes) {:.1} MiB/s",
                            pct,
                            format_size(received),
                            format_size(size),
                            speed
                        );
                        last_report = now;
                    }
                }
                file.flush().await?;

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
        };
        write_msg(&mut send, &req).await?;

        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::Ok => {
                // Send file data on uni stream
                let mut uni_send = self.connection.open_uni().await?;

                let mut file = tokio::io::BufReader::with_capacity(
                    CHUNK_SIZE,
                    tokio::fs::File::open(local_path).await?,
                );
                let mut sent = 0u64;
                let mut buf = vec![0u8; CHUNK_SIZE];
                let start = std::time::Instant::now();
                let mut last_report = start;

                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    uni_send.write_all(&buf[..n]).await?;
                    sent += n as u64;

                    let now = std::time::Instant::now();
                    if now.duration_since(last_report).as_millis() > 500 {
                        let elapsed = now.duration_since(start).as_secs_f64();
                        let speed = sent as f64 / elapsed / 1024.0 / 1024.0;
                        let pct = (sent as f64 / size as f64 * 100.0) as u32;
                        eprint!(
                            "\r  {}% ({}/{} bytes) {:.1} MiB/s",
                            pct,
                            format_size(sent),
                            format_size(size),
                            speed
                        );
                        last_report = now;
                    }
                }
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
                eprintln!(
                    "\r  100% {} transferred in {:.1}s ({:.1} MiB/s)       ",
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
