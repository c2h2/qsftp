use serde::{Deserialize, Serialize};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 1022;
pub const ALPN_QSFTP: &[u8] = b"qsftp/1";

const MIN_CHUNK: usize = 256 * 1024;      // 256 KiB
const MAX_CHUNK: usize = 16 * 1024 * 1024; // 16 MiB

/// Choose chunk/buffer size based on file size:
///   < 1 MiB   → 256 KiB
///   < 16 MiB  → 1 MiB
///   < 256 MiB → 4 MiB
///   >= 256 MiB → 16 MiB
pub fn dynamic_chunk_size(file_size: u64) -> usize {
    if file_size < 1024 * 1024 {
        MIN_CHUNK
    } else if file_size < 16 * 1024 * 1024 {
        1024 * 1024
    } else if file_size < 256 * 1024 * 1024 {
        4 * 1024 * 1024
    } else {
        MAX_CHUNK
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Auth { username: String, password: String },
    /// SSH key auth step 1: client sends username + public key (OpenSSH format)
    AuthPubKey { username: String, pub_key: String },
    /// SSH key auth step 2: client sends signature over the challenge
    AuthPubKeySign { signature: Vec<u8> },
    Ls { path: String },
    Stat { path: String },
    Mkdir { path: String },
    Rm { path: String },
    Rename { old_path: String, new_path: String },
    Chmod { path: String, mode: u32 },
    Get { path: String },
    Put { path: String, size: u64, mode: u32 },
    Pwd,
    Cd { path: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Ok,
    Error { message: String },
    AuthOk { home_dir: String },
    /// Challenge for SSH key auth
    AuthChallenge { challenge: Vec<u8> },
    DirListing { entries: Vec<DirEntry> },
    FileStat { stat: FileStat },
    Pwd { path: String },
    FileData { size: u64 },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileStat {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub is_dir: bool,
}

pub async fn write_msg<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let data = bincode::serialize(msg)?;
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&data).await?;
    Ok(())
}

pub async fn read_msg<R: AsyncReadExt + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

/// Pipelined chunk transfer: reader and writer run concurrently with a
/// bounded channel between them so disk I/O and network I/O overlap.
/// `queue_depth` controls how many chunks can be in-flight at once.
/// Returns `(bytes_transferred, writer)` so the caller can finalize the
/// writer (e.g. call `finish()` on a quinn SendStream).
pub async fn pipe_chunks<R, W>(
    mut reader: R,
    mut writer: W,
    chunk_size: usize,
    queue_depth: usize,
) -> Result<(u64, W)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(queue_depth);

    // Reader task: read chunks from source and push onto channel
    let reader_task = tokio::spawn(async move {
        let mut total = 0u64;
        loop {
            let mut buf = vec![0u8; chunk_size];
            let mut filled = 0usize;
            // Fill the buffer fully before sending (avoids tiny sends)
            while filled < chunk_size {
                match reader.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) => return Err(anyhow::anyhow!(e)),
                }
            }
            if filled == 0 {
                break;
            }
            buf.truncate(filled);
            total += filled as u64;
            if tx.send(bytes::Bytes::from(buf)).await.is_err() {
                break;
            }
        }
        Ok::<u64, anyhow::Error>(total)
    });

    // Writer task: drain channel and write to destination, then return writer
    let writer_task = tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok::<W, anyhow::Error>(writer)
    });

    let (read_res, write_res) = tokio::join!(reader_task, writer_task);
    let writer = write_res??;
    Ok((read_res??, writer))
}
