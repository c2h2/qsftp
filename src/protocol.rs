use serde::{Deserialize, Serialize};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 1022;
pub const ALPN_QSFTP: &[u8] = b"qsftp/1";
pub const DEFAULT_SSH_PORT: u16 = 1022;

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

/// Capabilities advertised by the server after auth.
/// The client sends Caps{} to query; old servers return an error which the
/// client treats as "no capabilities" for backwards compatibility.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ServerCaps {
    /// Server supports zstd per-transfer compression
    pub zstd: bool,
    /// Server version string (e.g. "dc34306" or "1.2.3")
    #[serde(default)]
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Auth { username: String, password: String },
    /// SSH key auth step 1: client sends username + public key (OpenSSH format)
    AuthPubKey { username: String, pub_key: String },
    /// SSH key auth step 2: client sends signature over the challenge
    AuthPubKeySign { signature: Vec<u8> },
    /// Capability query — sent after auth; old servers return Error (caps = none)
    Caps,
    Ls { path: String },
    Stat { path: String },
    Mkdir { path: String },
    Rm { path: String },
    Rename { old_path: String, new_path: String },
    Chmod { path: String, mode: u32 },
    Get { path: String, compress: bool },
    Put { path: String, size: u64, mode: u32, compress: bool },
    Pwd,
    Cd { path: String },
    /// Open an interactive shell session (PTY)
    Shell {
        /// Terminal type (e.g. "xterm-256color")
        term: String,
        /// Initial terminal width in columns
        cols: u16,
        /// Initial terminal height in rows
        rows: u16,
    },
    /// Execute a single command and return its output
    Exec {
        /// Command line to execute via /bin/sh -c
        command: String,
    },
    /// Terminal resize notification (sent mid-session)
    WindowChange { cols: u16, rows: u16 },
    /// Local → remote TCP forward: server opens connection to target host:port
    /// and bridges it to the stream.  Client sends this request then streams
    /// raw TCP data on the same bi-directional QUIC stream.
    TcpForward {
        /// Target host
        host: String,
        /// Target port
        port: u16,
    },
    /// Remote port forward bind: server listens on bind:port and for each
    /// accepted TCP connection opens a new bi-stream to the client.
    RemoteForwardBind {
        /// Bind address on server (e.g. "127.0.0.1" or "0.0.0.0")
        bind: String,
        /// Port to listen on
        port: u16,
    },
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
    FileData { size: u64, compress: bool },
    /// Response to Caps query
    CapsOk { caps: ServerCaps },
    /// Shell/exec session opened; data flows on the same bi-stream after this
    SessionOk,
    /// Shell/exec exited with the given status code
    ExitStatus { code: i32 },
    /// Exec stdout/stderr chunk (used in non-interactive exec mode)
    ExecData { stdout: Vec<u8>, stderr: Vec<u8>, done: bool },
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

/// zstd compression level: 3 is the default sweet spot (fast, decent ratio).
pub const ZSTD_LEVEL: i32 = 3;

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

/// Like `pipe_chunks` but compresses each chunk with zstd before writing.
/// Returns `(uncompressed_bytes, compressed_bytes, writer)`.
pub async fn pipe_chunks_compress<R, W>(
    mut reader: R,
    mut writer: W,
    chunk_size: usize,
    queue_depth: usize,
) -> Result<(u64, u64, W)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(queue_depth);

    let reader_task = tokio::spawn(async move {
        let mut raw_total = 0u64;
        loop {
            let mut buf = vec![0u8; chunk_size];
            let mut filled = 0usize;
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
            raw_total += filled as u64;
            // Compress on the blocking thread pool to avoid stalling the async runtime
            let compressed = tokio::task::spawn_blocking(move || {
                zstd::encode_all(buf.as_slice(), ZSTD_LEVEL)
            })
            .await??;
            // Frame: 4-byte little-endian length prefix + compressed data
            let mut framed = Vec::with_capacity(4 + compressed.len());
            framed.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            framed.extend_from_slice(&compressed);
            if tx.send(bytes::Bytes::from(framed)).await.is_err() {
                break;
            }
        }
        Ok::<u64, anyhow::Error>(raw_total)
    });

    let writer_task = tokio::spawn(async move {
        let mut compressed_total = 0u64;
        while let Some(chunk) = rx.recv().await {
            compressed_total += chunk.len() as u64;
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok::<(u64, W), anyhow::Error>((compressed_total, writer))
    });

    let (read_res, write_res) = tokio::join!(reader_task, writer_task);
    let (compressed_total, writer) = write_res??;
    Ok((read_res??, compressed_total, writer))
}

/// Receives a zstd-compressed stream (framed with 4-byte LE length prefixes)
/// and writes decompressed data to writer.
/// Returns `(uncompressed_bytes, writer)`.
pub async fn pipe_chunks_decompress<R, W>(
    mut reader: R,
    mut writer: W,
    queue_depth: usize,
) -> Result<(u64, W)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(queue_depth);

    let reader_task = tokio::spawn(async move {
        loop {
            // Read 4-byte frame length
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
            let frame_len = u32::from_le_bytes(len_buf) as usize;
            if frame_len == 0 {
                break;
            }
            let mut compressed = vec![0u8; frame_len];
            reader.read_exact(&mut compressed).await?;
            // Decompress on the blocking thread pool
            let decompressed = tokio::task::spawn_blocking(move || {
                zstd::decode_all(compressed.as_slice())
            })
            .await??;
            if tx.send(bytes::Bytes::from(decompressed)).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let writer_task = tokio::spawn(async move {
        let mut total = 0u64;
        while let Some(chunk) = rx.recv().await {
            total += chunk.len() as u64;
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok::<(u64, W), anyhow::Error>((total, writer))
    });

    let (read_res, write_res) = tokio::join!(reader_task, writer_task);
    read_res??;
    let (total, writer) = write_res??;
    Ok((total, writer))
}
