use serde::{Deserialize, Serialize};
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 1022;
pub const CHUNK_SIZE: usize = 256 * 1024; // 256 KiB
pub const ALPN_QSFTP: &[u8] = b"qsftp/1";

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
