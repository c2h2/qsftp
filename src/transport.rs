//! Transport abstraction: lets qsftp run over either QUIC (`quinn`) or our
//! custom obfuscated UDP protocol VEIL ([`crate::veil`]).
//!
//! The whole codebase opens streams and reads/writes bytes through these three
//! enums, so switching transports is a single `--protocol` flag at the edges;
//! none of the protocol/forwarding logic needs to know which is underneath.
//!
//! Both transports already expose the same QUIC-shaped stream API, so each
//! method here is a thin dispatch.

use anyhow::Result;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::veil;

/// Which wire transport to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Standard QUIC over UDP (interoperable, but DPI-recognisable).
    Quic,
    /// VEIL: obfuscated, indistinguishable-from-random UDP transport.
    Veil,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Quic
    }
}

impl FromStr for Protocol {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "quic" => Ok(Protocol::Quic),
            "veil" => Ok(Protocol::Veil),
            other => anyhow::bail!("unknown protocol '{}' (use 'quic' or 'veil')", other),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Protocol::Quic => "quic",
            Protocol::Veil => "veil",
        })
    }
}

impl clap::ValueEnum for Protocol {
    fn value_variants<'a>() -> &'a [Self] {
        &[Protocol::Quic, Protocol::Veil]
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Protocol::Quic => clap::builder::PossibleValue::new("quic")
                .help("Standard QUIC (interoperable, DPI-recognisable)"),
            Protocol::Veil => clap::builder::PossibleValue::new("veil")
                .help("Obfuscated UDP, indistinguishable from random"),
        })
    }
}

// ── Connection ────────────────────────────────────────────────────────────────

/// A transport connection — either a QUIC connection or a VEIL connection.
#[derive(Clone)]
pub enum Conn {
    Quic(quinn::Connection),
    Veil(veil::VeilConnection),
}

impl Conn {
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        match self {
            Conn::Quic(c) => {
                let (s, r) = c.open_bi().await?;
                Ok((SendStream::Quic(s), RecvStream::Quic(r)))
            }
            Conn::Veil(c) => {
                let (s, r) = c.open_bi().await?;
                Ok((SendStream::Veil(s), RecvStream::Veil(r)))
            }
        }
    }

    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        match self {
            Conn::Quic(c) => {
                let (s, r) = c.accept_bi().await?;
                Ok((SendStream::Quic(s), RecvStream::Quic(r)))
            }
            Conn::Veil(c) => {
                let (s, r) = c.accept_bi().await?;
                Ok((SendStream::Veil(s), RecvStream::Veil(r)))
            }
        }
    }

    pub async fn open_uni(&self) -> Result<SendStream> {
        match self {
            Conn::Quic(c) => Ok(SendStream::Quic(c.open_uni().await?)),
            Conn::Veil(c) => Ok(SendStream::Veil(c.open_uni().await?)),
        }
    }

    pub async fn accept_uni(&self) -> Result<RecvStream> {
        match self {
            Conn::Quic(c) => Ok(RecvStream::Quic(c.accept_uni().await?)),
            Conn::Veil(c) => Ok(RecvStream::Veil(c.accept_uni().await?)),
        }
    }

    /// Resolves when the connection closes; returns a human-readable reason.
    pub async fn closed(&self) -> String {
        match self {
            Conn::Quic(c) => c.closed().await.to_string(),
            Conn::Veil(c) => c.closed().await,
        }
    }

    pub fn remote_address(&self) -> SocketAddr {
        match self {
            Conn::Quic(c) => c.remote_address(),
            Conn::Veil(c) => c.remote_address(),
        }
    }
}

// ── Send stream ────────────────────────────────────────────────────────────────

pub enum SendStream {
    Quic(quinn::SendStream),
    Veil(veil::VeilSend),
}

impl SendStream {
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            SendStream::Quic(s) => {
                s.write_all(buf).await?;
                Ok(())
            }
            SendStream::Veil(s) => s.write_all(buf).await,
        }
    }

    pub fn finish(&mut self) -> Result<()> {
        match self {
            SendStream::Quic(s) => {
                let _ = s.finish();
                Ok(())
            }
            SendStream::Veil(s) => s.finish(),
        }
    }

    pub async fn stopped(&mut self) -> Result<()> {
        match self {
            SendStream::Quic(s) => {
                let _ = s.stopped().await;
                Ok(())
            }
            SendStream::Veil(s) => s.stopped().await,
        }
    }
}

// ── Recv stream ────────────────────────────────────────────────────────────────

pub enum RecvStream {
    Quic(quinn::RecvStream),
    Veil(veil::VeilRecv),
}

impl RecvStream {
    /// Read up to `buf.len()` bytes; `Ok(None)` at end of stream.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        match self {
            RecvStream::Quic(r) => Ok(r.read(buf).await?),
            RecvStream::Veil(r) => r.read(buf).await,
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            RecvStream::Quic(r) => {
                r.read_exact(buf).await?;
                Ok(())
            }
            RecvStream::Veil(r) => r.read_exact(buf).await,
        }
    }
}

// ── tokio AsyncRead / AsyncWrite so transport streams work with the generic
//    write_msg / read_msg / pipe_chunks helpers in protocol.rs. ────────────────

use tokio::io::{AsyncRead, AsyncWrite};

impl AsyncWrite for SendStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            SendStream::Quic(s) => AsyncWrite::poll_write(std::pin::Pin::new(s), cx, buf),
            SendStream::Veil(s) => AsyncWrite::poll_write(std::pin::Pin::new(s), cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SendStream::Quic(s) => AsyncWrite::poll_flush(std::pin::Pin::new(s), cx),
            SendStream::Veil(s) => AsyncWrite::poll_flush(std::pin::Pin::new(s), cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SendStream::Quic(s) => AsyncWrite::poll_shutdown(std::pin::Pin::new(s), cx),
            SendStream::Veil(s) => AsyncWrite::poll_shutdown(std::pin::Pin::new(s), cx),
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RecvStream::Quic(r) => AsyncRead::poll_read(std::pin::Pin::new(r), cx, buf),
            RecvStream::Veil(r) => AsyncRead::poll_read(std::pin::Pin::new(r), cx, buf),
        }
    }
}
