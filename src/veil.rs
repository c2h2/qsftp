//! VEIL — an obfuscated, reliable, multiplexed transport over UDP.
//!
//! Why this exists: some ISPs / middleboxes parse and drop QUIC (they recognise
//! its cleartext Initial header and version field). VEIL is a fully custom UDP
//! protocol whose every packet, from the very first byte, is ChaCha20-Poly1305
//! ciphertext under a pre-shared key. There is no cleartext header, no version
//! number, no handshake fingerprint — on the wire it is indistinguishable from
//! random data. A DPI box has nothing to match a filter rule against.
//!
//! What it provides: a small, QUIC-shaped API — [`VeilConnection`] with
//! `open_bi`/`accept_bi`/`open_uni`/`accept_uni`, each returning [`VeilSend`] /
//! [`VeilRecv`] stream halves with `write_all` / `read` / `read_exact` /
//! `finish` / `stopped` / `closed`. The qsftp client/server code is written
//! against these methods, so it runs over VEIL unchanged.
//!
//! Design (deliberately minimal — not a full QUIC clone):
//!   * Obfuscation: every datagram = random 12-byte nonce ‖ AEAD(key, frame).
//!     Wire bytes are uniformly random; replays/forgeries fail the AEAD tag.
//!   * Reliability: each stream is a numbered sequence of DATA frames with
//!     cumulative ACKs and timer-based retransmission of unacked frames.
//!   * Multiplexing: many concurrent streams over one UDP flow, each tagged
//!     with a stream-id; bi/uni is a flag at open time.
//!   * Establishment: no cleartext handshake — the first datagram that decrypts
//!     under the shared key *is* the connection. The server keys connections by
//!     source address, gated on successful decryption.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use ring::aead::{LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tokio::time::{interval, Instant};

const HKDF_INFO: &[u8] = b"veil/1 chacha20poly1305 transport key";
const MAX_PAYLOAD: usize = 1100;
const RTO: Duration = Duration::from_millis(300);
const KEEPALIVE: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How many DATA frames may be in flight (unacked) per connection before
/// `write_all` blocks. Bounds memory and gives basic congestion control.
const SEND_WINDOW: usize = 256;
/// zstd level for per-frame stream compression. Frames are small (≤1100 B) and
/// latency-sensitive, so level 1 (fast) is the right trade-off; incompressible
/// frames are sent raw via the per-frame flag, so the cost is just a cheap probe.
const VEIL_ZSTD_LEVEL: i32 = 1;

// ── Crypto ────────────────────────────────────────────────────────────────────

/// Shared obfuscation key, derived from a passphrase via HKDF-SHA256.
#[derive(Clone)]
pub struct VeilKey(Arc<LessSafeKey>);

struct KeyLen32;
impl ring::hkdf::KeyType for KeyLen32 {
    fn len(&self) -> usize {
        32
    }
}

impl VeilKey {
    pub fn from_passphrase(passphrase: &str) -> Self {
        let salt = Salt::new(HKDF_SHA256, b"veil/1 static salt");
        let prk = salt.extract(passphrase.as_bytes());
        let okm = prk.expand(&[HKDF_INFO], KeyLen32).expect("hkdf expand");
        let mut key_bytes = [0u8; 32];
        okm.fill(&mut key_bytes).expect("hkdf fill");
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).expect("chacha key");
        VeilKey(Arc::new(LessSafeKey::new(unbound)))
    }

    /// `nonce(12) ‖ ciphertext ‖ tag(16)` — output is indistinguishable from random.
    fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand_fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut in_out)
            .expect("seal");
        let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        out
    }

    /// Returns the plaintext frame, or None if the datagram isn't ours.
    fn open(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < NONCE_LEN + 16 {
            return None;
        }
        let (nb, ct) = datagram.split_at(NONCE_LEN);
        let mut arr = [0u8; NONCE_LEN];
        arr.copy_from_slice(nb);
        let nonce = Nonce::assume_unique_for_key(arr);
        let mut buf = ct.to_vec();
        self.0
            .open_in_place(nonce, ring::aead::Aad::empty(), &mut buf)
            .ok()
            .map(|pt| pt.to_vec())
    }
}

fn rand_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

// ── Frames ──────────────────────────────────────────────────────────────────
// Each decrypted datagram is exactly one frame. First byte = type; ints big-endian.

const F_OPEN: u8 = 1; // [type][sid:8][flags:1]            flags bit0 = bidi
const F_DATA: u8 = 2; // [type][sid:8][seq:8][len:2][bytes]
const F_ACK: u8 = 3; //  [type][sid:8][ack:8]              ack = next-expected seq
const F_FIN: u8 = 4; //  [type][sid:8][final_seq:8]        no more data after final_seq
const F_RST: u8 = 5; //  [type][sid:8]
const F_PING: u8 = 6; // [type]                            keepalive / handshake probe
const F_CLOSE: u8 = 7; // [type]                           graceful connection close

fn fr_open(sid: u64, bidi: bool) -> Vec<u8> {
    let mut v = vec![F_OPEN];
    v.extend_from_slice(&sid.to_be_bytes());
    v.push(if bidi { 1 } else { 0 });
    v
}
/// DATA frame flags (the `flag` byte after `seq`).
const DF_COMPRESSED: u8 = 0x01;

/// Build a DATA frame. When `compress` is set we zstd the payload but keep it
/// only if it actually got smaller — tunnels often carry already-encrypted
/// (incompressible) bytes, so we never let compression expand a frame. The
/// per-frame flag tells the receiver whether to decompress.
///
/// Format: `[F_DATA][sid:8][seq:8][flag:1][len:2][payload]` where `len` is the
/// length of `payload` as it appears on the wire (compressed or raw).
fn fr_data(sid: u64, seq: u64, bytes: &[u8], compress: bool) -> Vec<u8> {
    let (flag, payload): (u8, std::borrow::Cow<[u8]>) = if compress && !bytes.is_empty() {
        match zstd::encode_all(bytes, VEIL_ZSTD_LEVEL) {
            Ok(c) if c.len() < bytes.len() => (DF_COMPRESSED, std::borrow::Cow::Owned(c)),
            _ => (0, std::borrow::Cow::Borrowed(bytes)),
        }
    } else {
        (0, std::borrow::Cow::Borrowed(bytes))
    };
    let mut v = Vec::with_capacity(20 + payload.len());
    v.push(F_DATA);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.push(flag);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&payload);
    v
}
fn fr_ack(sid: u64, ack: u64) -> Vec<u8> {
    let mut v = vec![F_ACK];
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&ack.to_be_bytes());
    v
}
fn fr_fin(sid: u64, final_seq: u64) -> Vec<u8> {
    let mut v = vec![F_FIN];
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&final_seq.to_be_bytes());
    v
}
fn be64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

// ── Public stream halves ──────────────────────────────────────────────────────

/// Send half of a VEIL stream. Subset of `quinn::SendStream` used by qsftp.
pub struct VeilSend {
    sid: u64,
    to_driver: mpsc::Sender<Cmd>,
    next_seq: u64,
    finished: bool,
    closed: Arc<Notify>,
    /// In-flight channel send for the `AsyncWrite::poll_write` path: a reserve
    /// future plus the bytes it will deliver once a slot is free.
    pending: Option<(
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ()>> + Send>>,
        usize,
    )>,
}

impl VeilSend {
    pub async fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = buf.len().min(MAX_PAYLOAD);
            let (chunk, rest) = buf.split_at(n);
            let seq = self.next_seq;
            self.next_seq += 1;
            let (done_tx, done_rx) = oneshot::channel();
            self.to_driver
                .send(Cmd::Send {
                    sid: self.sid,
                    seq,
                    bytes: Bytes::copy_from_slice(chunk),
                    accepted: done_tx,
                })
                .await
                .map_err(|_| anyhow!("connection closed"))?;
            // Blocks while the in-flight window is full (driver delays the reply).
            done_rx.await.map_err(|_| anyhow!("connection closed"))?;
            buf = rest;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        if !self.finished {
            self.finished = true;
            let _ = self.to_driver.try_send(Cmd::Fin {
                sid: self.sid,
                final_seq: self.next_seq,
            });
        }
        Ok(())
    }

    /// Best-effort: resolves when the connection closes (sufficient for the
    /// auth-rejection flush use case the server relies on).
    pub async fn stopped(&mut self) -> Result<()> {
        self.closed.notified().await;
        Ok(())
    }
}

impl Drop for VeilSend {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.to_driver.try_send(Cmd::Fin {
                sid: self.sid,
                final_seq: self.next_seq,
            });
        }
    }
}

/// Receive half of a VEIL stream. Subset of `quinn::RecvStream`.
pub struct VeilRecv {
    rx: mpsc::Receiver<Bytes>,
    leftover: Bytes,
    eof: bool,
}

impl VeilRecv {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>> {
        if self.leftover.is_empty() {
            if self.eof {
                return Ok(None);
            }
            match self.rx.recv().await {
                Some(b) => self.leftover = b,
                None => {
                    self.eof = true;
                    return Ok(None);
                }
            }
        }
        let n = buf.len().min(self.leftover.len());
        buf[..n].copy_from_slice(&self.leftover[..n]);
        self.leftover = self.leftover.slice(n..);
        Ok(Some(n))
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.read(&mut buf[filled..]).await? {
                Some(0) | None => return Err(anyhow!("unexpected eof")),
                Some(n) => filled += n,
            }
        }
        Ok(())
    }
}

// `AsyncRead`/`AsyncWrite` impls so VEIL streams drop into the generic
// `write_msg`/`read_msg`/`pipe_chunks` helpers in `protocol.rs` exactly like
// quinn's streams do.

impl tokio::io::AsyncRead for VeilRecv {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if self.leftover.is_empty() {
            if self.eof {
                return Poll::Ready(Ok(())); // EOF: 0 bytes filled
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => self.leftover = b,
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(self.leftover.len());
        buf.put_slice(&self.leftover[..n]);
        self.leftover = self.leftover.slice(n..);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for VeilSend {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;
        use std::task::Poll;
        let broken = || {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "veil connection closed")
        };

        // If a previous poll_write is mid-flight (channel was full), drive it.
        if let Some((fut, n)) = self.pending.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    let n = *n;
                    self.pending = None;
                    self.next_seq += 1;
                    return Poll::Ready(Ok(n));
                }
                Poll::Ready(Err(())) => {
                    self.pending = None;
                    return Poll::Ready(Err(broken()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let n = buf.len().min(MAX_PAYLOAD);
        let seq = self.next_seq;
        let sid = self.sid;
        let tx = self.to_driver.clone();
        let bytes = Bytes::copy_from_slice(&buf[..n]);
        let mut fut: std::pin::Pin<
            Box<dyn Future<Output = Result<(), ()>> + Send>,
        > = Box::pin(async move {
            let (accepted, _drop_rx) = oneshot::channel();
            tx.send(Cmd::Send { sid, seq, bytes, accepted })
                .await
                .map_err(|_| ())
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.next_seq += 1;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(())) => Poll::Ready(Err(broken())),
            Poll::Pending => {
                self.pending = Some((fut, n));
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.finish();
        std::task::Poll::Ready(Ok(()))
    }
}

// ── Connection handle ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct VeilConnection {
    cmd_tx: mpsc::Sender<Cmd>,
    accept_rx: Arc<Mutex<mpsc::Receiver<AcceptedStream>>>,
    next_sid: Arc<AtomicU64>,
    is_client: bool,
    closed: Arc<Notify>,
    close_reason: Arc<Mutex<Option<String>>>,
    peer: SocketAddr,
}

struct AcceptedStream {
    send: VeilSend,
    recv: VeilRecv,
    bidi: bool,
}

impl VeilConnection {
    pub async fn open_bi(&self) -> Result<(VeilSend, VeilRecv)> {
        let sid = self.alloc_sid();
        let (ready_tx, ready_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Open {
                sid,
                bidi: true,
                recv_ready: Some(ready_tx),
            })
            .await
            .map_err(|_| anyhow!("connection closed"))?;
        let recv = ready_rx.await.map_err(|_| anyhow!("connection closed"))?;
        Ok((self.make_send(sid), recv))
    }

    pub async fn open_uni(&self) -> Result<VeilSend> {
        let sid = self.alloc_sid();
        self.cmd_tx
            .send(Cmd::Open {
                sid,
                bidi: false,
                recv_ready: None,
            })
            .await
            .map_err(|_| anyhow!("connection closed"))?;
        Ok(self.make_send(sid))
    }

    pub async fn accept_bi(&self) -> Result<(VeilSend, VeilRecv)> {
        loop {
            let mut g = self.accept_rx.lock().await;
            match g.recv().await {
                Some(s) if s.bidi => return Ok((s.send, s.recv)),
                Some(_) => continue,
                None => return Err(anyhow!("connection closed")),
            }
        }
    }

    pub async fn accept_uni(&self) -> Result<VeilRecv> {
        loop {
            let mut g = self.accept_rx.lock().await;
            match g.recv().await {
                Some(s) if !s.bidi => return Ok(s.recv),
                Some(_) => continue,
                None => return Err(anyhow!("connection closed")),
            }
        }
    }

    pub async fn closed(&self) -> String {
        self.closed.notified().await;
        self.close_reason
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| "closed".into())
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.peer
    }

    fn alloc_sid(&self) -> u64 {
        let n = self.next_sid.fetch_add(1, Ordering::Relaxed);
        if self.is_client {
            n * 2
        } else {
            n * 2 + 1
        }
    }

    fn make_send(&self, sid: u64) -> VeilSend {
        VeilSend {
            sid,
            to_driver: self.cmd_tx.clone(),
            next_seq: 0,
            finished: false,
            closed: self.closed.clone(),
            pending: None,
        }
    }
}

// ── Driver: commands & per-stream state ────────────────────────────────────────

enum Cmd {
    Open {
        sid: u64,
        bidi: bool,
        recv_ready: Option<oneshot::Sender<VeilRecv>>,
    },
    Send {
        sid: u64,
        seq: u64,
        bytes: Bytes,
        accepted: oneshot::Sender<()>,
    },
    Fin {
        sid: u64,
        final_seq: u64,
    },
}

/// One unacked outbound DATA frame awaiting its ACK.
struct InFlight {
    sid: u64,
    seq: u64,
    /// The fully-built DATA frame body (header + possibly-compressed payload),
    /// built once so retransmits don't recompress. Encrypted fresh each send.
    frame: Vec<u8>,
    last_sent: Instant,
    /// Notified once this seq is acked, releasing the writer's window slot.
    accepted: Option<oneshot::Sender<()>>,
}

/// Receive-side reassembly for one stream.
struct RxStream {
    next_expected: u64,
    buffered: BTreeMap<u64, Bytes>,
    to_app: mpsc::Sender<Bytes>,
    final_seq: Option<u64>,
    finished: bool,
}

/// Send-side bookkeeping for one stream.
struct TxStream {
    /// Highest seq we've ACKed-from-peer (cumulative). Frames below are done.
    acked_upto: u64,
    fin_sent_final: Option<u64>,
}

// ── Connect / server ───────────────────────────────────────────────────────────

pub async fn connect(server: SocketAddr, key: VeilKey) -> Result<VeilConnection> {
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    set_udp_buffers(&sock);
    let sock = Arc::new(sock);

    // Per-connection inbound datagram channel fed by a small recv pump.
    let (dgram_tx, dgram_rx) = mpsc::channel::<Vec<u8>>(1024);
    let pump_sock = sock.clone();
    let pump_key = key.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match pump_sock.recv(&mut buf).await {
                Ok(n) => {
                    if let Some(frame) = pump_key.open(&buf[..n]) {
                        if dgram_tx.send(frame).await.is_err() {
                            break;
                        }
                    } // else: not ours / corrupt — drop silently
                }
                Err(_) => break,
            }
        }
    });

    Ok(spawn_driver(
        Sender::Connected(sock),
        key,
        server,
        true,  // is_client
        true,  // compress: zstd per-frame, on by default
        dgram_rx,
    ))
}

pub struct VeilEndpoint {
    accept_rx: mpsc::Receiver<VeilConnection>,
}

impl VeilEndpoint {
    pub async fn accept(&mut self) -> Option<VeilConnection> {
        self.accept_rx.recv().await
    }
}

pub async fn server(addr: SocketAddr, key: VeilKey) -> Result<VeilEndpoint> {
    let sock = Arc::new(UdpSocket::bind(addr).await?);
    set_udp_buffers(&sock);
    let (accept_tx, accept_rx) = mpsc::channel::<VeilConnection>(64);
    tokio::spawn(server_loop(sock, key, accept_tx));
    Ok(VeilEndpoint { accept_rx })
}

/// Server demux: one shared socket, routing decrypted datagrams to per-peer
/// driver tasks. A new peer (whose first packet decrypts) becomes a connection.
async fn server_loop(
    sock: Arc<UdpSocket>,
    key: VeilKey,
    accept_tx: mpsc::Sender<VeilConnection>,
) {
    let mut peers: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let frame = match key.open(&buf[..n]) {
            Some(f) => f,
            None => continue, // not a VEIL packet for us — invisible to attackers
        };
        if let Some(tx) = peers.get(&from) {
            match tx.send(frame).await {
                Ok(()) => continue,
                Err(returned) => {
                    // Driver gone; recreate with the same frame.
                    peers.remove(&from);
                    let frame = returned.0;
                    let (dgram_tx, dgram_rx) = mpsc::channel::<Vec<u8>>(1024);
                    let _ = dgram_tx.send(frame).await;
                    peers.insert(from, dgram_tx);
                    let conn = spawn_driver(
                        Sender::Shared { sock: sock.clone(), peer: from },
                        key.clone(),
                        from,
                        false, // is_client
                        true,  // compress
                        dgram_rx,
                    );
                    if accept_tx.send(conn).await.is_err() {
                        break;
                    }
                    continue;
                }
            }
        }
        // New peer.
        let (dgram_tx, dgram_rx) = mpsc::channel::<Vec<u8>>(1024);
        let _ = dgram_tx.send(frame).await;
        peers.insert(from, dgram_tx);
        let conn = spawn_driver(
            Sender::Shared {
                sock: sock.clone(),
                peer: from,
            },
            key.clone(),
            from,
            false, // is_client
            true,  // compress
            dgram_rx,
        );
        if accept_tx.send(conn).await.is_err() {
            break;
        }
    }
}

/// How the driver sends datagrams: a connected socket (client) or a shared
/// server socket with an explicit peer address.
enum Sender {
    Connected(Arc<UdpSocket>),
    Shared { sock: Arc<UdpSocket>, peer: SocketAddr },
}

impl Sender {
    async fn send(&self, datagram: &[u8]) {
        match self {
            Sender::Connected(s) => {
                let _ = s.send(datagram).await;
            }
            Sender::Shared { sock, peer } => {
                let _ = sock.send_to(datagram, *peer).await;
            }
        }
    }
}

// ── The driver task ────────────────────────────────────────────────────────────

fn spawn_driver(
    sender: Sender,
    key: VeilKey,
    peer: SocketAddr,
    is_client: bool,
    compress: bool,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
) -> VeilConnection {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(SEND_WINDOW + 16);
    let (accept_tx, accept_rx) = mpsc::channel::<AcceptedStream>(64);
    let closed = Arc::new(Notify::new());
    let close_reason = Arc::new(Mutex::new(None));

    let conn = VeilConnection {
        cmd_tx: cmd_tx.clone(),
        accept_rx: Arc::new(Mutex::new(accept_rx)),
        next_sid: Arc::new(AtomicU64::new(0)),
        is_client,
        closed: closed.clone(),
        close_reason: close_reason.clone(),
        peer,
    };

    let driver_cmd_tx = cmd_tx.clone();
    tokio::spawn(async move {
        let _ = driver_cmd_tx; // keep an extra handle so cmd_rx stays open
        let mut inflight: Vec<InFlight> = Vec::new();
        let mut rx_streams: HashMap<u64, RxStream> = HashMap::new();
        let mut tx_streams: HashMap<u64, TxStream> = HashMap::new();
        // Streams the peer opened that we've already surfaced to accept().
        let mut known_peer_streams: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // On the client, send an immediate PING so the server learns our addr
        // and the connection is established before any stream opens.
        if is_client {
            sender.send(&key.seal(&[F_PING])).await;
        }

        let mut tick = interval(Duration::from_millis(50));
        let mut keepalive = interval(KEEPALIVE);
        let mut last_recv = Instant::now();

        loop {
            tokio::select! {
                // ----- application commands -----
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(Cmd::Open { sid, bidi, recv_ready }) => {
                            sender.send(&key.seal(&fr_open(sid, bidi))).await;
                            tx_streams.entry(sid).or_insert(TxStream { acked_upto: 0, fin_sent_final: None });
                            if bidi {
                                // Our own bidi stream also has a recv side.
                                let (to_app, from_drv) = mpsc::channel::<Bytes>(64);
                                rx_streams.insert(sid, RxStream {
                                    next_expected: 0,
                                    buffered: BTreeMap::new(),
                                    to_app,
                                    final_seq: None,
                                    finished: false,
                                });
                                if let Some(r) = recv_ready {
                                    let _ = r.send(VeilRecv { rx: from_drv, leftover: Bytes::new(), eof: false });
                                }
                            }
                        }
                        Some(Cmd::Send { sid, seq, bytes, accepted }) => {
                            // Build the DATA frame once (zstd per-frame when enabled,
                            // kept only if it shrinks); reused verbatim on retransmit.
                            let frame = fr_data(sid, seq, &bytes, compress);
                            sender.send(&key.seal(&frame)).await;
                            inflight.push(InFlight {
                                sid, seq, frame,
                                last_sent: Instant::now(),
                                accepted: Some(accepted),
                            });
                            // If under window, release the writer immediately to pipeline.
                            if inflight.len() <= SEND_WINDOW {
                                if let Some(f) = inflight.last_mut() {
                                    if let Some(tx) = f.accepted.take() { let _ = tx.send(()); }
                                }
                            }
                        }
                        Some(Cmd::Fin { sid, final_seq }) => {
                            if let Some(t) = tx_streams.get_mut(&sid) { t.fin_sent_final = Some(final_seq); }
                            sender.send(&key.seal(&fr_fin(sid, final_seq))).await;
                        }
                        None => { break; }
                    }
                }

                // ----- inbound datagrams (already decrypted) -----
                dg = dgram_rx.recv() => {
                    let frame = match dg { Some(f) => f, None => break };
                    last_recv = Instant::now();
                    if frame.is_empty() { continue; }
                    match frame[0] {
                        F_PING => { /* keepalive / handshake */ }
                        F_CLOSE => {
                            *close_reason.lock().await = Some("peer closed".into());
                            break;
                        }
                        F_OPEN if frame.len() >= 10 => {
                            let sid = be64(&frame[1..9]);
                            let bidi = frame[9] & 1 == 1;
                            if known_peer_streams.insert(sid) {
                                let (to_app, from_drv) = mpsc::channel::<Bytes>(64);
                                rx_streams.insert(sid, RxStream {
                                    next_expected: 0,
                                    buffered: BTreeMap::new(),
                                    to_app,
                                    final_seq: None,
                                    finished: false,
                                });
                                let send_half = VeilSend {
                                    sid,
                                    to_driver: cmd_tx.clone(),
                                    next_seq: 0,
                                    finished: false,
                                    closed: closed.clone(),
                                    pending: None,
                                };
                                if bidi {
                                    tx_streams.entry(sid).or_insert(TxStream { acked_upto: 0, fin_sent_final: None });
                                }
                                let _ = accept_tx.send(AcceptedStream {
                                    send: send_half,
                                    recv: VeilRecv { rx: from_drv, leftover: Bytes::new(), eof: false },
                                    bidi,
                                }).await;
                            }
                        }
                        // [F_DATA][sid:8][seq:8][flag:1][len:2][payload]
                        F_DATA if frame.len() >= 20 => {
                            let sid = be64(&frame[1..9]);
                            let seq = be64(&frame[9..17]);
                            let flag = frame[17];
                            let len = u16::from_be_bytes([frame[18], frame[19]]) as usize;
                            if frame.len() < 20 + len { continue; }
                            let raw = &frame[20..20 + len];
                            let payload = if flag & DF_COMPRESSED != 0 {
                                match zstd::decode_all(raw) {
                                    Ok(d) => Bytes::from(d),
                                    Err(_) => continue, // corrupt frame; let retransmit recover
                                }
                            } else {
                                Bytes::copy_from_slice(raw)
                            };
                            if let Some(rs) = rx_streams.get_mut(&sid) {
                                if seq >= rs.next_expected {
                                    rs.buffered.insert(seq, payload);
                                    // Deliver in-order runs.
                                    while let Some(b) = rs.buffered.remove(&rs.next_expected) {
                                        let _ = rs.to_app.send(b).await;
                                        rs.next_expected += 1;
                                    }
                                }
                                // Cumulative ACK of next-expected.
                                sender.send(&key.seal(&fr_ack(sid, rs.next_expected))).await;
                                maybe_finish_rx(rs);
                            } else {
                                // Unknown stream: ack anyway to stop retransmit storms.
                                sender.send(&key.seal(&fr_ack(sid, seq + 1))).await;
                            }
                        }
                        F_ACK if frame.len() >= 17 => {
                            let sid = be64(&frame[1..9]);
                            let ack = be64(&frame[9..17]);
                            if let Some(t) = tx_streams.get_mut(&sid) {
                                if ack > t.acked_upto { t.acked_upto = ack; }
                            }
                            // Release window slots and writers for acked frames.
                            inflight.retain_mut(|f| {
                                if f.sid == sid && f.seq < ack {
                                    if let Some(tx) = f.accepted.take() { let _ = tx.send(()); }
                                    false
                                } else { true }
                            });
                        }
                        F_FIN if frame.len() >= 17 => {
                            let sid = be64(&frame[1..9]);
                            let final_seq = be64(&frame[9..17]);
                            if let Some(rs) = rx_streams.get_mut(&sid) {
                                rs.final_seq = Some(final_seq);
                                maybe_finish_rx(rs);
                            }
                        }
                        F_RST if frame.len() >= 9 => {
                            let sid = be64(&frame[1..9]);
                            rx_streams.remove(&sid);
                        }
                        _ => {}
                    }
                }

                // ----- retransmit timer -----
                _ = tick.tick() => {
                    let now = Instant::now();
                    for f in inflight.iter_mut() {
                        if now.duration_since(f.last_sent) >= RTO {
                            // Reuse the frame built at first send (no recompression).
                            sender.send(&key.seal(&f.frame)).await;
                            f.last_sent = now;
                        }
                    }
                    if now.duration_since(last_recv) >= IDLE_TIMEOUT {
                        *close_reason.lock().await = Some("timed out".into());
                        break;
                    }
                }

                // ----- keepalive -----
                _ = keepalive.tick() => {
                    sender.send(&key.seal(&[F_PING])).await;
                }
            }
        }

        // Connection ending: tell the peer and wake everyone waiting on close.
        sender.send(&key.seal(&[F_CLOSE])).await;
        closed.notify_waiters();
        // Dropping rx_streams closes the app-facing channels → readers see EOF.
    });

    conn
}

/// If the receive side has seen its FIN and delivered everything up to it,
/// close the app channel so the reader observes EOF.
fn maybe_finish_rx(rs: &mut RxStream) {
    if rs.finished {
        return;
    }
    if let Some(fin) = rs.final_seq {
        if rs.next_expected >= fin && rs.buffered.is_empty() {
            rs.finished = true;
            // Replace the sender with a closed one by dropping it: set to a
            // channel whose receiver is gone is not possible here, so we signal
            // EOF by dropping the sender clone. We hold exactly one sender; drop
            // it by swapping with a fresh closed channel sender.
            let (dead_tx, _dead_rx) = mpsc::channel::<Bytes>(1);
            rs.to_app = dead_tx; // old sender dropped → reader gets None
        }
    }
}

fn set_udp_buffers(sock: &UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let sz: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> VeilKey {
        VeilKey::from_passphrase("test-passphrase-123")
    }

    /// Bind a server on an ephemeral port and run an echo handler. Returns addr.
    async fn echo_server() -> SocketAddr {
        // Bind the UDP socket ourselves to learn the port, then hand it to a
        // server loop equivalent. We replicate `server()` but expose the addr.
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        set_udp_buffers(&sock);
        let (accept_tx, mut accept_rx) = mpsc::channel::<VeilConnection>(64);
        tokio::spawn(server_loop(sock, key(), accept_tx));
        tokio::spawn(async move {
            while let Some(conn) = accept_rx.recv().await {
                tokio::spawn(async move {
                    loop {
                        match conn.accept_bi().await {
                            Ok((mut s, mut r)) => {
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 4096];
                                    while let Ok(Some(n)) = r.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        if s.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    let _ = s.finish();
                                });
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn bidi_echo_small() {
        let addr = echo_server().await;
        let conn = connect(addr, key()).await.unwrap();
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(b"hello veil").await.unwrap();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        while got.len() < 10 {
            let n = r.read(&mut buf).await.unwrap().unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, b"hello veil");
    }

    #[tokio::test]
    async fn bidi_echo_large_multiframe() {
        let addr = echo_server().await;
        let conn = connect(addr, key()).await.unwrap();
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        // 64 KiB forces many DATA frames (MAX_PAYLOAD = 1100).
        let payload: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            s.write_all(&p2).await.unwrap();
            let _ = s.finish();
        });
        let mut got = Vec::new();
        let mut buf = vec![0u8; 8192];
        while got.len() < payload.len() {
            match r.read(&mut buf).await.unwrap() {
                Some(n) => got.extend_from_slice(&buf[..n]),
                None => break,
            }
        }
        writer.await.unwrap();
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn compressible_data_roundtrips() {
        // Highly compressible payload (1 MiB of a repeating pattern) must arrive
        // byte-identical through the zstd-on-by-default DATA path.
        let addr = echo_server().await;
        let conn = connect(addr, key()).await.unwrap();
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let payload: Vec<u8> = std::iter::repeat(b"the quick brown fox jumps. ")
            .take(40000)
            .flatten()
            .copied()
            .collect();
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            s.write_all(&p2).await.unwrap();
            let _ = s.finish();
        });
        let mut got = Vec::new();
        let mut buf = vec![0u8; 16384];
        while got.len() < payload.len() {
            match r.read(&mut buf).await.unwrap() {
                Some(n) => got.extend_from_slice(&buf[..n]),
                None => break,
            }
        }
        writer.await.unwrap();
        assert_eq!(got, payload, "compressible data must round-trip exactly");
    }

    #[test]
    fn frame_compression_flag() {
        // Compressible payload → frame carries DF_COMPRESSED and is smaller.
        let text = vec![b'a'; 1000];
        let f = fr_data(7, 3, &text, true);
        assert_eq!(f[17] & DF_COMPRESSED, DF_COMPRESSED, "should be flagged compressed");
        assert!(f.len() < 20 + text.len(), "compressed frame should be smaller");

        // Incompressible payload (random) → stored raw, flag clear, no expansion.
        let mut rnd = vec![0u8; 1000];
        rand_fill(&mut rnd);
        let f2 = fr_data(7, 4, &rnd, true);
        assert_eq!(f2[17] & DF_COMPRESSED, 0, "random data should be sent raw");
        assert_eq!(f2.len(), 20 + rnd.len(), "raw frame must not expand");

        // compress=false → always raw.
        let f3 = fr_data(7, 5, &text, false);
        assert_eq!(f3[17] & DF_COMPRESSED, 0);
    }

    #[tokio::test]
    async fn wrong_key_is_rejected() {
        let addr = echo_server().await;
        // Wrong passphrase: the server can't decrypt, so open_bi never completes.
        let conn = connect(addr, VeilKey::from_passphrase("WRONG"))
            .await
            .unwrap();
        let res =
            tokio::time::timeout(Duration::from_secs(2), conn.open_bi()).await;
        // Either times out (server silently drops) — never a successful echo.
        if let Ok(Ok((mut s, mut r))) = res {
            let _ = s.write_all(b"x").await;
            let mut buf = [0u8; 8];
            let got = tokio::time::timeout(Duration::from_secs(1), r.read(&mut buf)).await;
            assert!(got.is_err() || matches!(got, Ok(Ok(None))), "wrong key must not echo");
        }
    }

    #[test]
    fn ciphertext_looks_random() {
        let k = key();
        let a = k.seal(b"the same plaintext");
        let b = k.seal(b"the same plaintext");
        // Random nonce → identical plaintext yields different ciphertext.
        assert_ne!(a, b);
        // No frame-type byte is visible in cleartext (first bytes are the nonce).
        assert!(k.open(&a).is_some());
        // A different key cannot open it.
        let other = VeilKey::from_passphrase("different");
        assert!(other.open(&a).is_none());
    }
}
