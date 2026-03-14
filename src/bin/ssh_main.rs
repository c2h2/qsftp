use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[derive(Parser)]
#[command(
    name = "qssh",
    version = env!("GIT_VERSION"),
    about = "SSH client over QUIC — interactive shell, exec, and port forwarding"
)]
struct Args {
    /// [user@]host
    destination: String,

    /// Port number
    #[arg(short = 'p', long, default_value = "1022")]
    port: u16,

    /// Identity file (SSH private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Password (optional, prompts if not given)
    #[arg(long, env = "QSSH_PASSWORD", hide = true)]
    password: Option<String>,

    /// Local port forward: -L [bind_addr:]local_port:remote_host:remote_port
    /// Listens locally and forwards to remote_host:remote_port via the server.
    #[arg(short = 'L', long, value_name = "[bind:]lport:rhost:rport")]
    local_forward: Vec<String>,

    /// Remote port forward: -R [bind_addr:]remote_port:local_host:local_port
    /// Asks the server to listen on remote_port and forward to local_host:local_port.
    #[arg(short = 'R', long, value_name = "[bind:]rport:lhost:lport")]
    remote_forward: Vec<String>,

    /// Do not execute a shell or command (useful with -L/-R only)
    #[arg(short = 'N', long)]
    no_shell: bool,

    /// Verbose/debug output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Remote command to execute (non-interactive); all remaining args after --
    #[arg(last = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let default_level = if args.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();

    let (username, host) = parse_destination(&args.destination)?;

    let addr = tokio::net::lookup_host(format!("{}:{}", host, args.port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve host: {}", host))?;

    let client = connect_and_auth(addr, &username, &host, args.identity.as_deref(), &args.password).await?;

    eprintln!("Connected to {} ({})", host, client.tls_cipher);

    // Spawn remote-forward listeners before anything else
    let mut forward_tasks = tokio::task::JoinSet::new();
    for spec in &args.remote_forward {
        match parse_remote_forward(spec) {
            Ok((bind, rport, lhost, lport)) => {
                let conn = client.connection.clone();
                let bind = bind.clone();
                let lhost = lhost.clone();
                eprintln!("Remote forward: {}:{} → {}:{}", bind, rport, lhost, lport);
                forward_tasks.spawn(async move {
                    if let Err(e) = run_remote_forward(conn, &bind, rport, &lhost, lport).await {
                        eprintln!("Remote forward error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Bad -R spec '{}': {}", spec, e),
        }
    }

    // Spawn local-forward listeners
    for spec in &args.local_forward {
        match parse_local_forward(spec) {
            Ok((bind, lport, rhost, rport)) => {
                let conn = client.connection.clone();
                let rhost = rhost.clone();
                eprintln!("Local forward: {}:{} → {}:{}", bind, lport, rhost, rport);
                forward_tasks.spawn(async move {
                    if let Err(e) = run_local_forward(conn, &bind, lport, &rhost, rport).await {
                        eprintln!("Local forward error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Bad -L spec '{}': {}", spec, e),
        }
    }

    if args.no_shell {
        // Just keep forwards alive until killed
        forward_tasks.join_all().await;
        return Ok(());
    }

    if !args.command.is_empty() {
        // Non-interactive exec
        let cmd = args.command.join(" ");
        run_exec(&client, &cmd).await?;
    } else {
        // Interactive shell
        run_shell(&client).await?;
    }

    forward_tasks.abort_all();
    Ok(())
}

// ── Authentication ──────────────────────────────────────────────────────────

async fn connect_and_auth(
    addr: SocketAddr,
    user: &str,
    host: &str,
    identity: Option<&std::path::Path>,
    password: &Option<String>,
) -> Result<QsftpClient> {
    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;

    if let Ok(private_key) = qsftp::ssh_auth::find_private_key(identity) {
        match QsftpClient::authenticate_key(connection.clone(), user, &private_key).await {
            Ok(client) => {
                eprintln!("Authenticated with SSH key.");
                return Ok(client);
            }
            Err(e) => tracing::debug!("Key auth failed: {}", e),
        }
    }

    let pw = match password {
        Some(p) => p.clone(),
        None => rpassword::read_password_from_tty(Some(&format!("{}@{}'s password: ", user, host)))?,
    };
    let (conn2, _ep2) = QsftpClient::connect(addr, "localhost").await?;
    QsftpClient::authenticate(conn2, user, &pw).await
}

// ── Interactive shell ────────────────────────────────────────────────────────

async fn run_shell(client: &QsftpClient) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Get terminal size
    let (cols, rows) = terminal_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    let (mut send, mut recv) = client.connection.open_bi().await?;

    write_msg(&mut send, &Request::Shell { term, cols, rows }).await?;

    // Wait for SessionOk
    let resp: Response = read_msg(&mut recv).await?;
    match resp {
        Response::SessionOk => {}
        Response::Error { message } => anyhow::bail!("Shell error: {}", message),
        _ => anyhow::bail!("Unexpected response to Shell request"),
    }

    // Put terminal into raw mode
    let _raw_guard = RawModeGuard::enter()?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // stdin → network
    let stdin_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send.write_all(&buf[..n]).await.is_err() { break; }
        }
        let _ = send.finish();
    });

    // network → stdout
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = match recv.read(&mut buf).await {
                Ok(Some(n)) if n > 0 => n,
                _ => break,
            };
            if stdout.write_all(&buf[..n]).await.is_err() { break; }
            let _ = stdout.flush().await;
        }
    });

    tokio::select! {
        _ = stdin_task => {}
        _ = stdout_task => {}
    }

    Ok(())
}

// ── Non-interactive exec ─────────────────────────────────────────────────────

async fn run_exec(client: &QsftpClient, command: &str) -> Result<()> {
    let (mut send, mut recv) = client.connection.open_bi().await?;

    write_msg(&mut send, &Request::Exec { command: command.to_string() }).await?;
    send.finish()?;

    loop {
        let resp: Response = read_msg(&mut recv).await?;
        match resp {
            Response::ExecData { stdout, stderr, done } => {
                if !stdout.is_empty() {
                    use std::io::Write;
                    std::io::stdout().write_all(&stdout)?;
                }
                if !stderr.is_empty() {
                    use std::io::Write;
                    std::io::stderr().write_all(&stderr)?;
                }
                if done { break; }
            }
            Response::ExitStatus { code } => {
                if code != 0 {
                    std::process::exit(code);
                }
                break;
            }
            Response::Error { message } => anyhow::bail!("Exec error: {}", message),
            _ => break,
        }
    }

    Ok(())
}

// ── Local port forward (-L) ──────────────────────────────────────────────────
//
// Listen on local bind:lport; for each connection open a TcpForward stream
// to the server asking it to connect to rhost:rport.

async fn run_local_forward(
    conn: quinn::Connection,
    bind: &str,
    lport: u16,
    rhost: &str,
    rport: u16,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind, lport)).await?;

    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::debug!("Local forward: new TCP connection from {}", peer);
        let conn2 = conn.clone();
        let rhost2 = rhost.to_string();

        tokio::spawn(async move {
            let result: Result<()> = async {
                let (mut quic_send, mut quic_recv) = conn2.open_bi().await?;

                write_msg(&mut quic_send, &Request::TcpForward {
                    host: rhost2.clone(),
                    port: rport,
                }).await?;

                let resp: Response = read_msg(&mut quic_recv).await?;
                match resp {
                    Response::SessionOk => {}
                    Response::Error { message } => anyhow::bail!("Forward refused: {}", message),
                    _ => anyhow::bail!("Unexpected forward response"),
                }

                let (mut tcp_read, mut tcp_write) = tcp.into_split();

                let t2q = tokio::spawn(async move {
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = match tcp_read.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if quic_send.write_all(&buf[..n]).await.is_err() { break; }
                    }
                    let _ = quic_send.finish();
                });

                let q2t = tokio::spawn(async move {
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = match quic_recv.read(&mut buf).await {
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
                tracing::debug!("Local forward session error: {}", e);
            }
        });
    }
}

// ── Remote port forward (-R) ─────────────────────────────────────────────────
//
// Send a RemoteForward request to the server; the server listens on rport
// and for each incoming TCP connection opens a new bi-stream back to us.
// We then connect locally to lhost:lport and bridge it.
//
// Protocol: client sends Request::RemoteForward, server acks with SessionOk,
// then for each incoming remote connection the server opens a new uni/bi stream
// carrying a TcpForward notification followed by raw data.
//
// Simpler approach that doesn't require new server listen logic:
// We send a single TcpForward per accepted stream. For -R we use a different
// strategy: we ask the server to listen by sending RemoteForwardBind, then
// accept uni streams from the server where each is a new forwarded connection.
//
// For now we implement -R by having the client poll for server-initiated
// streams (which the server opens when a remote TCP connects to the bound port).
// The server bind is done via Request::RemoteForwardBind.

async fn run_remote_forward(
    conn: quinn::Connection,
    bind: &str,
    rport: u16,
    lhost: &str,
    lport: u16,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Send the bind request on a dedicated bi-stream; keep it open.
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;
    write_msg(&mut ctrl_send, &Request::RemoteForwardBind {
        bind: bind.to_string(),
        port: rport,
    }).await?;

    let resp: Response = read_msg(&mut ctrl_recv).await?;
    match resp {
        Response::SessionOk => {}
        Response::Error { message } => anyhow::bail!("Remote forward bind failed: {}", message),
        _ => anyhow::bail!("Unexpected response to RemoteForwardBind"),
    }

    eprintln!("Remote forward listening on server port {}", rport);

    // The server pushes a new bi-stream for each accepted connection.
    // We accept those streams and bridge them to lhost:lport locally.
    loop {
        // Server opens bi-stream for each forwarded connection.
        // quinn doesn't let the server open bi-streams initiated by the server
        // on the same connection without the client calling accept_bi().
        // We do that here:
        let (mut fwd_send, mut fwd_recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };

        let lhost2 = lhost.to_string();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let tcp = tokio::net::TcpStream::connect(format!("{}:{}", lhost2, lport)).await?;
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

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_destination(dest: &str) -> Result<(String, String)> {
    if let Some(at_pos) = dest.find('@') {
        Ok((dest[..at_pos].to_string(), dest[at_pos + 1..].to_string()))
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        Ok((user, dest.to_string()))
    }
}

/// Parse -L [bind:]lport:rhost:rport → (bind, lport, rhost, rport)
fn parse_local_forward(spec: &str) -> Result<(String, u16, String, u16)> {
    parse_forward_spec(spec)
}

/// Parse -R [bind:]rport:lhost:lport → (bind, rport, lhost, lport)
fn parse_remote_forward(spec: &str) -> Result<(String, u16, String, u16)> {
    parse_forward_spec(spec)
}

fn parse_forward_spec(spec: &str) -> Result<(String, u16, String, u16)> {
    // Formats:
    //   lport:rhost:rport
    //   bind:lport:rhost:rport
    // We split on ':' but handle IPv6 addresses in brackets.
    let parts = split_forward_spec(spec)?;
    match parts.as_slice() {
        [p1, host, p2] => {
            let port1 = p1.parse::<u16>().map_err(|_| anyhow::anyhow!("Invalid port: {}", p1))?;
            let port2 = p2.parse::<u16>().map_err(|_| anyhow::anyhow!("Invalid port: {}", p2))?;
            Ok(("127.0.0.1".to_string(), port1, host.clone(), port2))
        }
        [bind, p1, host, p2] => {
            let port1 = p1.parse::<u16>().map_err(|_| anyhow::anyhow!("Invalid port: {}", p1))?;
            let port2 = p2.parse::<u16>().map_err(|_| anyhow::anyhow!("Invalid port: {}", p2))?;
            Ok((bind.clone(), port1, host.clone(), port2))
        }
        _ => anyhow::bail!("Invalid forward spec '{}'. Use [bind:]port:host:port", spec),
    }
}

fn split_forward_spec(spec: &str) -> Result<Vec<String>> {
    // Handle [ipv6]:port style
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_bracket = false;

    for ch in spec.chars() {
        match ch {
            '[' => { in_bracket = true; cur.push(ch); }
            ']' => { in_bracket = false; cur.push(ch); }
            ':' if !in_bracket => {
                parts.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() { parts.push(cur); }
    Ok(parts)
}

fn terminal_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ as _, &mut ws) == 0
            && ws.ws_col > 0 && ws.ws_row > 0
        {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

// ── Raw terminal mode ────────────────────────────────────────────────────────

struct RawModeGuard {
    orig: libc::termios,
}

impl RawModeGuard {
    fn enter() -> Result<Self> {
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                anyhow::bail!("tcgetattr failed");
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                anyhow::bail!("tcsetattr failed");
            }
            Ok(RawModeGuard { orig })
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
        }
    }
}
