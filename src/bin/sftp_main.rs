use anyhow::Result;
use clap::Parser;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor};
use rustyline_derive::Helper;
use std::path::{Path, PathBuf};

use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[derive(Parser)]
#[command(name = "qsftp", version = env!("GIT_VERSION"), about = "Interactive SFTP client over QUIC")]
struct Args {
    /// [user@]host
    destination: String,

    /// Port number
    #[arg(short = 'P', long, default_value = "1022")]
    port: u16,

    /// Identity file (SSH private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Password (optional, prompts if not given)
    #[arg(long, env = "QSFTP_PASSWORD", hide = true)]
    password: Option<String>,

    /// Verbose/debug output (like ssh -v)
    #[arg(short = 'v', long)]
    verbose: bool,
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

    tracing::debug!("Resolving host '{}' port {}", host, args.port);
    let addr = tokio::net::lookup_host(format!("{}:{}", host, args.port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve host: {}", host))?;
    tracing::debug!("Resolved to {}", addr);

    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;

    // Try SSH key auth first, fall back to password
    let client = match try_key_auth(&connection, &username, args.identity.as_deref()).await {
        Ok(client) => {
            eprintln!("Authenticated with SSH key.");
            client
        }
        Err(key_err) => {
            tracing::debug!("SSH key auth failed: {}", key_err);
            // Fall back to password
            let password = if let Some(pw) = args.password {
                pw
            } else {
                rpassword::read_password_from_tty(Some(&format!(
                    "{}@{}'s password: ",
                    username, host
                )))?
            };
            // Need a new connection since the old auth stream may be consumed
            let (connection2, _endpoint2) = QsftpClient::connect(addr, "localhost").await?;
            QsftpClient::authenticate(connection2, &username, &password).await?
        }
    };

    eprintln!("Connected to {}. Home: {}", host, client.home_dir);
    eprintln!("Type 'help' for available commands.");

    run_interactive(&client).await?;

    Ok(())
}

async fn try_key_auth(
    connection: &quinn::Connection,
    username: &str,
    identity_file: Option<&Path>,
) -> Result<QsftpClient> {
    let private_key = qsftp::ssh_auth::find_private_key(identity_file)?;
    QsftpClient::authenticate_key(connection.clone(), username, &private_key).await
}

fn parse_destination(dest: &str) -> Result<(String, String)> {
    if let Some(at_pos) = dest.find('@') {
        let user = &dest[..at_pos];
        let host = &dest[at_pos + 1..];
        Ok((user.to_string(), host.to_string()))
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        Ok((user, dest.to_string()))
    }
}

/// rustyline helper: local filesystem tab completion
#[derive(Helper)]
struct SftpHelper {
    file_completer: FilenameCompleter,
}

impl Completer for SftpHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        self.file_completer.complete(line, pos, ctx)
    }
}

impl Hinter for SftpHelper {
    type Hint = String;
}

impl Highlighter for SftpHelper {}
impl Validator for SftpHelper {}

/// Expand a token that may contain glob characters against the local filesystem.
/// Returns the original token unchanged if it has no glob chars or no matches.
fn expand_local_glob(local_cwd: &Path, token: &str) -> Vec<String> {
    // Only expand if the token contains glob metacharacters
    if !token.contains('*') && !token.contains('?') && !token.contains('[') {
        return vec![token.to_string()];
    }

    let pattern = if Path::new(token).is_absolute() {
        token.to_string()
    } else {
        local_cwd.join(token).to_string_lossy().to_string()
    };

    match glob::glob(&pattern) {
        Ok(paths) => {
            let matches: Vec<String> = paths
                .filter_map(|p| p.ok())
                .map(|p| p.to_string_lossy().to_string())
                .collect();
            if matches.is_empty() {
                vec![token.to_string()]
            } else {
                matches
            }
        }
        Err(_) => vec![token.to_string()],
    }
}

async fn run_interactive(client: &QsftpClient) -> Result<()> {
    let mut local_cwd = std::env::current_dir()?;

    let config = Config::builder()
        .completion_type(CompletionType::List)
        .build();
    let helper = SftpHelper {
        file_completer: FilenameCompleter::new(),
    };
    let mut rl = Editor::with_config(config)?;
    rl.set_helper(Some(helper));

    loop {
        let readline = rl.readline("qsftp> ");
        let input = match readline {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    rl.add_history_entry(&trimmed)?;
                }
                trimmed
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        };

        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        let cmd = parts[0];

        match cmd {
            "help" | "?" => {
                println!("Commands:");
                println!("  ls [path]        - List remote directory");
                println!("  lls [path]       - List local directory");
                println!("  cd <path>        - Change remote directory");
                println!("  pwd              - Print remote working directory");
                println!("  lpwd             - Print local working directory");
                println!("  lcd <path>       - Change local directory");
                println!("  get [-r] <remote> [local] - Download file (-r for recursive)");
                println!("  put [-r] <local> [remote] - Upload file(s) (-r for recursive, globs ok)");
                println!("  mkdir <path>     - Create remote directory");
                println!("  rm <path>        - Remove remote file/directory");
                println!("  rename <old> <new> - Rename remote file");
                println!("  chmod <mode> <path> - Change remote file mode");
                println!("  stat <path>      - Show file info");
                println!("  exit/quit/bye    - Exit");
            }
            "ls" => {
                let path = if parts.len() > 1 { parts[1] } else { "." };
                let resp = client.command(&Request::Ls { path: path.to_string() }).await?;
                match resp {
                    Response::DirListing { entries } => {
                        for e in &entries {
                            let kind = if e.is_dir { "d" } else { "-" };
                            let mode_str = format_mode(e.mode);
                            println!(
                                "{}{} {:>10} {}",
                                kind,
                                mode_str,
                                qsftp::client::format_size(e.size),
                                e.name
                            );
                        }
                        println!("({} entries)", entries.len());
                    }
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "lls" => {
                let dir = if parts.len() > 1 {
                    if Path::new(parts[1]).is_absolute() {
                        PathBuf::from(parts[1])
                    } else {
                        local_cwd.join(parts[1])
                    }
                } else {
                    local_cwd.clone()
                };
                match std::fs::read_dir(&dir) {
                    Ok(entries) => {
                        let mut names: Vec<String> = entries
                            .filter_map(|e| e.ok())
                            .map(|e| {
                                let name = e.file_name().to_string_lossy().to_string();
                                if e.path().is_dir() {
                                    format!("{}/", name)
                                } else {
                                    name
                                }
                            })
                            .collect();
                        names.sort();
                        for name in &names {
                            println!("{}", name);
                        }
                        println!("({} entries)", names.len());
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            "cd" => {
                if parts.len() < 2 {
                    eprintln!("Usage: cd <path>");
                    continue;
                }
                let resp = client
                    .command(&Request::Cd {
                        path: parts[1].to_string(),
                    })
                    .await?;
                match resp {
                    Response::Ok => {}
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "pwd" => {
                let resp = client.command(&Request::Pwd).await?;
                match resp {
                    Response::Pwd { path } => println!("{}", path),
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "lpwd" => {
                println!("{}", local_cwd.display());
            }
            "lcd" => {
                if parts.len() < 2 {
                    eprintln!("Usage: lcd <path>");
                    continue;
                }
                let new_dir = if Path::new(parts[1]).is_absolute() {
                    PathBuf::from(parts[1])
                } else {
                    local_cwd.join(parts[1])
                };
                match new_dir.canonicalize() {
                    Ok(p) if p.is_dir() => {
                        local_cwd = p;
                    }
                    Ok(p) => eprintln!("{}: Not a directory", p.display()),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            "get" => {
                let recursive = parts.get(1) == Some(&"-r");
                let arg_start = if recursive { 2 } else { 1 };
                if parts.len() <= arg_start {
                    eprintln!("Usage: get [-r] <remote> [local]");
                    continue;
                }
                let remote = parts[arg_start];
                let local_name = if parts.len() > arg_start + 1 {
                    parts[arg_start + 1]
                } else {
                    Path::new(remote)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(remote)
                };
                let local_path = if Path::new(local_name).is_absolute() {
                    PathBuf::from(local_name)
                } else {
                    local_cwd.join(local_name)
                };
                if recursive {
                    match download_recursive(client, remote, &local_path).await {
                        Ok(_) => {}
                        Err(e) => eprintln!("Error: {}", e),
                    }
                } else {
                    eprintln!("Downloading {} -> {}", remote, local_path.display());
                    match client.download(remote, &local_path).await {
                        Ok(_) => {}
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
            }
            "put" => {
                let recursive = parts.get(1) == Some(&"-r");
                let arg_start = if recursive { 2 } else { 1 };
                if parts.len() <= arg_start {
                    eprintln!("Usage: put [-r] <local> [remote]");
                    continue;
                }
                let local_pattern = parts[arg_start];
                // Explicit remote destination only makes sense for single-file transfers
                let explicit_remote = if parts.len() > arg_start + 1 {
                    Some(parts[arg_start + 1].to_string())
                } else {
                    None
                };

                let expanded = expand_local_glob(&local_cwd, local_pattern);
                let multi = expanded.len() > 1;

                for local_str in &expanded {
                    let local_path = PathBuf::from(local_str);
                    let remote: String = if let (Some(ref r), false) = (&explicit_remote, multi) {
                        r.clone()
                    } else {
                        local_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(local_str.as_str())
                            .to_string()
                    };
                    if recursive {
                        match upload_recursive(client, &local_path, &remote).await {
                            Ok(_) => {}
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    } else {
                        eprintln!("Uploading {} -> {}", local_path.display(), remote);
                        match client.upload(&local_path, &remote).await {
                            Ok(_) => {}
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                }
            }
            "mkdir" => {
                if parts.len() < 2 {
                    eprintln!("Usage: mkdir <path>");
                    continue;
                }
                let resp = client
                    .command(&Request::Mkdir {
                        path: parts[1].to_string(),
                    })
                    .await?;
                match resp {
                    Response::Ok => println!("Created {}", parts[1]),
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "rm" => {
                if parts.len() < 2 {
                    eprintln!("Usage: rm <path>");
                    continue;
                }
                let resp = client
                    .command(&Request::Rm {
                        path: parts[1].to_string(),
                    })
                    .await?;
                match resp {
                    Response::Ok => println!("Removed {}", parts[1]),
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "rename" => {
                if parts.len() < 3 {
                    eprintln!("Usage: rename <old> <new>");
                    continue;
                }
                let resp = client
                    .command(&Request::Rename {
                        old_path: parts[1].to_string(),
                        new_path: parts[2].to_string(),
                    })
                    .await?;
                match resp {
                    Response::Ok => println!("Renamed {} -> {}", parts[1], parts[2]),
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "chmod" => {
                if parts.len() < 3 {
                    eprintln!("Usage: chmod <mode> <path>");
                    continue;
                }
                let mode = u32::from_str_radix(parts[1], 8)?;
                let resp = client
                    .command(&Request::Chmod {
                        path: parts[2].to_string(),
                        mode,
                    })
                    .await?;
                match resp {
                    Response::Ok => println!("Changed mode of {}", parts[2]),
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "stat" => {
                if parts.len() < 2 {
                    eprintln!("Usage: stat <path>");
                    continue;
                }
                let resp = client
                    .command(&Request::Stat {
                        path: parts[1].to_string(),
                    })
                    .await?;
                match resp {
                    Response::FileStat { stat } => {
                        println!("  Size: {}", qsftp::client::format_size(stat.size));
                        println!("  Mode: {:o}", stat.mode & 0o7777);
                        println!("  UID:  {}", stat.uid);
                        println!("  GID:  {}", stat.gid);
                        println!("  Type: {}", if stat.is_dir { "directory" } else { "file" });
                    }
                    Response::Error { message } => eprintln!("Error: {}", message),
                    _ => eprintln!("Unexpected response"),
                }
            }
            "exit" | "quit" | "bye" => {
                println!("Goodbye.");
                break;
            }
            _ => {
                eprintln!("Unknown command: {}. Type 'help' for available commands.", cmd);
            }
        }
    }

    Ok(())
}

async fn download_recursive(client: &QsftpClient, remote_dir: &str, local_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(local_dir).await?;

    let resp = client
        .command(&Request::Ls {
            path: remote_dir.to_string(),
        })
        .await?;

    match resp {
        Response::DirListing { entries } => {
            for entry in entries {
                let remote_path = format!("{}/{}", remote_dir, entry.name);
                let local_path = local_dir.join(&entry.name);

                if entry.is_dir {
                    Box::pin(download_recursive(client, &remote_path, &local_path)).await?;
                } else {
                    eprintln!("Downloading {}", remote_path);
                    client.download(&remote_path, &local_path).await?;
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("Failed to list {}: {}", remote_dir, message);
        }
        _ => {
            anyhow::bail!("Unexpected response");
        }
    }

    Ok(())
}

async fn upload_recursive(client: &QsftpClient, local_dir: &Path, remote_dir: &str) -> Result<()> {
    let _ = client
        .command(&Request::Mkdir {
            path: remote_dir.to_string(),
        })
        .await?;

    let mut dir = tokio::fs::read_dir(local_dir).await?;
    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.metadata().await?;
        let name = entry.file_name().to_string_lossy().to_string();
        let remote_path = format!("{}/{}", remote_dir, name);
        let local_path = entry.path();

        if meta.is_dir() {
            Box::pin(upload_recursive(client, &local_path, &remote_path)).await?;
        } else {
            eprintln!("Uploading {}", local_path.display());
            client.upload(&local_path, &remote_path).await?;
        }
    }

    Ok(())
}

fn format_mode(mode: u32) -> String {
    let mode = mode & 0o777;
    let mut s = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}
