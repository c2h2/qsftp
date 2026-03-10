use anyhow::Result;
use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let port: u16 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10222".to_string())
        .parse()?;

    let username = std::env::args()
        .nth(2)
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));

    let password = rpassword::read_password_from_tty(Some(&format!(
        "Password for {}: ", username
    )))?;

    let addr = format!("127.0.0.1:{}", port).parse()?;

    println!("Connecting to {} as {}...", addr, username);
    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;

    match QsftpClient::authenticate(connection, &username, &password).await {
        Ok(client) => {
            println!("PAM Authentication successful!");
            println!("Home: {}", client.home_dir);

            // Quick test
            let resp = client.command(&Request::Ls { path: ".".to_string() }).await?;
            match resp {
                Response::DirListing { entries } => {
                    println!("Listed {} entries in home dir", entries.len());
                }
                _ => {}
            }
        }
        Err(e) => {
            eprintln!("Authentication FAILED: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
