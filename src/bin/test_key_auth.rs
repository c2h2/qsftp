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

    let identity = std::env::args().nth(2);

    let addr = format!("127.0.0.1:{}", port).parse()?;

    println!("=== SSH Key Auth Test ===");

    // Find private key
    let key_path = identity.as_ref().map(|s| std::path::Path::new(s.as_str()));
    let private_key = qsftp::ssh_auth::find_private_key(key_path)?;
    println!("Using key: {}", qsftp::ssh_auth::public_key_openssh(&private_key));

    // Connect
    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;
    println!("Connected.");

    // Authenticate with key
    let username = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let client = QsftpClient::authenticate_key(connection, &username, &private_key).await?;
    println!("Authenticated! Home: {}", client.home_dir);

    // Quick test
    let resp = client.command(&Request::Pwd).await?;
    println!("PWD: {:?}", resp);

    let resp = client.command(&Request::Ls { path: ".".to_string() }).await?;
    match resp {
        Response::DirListing { entries } => {
            println!("Listed {} entries", entries.len());
        }
        _ => println!("Unexpected: {:?}", resp),
    }

    println!("\n=== SSH Key Auth Test PASSED ===");
    Ok(())
}
