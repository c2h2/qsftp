/// Automated PAM auth test - pass password as arg
use anyhow::Result;
use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .init();

    let port: u16 = std::env::args().nth(1).unwrap_or("1022".into()).parse()?;
    let user = std::env::args().nth(2).unwrap_or_else(|| {
        std::env::var("USER").unwrap_or("root".into())
    });
    let pass = std::env::args().nth(3).unwrap_or_default();

    let addr = format!("127.0.0.1:{}", port).parse()?;
    println!("Testing PAM auth: user={} port={}", user, port);

    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;
    match QsftpClient::authenticate(connection, &user, &pass).await {
        Ok(client) => {
            println!("AUTH OK - home: {}", client.home_dir);
            let resp = client.command(&Request::Pwd).await?;
            println!("PWD: {:?}", resp);
        }
        Err(e) => {
            println!("AUTH FAILED: {}", e);
        }
    }
    Ok(())
}
