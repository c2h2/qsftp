use anyhow::Result;
use std::path::PathBuf;
use qsftp::client::QsftpClient;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let port: u16 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10222".to_string())
        .parse()?;

    let size_mb: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1024".to_string())
        .parse()?;

    let addr = format!("127.0.0.1:{}", port).parse()?;

    println!("=== QSFTP Benchmark: {} MiB ===", size_mb);
    println!("Connecting...");

    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;
    let client = QsftpClient::authenticate(connection, "test", "test").await?;

    // Generate test file
    let test_file = PathBuf::from("/tmp/qsftp_bench_file.bin");
    println!("Generating {} MiB test file...", size_mb);
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::File::create(&test_file).await?;
        let chunk = vec![0x55u8; 1024 * 1024];
        for _ in 0..size_mb {
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
    }

    let remote = "/tmp/qsftp_bench_remote.bin";

    // Upload benchmark
    println!("\n--- Upload {} MiB ---", size_mb);
    let start = std::time::Instant::now();
    let bytes = client.upload(&test_file, remote).await?;
    let elapsed = start.elapsed().as_secs_f64();
    let speed = bytes as f64 / elapsed / 1024.0 / 1024.0;
    println!("Upload: {:.1} MiB/s ({:.2}s)", speed, elapsed);

    // Download benchmark
    let dl_file = PathBuf::from("/tmp/qsftp_bench_download.bin");
    println!("\n--- Download {} MiB ---", size_mb);
    let start = std::time::Instant::now();
    let bytes = client.download(remote, &dl_file).await?;
    let elapsed = start.elapsed().as_secs_f64();
    let speed = bytes as f64 / elapsed / 1024.0 / 1024.0;
    println!("Download: {:.1} MiB/s ({:.2}s)", speed, elapsed);

    // Cleanup
    let _ = tokio::fs::remove_file(&test_file).await;
    let _ = tokio::fs::remove_file(&dl_file).await;
    let _ = tokio::fs::remove_file(remote).await;

    println!("\n=== Benchmark complete ===");
    Ok(())
}
