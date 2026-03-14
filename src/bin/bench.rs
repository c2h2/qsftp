use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use qsftp::client::QsftpClient;

async fn sha256_file(path: &std::path::Path) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

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

    // Generate test file with pseudo-random-ish content (not all zeros, catches corruption)
    let test_file = PathBuf::from("/tmp/qsftp_bench_file.bin");
    println!("Generating {} MiB test file...", size_mb);
    {
        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::File::create(&test_file).await?;
        // Use a repeating pattern that varies per MB so byte-level corruption is detectable
        for i in 0..size_mb {
            let byte = (i & 0xFF) as u8;
            let chunk = vec![byte ^ 0xA5; 1024 * 1024];
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
    }

    println!("Hashing source file...");
    let source_hash = sha256_file(&test_file).await?;
    println!("  SHA-256: {}", source_hash);

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

    // Integrity check
    println!("\n--- Integrity check ---");
    let dl_hash = sha256_file(&dl_file).await?;
    println!("  Source SHA-256:   {}", source_hash);
    println!("  Download SHA-256: {}", dl_hash);
    if source_hash == dl_hash {
        println!("  ✓ Hashes match — data integrity verified");
    } else {
        eprintln!("  ✗ HASH MISMATCH — DATA CORRUPTION DETECTED");
        std::process::exit(1);
    }

    // Cleanup
    let _ = tokio::fs::remove_file(&test_file).await;
    let _ = tokio::fs::remove_file(&dl_file).await;
    let _ = tokio::fs::remove_file(remote).await;

    println!("\n=== Benchmark complete ===");
    Ok(())
}
