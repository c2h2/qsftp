use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use qsftp::client::QsftpClient;
use qsftp::protocol::ZSTD_LEVEL;

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

struct BenchResult {
    label: &'static str,
    up_mibps: f64,
    dl_mibps: f64,
    ratio: Option<f64>, // compressed size / raw size (None if no compression)
}

async fn run_pass(
    client: &QsftpClient,
    test_file: &PathBuf,
    dl_file: &PathBuf,
    remote: &str,
    compress: bool,
    source_hash: &str,
) -> Result<BenchResult> {
    let file_size = tokio::fs::metadata(test_file).await?.len() as f64;

    // Upload — measure wire size for compression ratio via a temp compressed file
    let ratio = if compress {
        // Compress the source file locally to measure actual compressed size
        let raw_bytes = tokio::fs::read(test_file).await?;
        let compressed = tokio::task::spawn_blocking(move || {
            zstd::encode_all(raw_bytes.as_slice(), ZSTD_LEVEL)
        }).await??;
        Some(compressed.len() as f64 / file_size)
    } else {
        None
    };

    let start = std::time::Instant::now();
    let sent = client.upload(test_file, remote, compress).await?;
    let up_elapsed = start.elapsed().as_secs_f64();
    let up_mibps = sent as f64 / up_elapsed / 1024.0 / 1024.0;

    // Download
    let start = std::time::Instant::now();
    let received = client.download(remote, dl_file, compress).await?;
    let dl_elapsed = start.elapsed().as_secs_f64();
    let dl_mibps = received as f64 / dl_elapsed / 1024.0 / 1024.0;

    // Integrity check
    let dl_hash = sha256_file(dl_file).await?;
    if dl_hash != source_hash {
        anyhow::bail!(
            "HASH MISMATCH (compress={}) — DATA CORRUPTION DETECTED\n  expected: {}\n  got:      {}",
            compress, source_hash, dl_hash
        );
    }

    let label = if compress { "zstd compressed" } else { "uncompressed" };
    Ok(BenchResult { label, up_mibps, dl_mibps, ratio })
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

    // Two test files: compressible (text-like) and incompressible (binary)
    let tests: &[(&str, Box<dyn Fn(usize) -> u8>)] = &[
        ("compressible (text-like)", Box::new(|i| (i % 64) as u8)),
        ("incompressible (random-ish)", Box::new(|i| {
            // LCG to approximate random bytes
            let x = (i as u64).wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })),
    ];

    for (file_label, byte_fn) in tests {
        println!("\n{}", "=".repeat(60));
        println!("File type: {}", file_label);
        println!("{}", "=".repeat(60));

        let test_file = PathBuf::from("/tmp/qsftp_bench_file.bin");
        let dl_file = PathBuf::from("/tmp/qsftp_bench_download.bin");
        let remote = "/tmp/qsftp_bench_remote.bin";

        // Generate test file
        print!("  Generating {} MiB test file... ", size_mb);
        {
            use tokio::io::AsyncWriteExt;
            let mut f = tokio::fs::File::create(&test_file).await?;
            for i in 0..size_mb {
                let byte = byte_fn(i);
                f.write_all(&vec![byte; 1024 * 1024]).await?;
            }
            f.flush().await?;
        }
        println!("done");

        let source_hash = sha256_file(&test_file).await?;
        println!("  SHA-256: {}", source_hash);

        let mut results = Vec::new();

        for compress in [false, true] {
            let label = if compress { "zstd" } else { "plain" };
            print!("  Running {} pass... ", label);
            let r = run_pass(&client, &test_file, &dl_file, remote, compress, &source_hash).await?;
            println!("upload {:.1} MiB/s  download {:.1} MiB/s  integrity OK", r.up_mibps, r.dl_mibps);
            results.push(r);
        }

        // Print comparison table
        println!();
        let plain = &results[0];
        println!("  {:<22} {:>12} {:>12} {:>14} {:>8}", "Mode", "Upload", "Download", "Wire ratio", "Speedup");
        println!("  {}", "-".repeat(76));
        for r in &results {
            let ratio_str = match r.ratio {
                Some(ratio) => format!("{:.2}%", ratio * 100.0),
                None => "100.00% (raw)".to_string(),
            };
            let speedup_up = format!("{:.1}x", r.up_mibps / plain.up_mibps);
            let speedup_dl = format!("{:.1}x", r.dl_mibps / plain.dl_mibps);
            let speedup_str = if r.ratio.is_none() {
                "baseline".to_string()
            } else {
                format!("up {}  dl {}", speedup_up, speedup_dl)
            };
            println!(
                "  {:<22} {:>9.1} MiB/s {:>9.1} MiB/s {:>14} {:>16}",
                r.label, r.up_mibps, r.dl_mibps, ratio_str, speedup_str
            );
        }

        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_file(&dl_file).await;
        let _ = tokio::fs::remove_file(remote).await;
    }

    println!("\n=== Benchmark complete — all integrity checks passed ===");
    Ok(())
}
