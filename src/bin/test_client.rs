use anyhow::Result;
use std::path::PathBuf;
use qsftp::client::QsftpClient;
use qsftp::protocol::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10222".to_string())
        .parse()?;

    let addr = format!("127.0.0.1:{}", port).parse()?;

    println!("=== QSFTP Test Client ===");
    println!("Connecting to {}...", addr);

    let (connection, _endpoint) = QsftpClient::connect(addr, "localhost").await?;
    println!("[OK] Connected");

    let client = QsftpClient::authenticate(connection, "test", "test").await?;
    println!("[OK] Authenticated. Home: {}", client.home_dir);

    // Test: pwd
    println!("\n--- Test: pwd ---");
    let resp = client.command(&Request::Pwd).await?;
    match resp {
        Response::Pwd { path } => println!("[OK] PWD: {}", path),
        _ => println!("[FAIL] Unexpected response: {:?}", resp),
    }

    // Test: ls
    println!("\n--- Test: ls ---");
    let resp = client.command(&Request::Ls { path: ".".to_string() }).await?;
    match resp {
        Response::DirListing { entries } => {
            println!("[OK] Listed {} entries", entries.len());
            for e in entries.iter().take(10) {
                println!("  {} {} {}", if e.is_dir { "d" } else { "-" }, e.size, e.name);
            }
            if entries.len() > 10 {
                println!("  ... and {} more", entries.len() - 10);
            }
        }
        _ => println!("[FAIL] Unexpected response: {:?}", resp),
    }

    // Test: mkdir
    println!("\n--- Test: mkdir ---");
    let test_dir = "/tmp/qsftp_test_dir";
    let _ = tokio::fs::remove_dir_all(test_dir).await;
    let resp = client.command(&Request::Mkdir { path: test_dir.to_string() }).await?;
    match resp {
        Response::Ok => println!("[OK] mkdir {}", test_dir),
        _ => println!("[FAIL] mkdir: {:?}", resp),
    }

    // Test: upload a file
    println!("\n--- Test: upload ---");
    let test_data = vec![0xABu8; 1024 * 1024]; // 1 MiB test file
    let local_upload = PathBuf::from("/tmp/qsftp_test_upload.bin");
    tokio::fs::write(&local_upload, &test_data).await?;
    let remote_path = format!("{}/test_file.bin", test_dir);
    match client.upload(&local_upload, &remote_path).await {
        Ok(n) => println!("[OK] Uploaded {} bytes", n),
        Err(e) => println!("[FAIL] Upload failed: {}", e),
    }

    // Test: stat the uploaded file
    println!("\n--- Test: stat ---");
    let resp = client.command(&Request::Stat { path: remote_path.clone() }).await?;
    match resp {
        Response::FileStat { stat } => {
            println!("[OK] Stat: size={}, mode={:o}, is_dir={}", stat.size, stat.mode & 0o7777, stat.is_dir);
            assert_eq!(stat.size, 1024 * 1024);
        }
        _ => println!("[FAIL] stat: {:?}", resp),
    }

    // Test: download the file back
    println!("\n--- Test: download ---");
    let local_download = PathBuf::from("/tmp/qsftp_test_download.bin");
    match client.download(&remote_path, &local_download).await {
        Ok(n) => {
            println!("[OK] Downloaded {} bytes", n);
            let downloaded = tokio::fs::read(&local_download).await?;
            if downloaded == test_data {
                println!("[OK] Data integrity verified!");
            } else {
                println!("[FAIL] Data mismatch! Expected {} bytes, got {}", test_data.len(), downloaded.len());
            }
        }
        Err(e) => println!("[FAIL] Download failed: {}", e),
    }

    // Test: cd
    println!("\n--- Test: cd ---");
    let resp = client.command(&Request::Cd { path: test_dir.to_string() }).await?;
    match resp {
        Response::Ok => println!("[OK] cd {}", test_dir),
        _ => println!("[FAIL] cd: {:?}", resp),
    }
    let resp = client.command(&Request::Pwd).await?;
    match resp {
        Response::Pwd { path } => println!("[OK] PWD after cd: {}", path),
        _ => {}
    }

    // Test: ls in the test dir
    println!("\n--- Test: ls after cd ---");
    let resp = client.command(&Request::Ls { path: ".".to_string() }).await?;
    match resp {
        Response::DirListing { entries } => {
            println!("[OK] Listed {} entries in test dir", entries.len());
            for e in &entries {
                println!("  {} {}", e.name, e.size);
            }
        }
        _ => println!("[FAIL]"),
    }

    // Test: rename
    println!("\n--- Test: rename ---");
    let resp = client.command(&Request::Rename {
        old_path: "test_file.bin".to_string(),
        new_path: "renamed_file.bin".to_string(),
    }).await?;
    match resp {
        Response::Ok => println!("[OK] Renamed"),
        _ => println!("[FAIL] rename: {:?}", resp),
    }

    // Test: large file transfer (throughput test)
    println!("\n--- Test: large file transfer (100 MiB) ---");
    let large_data = vec![0x42u8; 100 * 1024 * 1024];
    let large_local = PathBuf::from("/tmp/qsftp_test_large.bin");
    tokio::fs::write(&large_local, &large_data).await?;

    let start = std::time::Instant::now();
    let remote_large = format!("{}/large_file.bin", test_dir);
    match client.upload(&large_local, &remote_large).await {
        Ok(n) => {
            let elapsed = start.elapsed().as_secs_f64();
            let speed = n as f64 / elapsed / 1024.0 / 1024.0;
            println!("[OK] Upload: {} bytes in {:.2}s = {:.1} MiB/s", n, elapsed, speed);
        }
        Err(e) => println!("[FAIL] Large upload: {}", e),
    }

    let start = std::time::Instant::now();
    let large_download = PathBuf::from("/tmp/qsftp_test_large_dl.bin");
    match client.download(&remote_large, &large_download).await {
        Ok(n) => {
            let elapsed = start.elapsed().as_secs_f64();
            let speed = n as f64 / elapsed / 1024.0 / 1024.0;
            println!("[OK] Download: {} bytes in {:.2}s = {:.1} MiB/s", n, elapsed, speed);
        }
        Err(e) => println!("[FAIL] Large download: {}", e),
    }

    // Verify large file integrity
    let orig = tokio::fs::read(&large_local).await?;
    let downloaded = tokio::fs::read(&large_download).await?;
    if orig == downloaded {
        println!("[OK] Large file integrity verified!");
    } else {
        println!("[FAIL] Large file data mismatch!");
    }

    // Test: rm
    println!("\n--- Test: cleanup ---");
    let resp = client.command(&Request::Rm { path: test_dir.to_string() }).await?;
    match resp {
        Response::Ok => println!("[OK] Removed test directory"),
        _ => println!("[FAIL] rm: {:?}", resp),
    }

    // Cleanup temp files
    let _ = tokio::fs::remove_file("/tmp/qsftp_test_upload.bin").await;
    let _ = tokio::fs::remove_file("/tmp/qsftp_test_download.bin").await;
    let _ = tokio::fs::remove_file("/tmp/qsftp_test_large.bin").await;
    let _ = tokio::fs::remove_file("/tmp/qsftp_test_large_dl.bin").await;

    println!("\n=== All tests passed! ===");

    Ok(())
}
