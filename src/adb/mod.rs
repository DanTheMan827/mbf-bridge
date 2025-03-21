use std::time::Duration;

#[cfg(not(target_os = "android"))]
use std::env;

use tokio::net::TcpStream;

/// Starts the ADB server using the provided executable path.
///
/// This function spawns the ADB server with arguments `server nodaemon` and the environment variable
/// `ADB_MDNS_OPENSCREEN` set to 1. It detaches stdout and stderr.
///
/// # Arguments
///
/// * `path` - Path to the ADB executable.
///
/// # Returns
///
/// A `tokio::io::Result<()>` indicating success or failure.
pub async fn adb_start(path: &str) -> tokio::io::Result<()> {
    use std::process::Stdio;
    use tokio::process::Command;

    let mut command = Command::new(path);
    command.args(&["server", "nodaemon"]);
    command.env("ADB_MDNS_OPENSCREEN", "1");
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW

    let mut process = command.spawn()?;
    // Spawn a background task to wait for the process (avoid blocking)
    tokio::spawn(async move {
        let _ = process.wait().await;
    });
    Ok(())
}

/// Connects to the ADB server.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the connection to the ADB server.
pub async fn adb_connect() -> tokio::io::Result<TcpStream> {
    TcpStream::connect("127.0.0.1:5037").await
}

/// Retries the connection to the ADB server up to 10 times with short delays.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the successful connection or an error.
pub async fn adb_connect_retry() -> tokio::io::Result<TcpStream> {
    let mut attempts = 0;
    loop {
        match adb_connect().await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if attempts == 10 {
                    return Err(err);
                }
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Extracts ADB binaries for Windows into a temporary subfolder and returns the path to the ADB executable.
///
/// The subfolder is named with a randomly generated UUID (using v4 as a placeholder for v7).
#[cfg(windows)]
pub async fn extract_adb_binaries_windows() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};
    use uuid::Uuid;

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb.exe");
    write(&adb_path, include_bytes!("../../adb/win/adb.exe")).await?;
    write(
        adb_subfolder.join("AdbWinApi.dll"),
        include_bytes!("../../adb/win/AdbWinApi.dll"),
    )
    .await?;
    write(
        adb_subfolder.join("AdbWinUsbApi.dll"),
        include_bytes!("../../adb/win/AdbWinUsbApi.dll"),
    )
    .await?;
    Ok(adb_path)
}

/// Extracts ADB binaries for Linux into a temporary subfolder and returns the path to the ADB executable.
///
/// The subfolder is named with a randomly generated UUID (using v4 as a placeholder for v7).
#[cfg(target_os = "linux")]
pub async fn extract_adb_binaries_linux() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb");
    write(&adb_path, include_bytes!("../../adb/linux/adb")).await?;
    // Set executable permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&adb_path, std::fs::Permissions::from_mode(0o755))?;
    Ok(adb_path)
}

/// Ensures a connection to the ADB server, starting it if necessary.
///
/// On Windows and Linux, if ADB is not running, the binaries are extracted into a temporary
/// subfolder (named with a random UUID) and then started.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the ADB connection.
pub async fn adb_connect_or_start() -> tokio::io::Result<TcpStream> {
    // Try to connect first.
    if let Ok(stream) = adb_connect().await {
        return Ok(stream);
    }

    // Attempt to start ADB normally using system-installed "adb".
    if adb_start("adb").await.is_ok() {
        return adb_connect_retry().await;
    }

    // Fallback extraction logic depending on the operating system.
    #[cfg(windows)]
    {
        let adb_path = extract_adb_binaries_windows().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    #[cfg(target_os = "linux")]
    {
        let adb_path = extract_adb_binaries_linux().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, assume ADB is located alongside the executable.
        let adb_exe = env::current_exe().unwrap().parent().unwrap().join("adb");
        adb_start(adb_exe.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    return Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ADB connection failed",
    ));
}
