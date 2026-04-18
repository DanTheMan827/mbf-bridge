#[cfg(all(any(windows, target_os = "linux"), feature = "embed-adb"))]
use std::sync::LazyLock;

use std::{sync::OnceLock, time::Duration};

#[cfg(any(all(windows, feature = "embed-adb"), all(target_os = "linux", feature = "embed-adb")))]
use std::io::Read;

#[cfg(any(all(windows, feature = "embed-adb"), all(target_os = "linux", feature = "embed-adb")))]
use flate2::read::GzDecoder;

#[cfg(not(target_os = "android"))]
use std::env;

use tokio::net::TcpStream;

pub static ADB_PORT: OnceLock<u16> = OnceLock::new();

/// Returns `true` when an embedded (or bundled) ADB binary is available to
/// start the ADB server automatically.
///
/// This is `true` only when:
///  - the `embed-adb` Cargo feature is enabled, **and**
///  - the current platform has an embedded/bundled binary (Windows, Linux,
///    or macOS with the binary placed next to the executable), **and**
///  - the app is not running inside the macOS sandbox (sandboxed apps cannot
///    launch helper processes).
pub fn embedded_adb_available() -> bool {
    if !cfg!(feature = "embed-adb") {
        return false;
    }

    #[cfg(target_os = "macos")]
    if is_macos_sandboxed() {
        return false;
    }

    // Platforms with an embedded/bundled ADB binary.
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

/// Returns `true` when the macOS App Sandbox is active for this process.
#[cfg(target_os = "macos")]
pub fn is_macos_sandboxed() -> bool {
    std::env::var("APP_SANDBOX_CONTAINER_ID").is_ok()
}

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
    command.args(&["server", "nodaemon", "-P", ADB_PORT.get_or_init(|| 5037).to_string().as_str()]);
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
    let port = ADB_PORT.get_or_init(|| 5037);
    TcpStream::connect(format!("127.0.0.1:{}", port)).await
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
#[cfg(all(windows, feature = "embed-adb"))]
static ADB_WIN_EXE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let compressed = include_bytes!("../../adb-gz/win/adb.exe");
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).expect("decompress adb.exe");
    buf
});

#[cfg(all(windows, feature = "embed-adb"))]
static ADB_WIN_API_DLL: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let compressed = include_bytes!("../../adb-gz/win/AdbWinApi.dll");
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).expect("decompress AdbWinApi.dll");
    buf
});

#[cfg(all(windows, feature = "embed-adb"))]
static ADB_WIN_USB_DLL: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let compressed = include_bytes!("../../adb-gz/win/AdbWinUsbApi.dll");
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).expect("decompress AdbWinUsbApi.dll");
    buf
});

#[cfg(all(windows, feature = "embed-adb"))]
pub async fn extract_adb_binaries_windows() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};
    use uuid::Uuid;

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb.exe");
    write(&adb_path, &*ADB_WIN_EXE).await?;
    write(adb_subfolder.join("AdbWinApi.dll"), &*ADB_WIN_API_DLL).await?;
    write(adb_subfolder.join("AdbWinUsbApi.dll"), &*ADB_WIN_USB_DLL).await?;
    Ok(adb_path)
}

/// Extracts ADB binaries for Linux into a temporary subfolder and returns the path to the ADB executable.
///
/// The subfolder is named with a randomly generated UUID (using v4 as a placeholder for v7).
#[cfg(all(target_os = "linux", feature = "embed-adb"))]
static ADB_LINUX_BIN: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let compressed = include_bytes!("../../adb-gz/linux/adb");
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).expect("decompress adb");
    buf
});

#[cfg(all(target_os = "linux", feature = "embed-adb"))]
pub async fn extract_adb_binaries_linux() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};
    use uuid::Uuid;

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb");
    write(&adb_path, &*ADB_LINUX_BIN).await?;
    // Set executable permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&adb_path, std::fs::Permissions::from_mode(0o755))?;
    Ok(adb_path)
}

/// Ensures a connection to the ADB server, starting it if necessary.
///
/// On Windows and Linux (when the `embed-adb` feature is enabled), if ADB is
/// not running the binaries are extracted into a temporary subfolder and then
/// started.  On macOS (when `embed-adb` is enabled and the app is not
/// sandboxed) the bundled `adb` binary located next to the executable is used.
///
/// When the `embed-adb` feature is disabled, or when running inside the macOS
/// sandbox, only the system-installed `adb` is attempted.  If that also fails
/// an `Err` is returned so the caller can inform the user to install ADB.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the ADB connection.
pub async fn adb_connect_or_start() -> tokio::io::Result<TcpStream> {
    // Try to connect first.
    if let Ok(stream) = adb_connect().await {
        return Ok(stream);
    }

    // Attempt to start ADB using the system-installed binary.
    if adb_start("adb").await.is_ok() {
        if let Ok(stream) = adb_connect_retry().await {
            return Ok(stream);
        }
    }

    // Fallback extraction logic depending on the operating system.
    // Each platform block returns on success; all fall through to the final Err
    // when the feature is disabled, the platform is unsupported, or (on macOS)
    // the app is sandboxed.

    #[cfg(all(windows, feature = "embed-adb"))]
    {
        let adb_path = extract_adb_binaries_windows().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    #[cfg(all(target_os = "linux", feature = "embed-adb"))]
    {
        let adb_path = extract_adb_binaries_linux().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    #[cfg(all(target_os = "macos", feature = "embed-adb"))]
    if !is_macos_sandboxed() {
        let adb_exe = env::current_exe().unwrap().parent().unwrap().join("adb");
        adb_start(adb_exe.to_str().unwrap()).await.unwrap();
        return adb_connect_retry().await;
    }

    // No ADB binary could be started (feature disabled, unsupported platform,
    // or macOS sandbox).  The caller is responsible for notifying the user.
    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "no-embedded-adb",
    ))
}
