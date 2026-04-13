use serde::Serialize;
use std::sync::{Arc, LazyLock};
use tauri::{Emitter, WebviewWindow};

pub static INIT_SCRIPT: LazyLock<String> = LazyLock::new(|| {
    // Prefix the init script with the ADB-available flag so bridge.js can
    // expose `isAdbAvailable` without an extra IPC round-trip.
    format!(
        "window.__mbfIsAdbAvailable=true;\n{}",
        include_str!("bridge.js")
    )
});

/// Maximum number of unacknowledged chunks in flight from Rust → JS.
/// When this limit is reached the read loop blocks, propagating back-pressure
/// all the way to the ADB TCP socket and ultimately to the device.
const FLOW_WINDOW: usize = 8;

/// Read buffer size per chunk (1 MiB).
const READ_BUFFER_SIZE: usize = 1 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct AdbConnectedPayload {
    pub id: String,
    pub success: bool,
}

#[derive(Serialize, Clone)]
pub struct AdbDataPayload {
    pub id: String,
    /// Raw bytes serialised as a JSON array of integers so the JS side can
    /// wrap them directly with `new Uint8Array(event.payload.data)`.
    pub data: Vec<u8>,
}

#[derive(Serialize, Clone)]
pub struct AdbClosedPayload {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

struct ConnectionState {
    writer: tokio::net::tcp::OwnedWriteHalf,
    /// Semaphore implementing the flow-control window.
    /// Starts with `FLOW_WINDOW` permits.  The read loop acquires one permit
    /// before emitting each `adb-data` event and forgets it (no auto-release).
    /// `adb_ack` restores a single permit; `close` closes the semaphore.
    flow_semaphore: Arc<tokio::sync::Semaphore>,
    /// Held only for its drop side-effect: dropping the `Sender` wakes the
    /// read loop's `watch::Receiver` with a `RecvError`, causing it to exit.
    #[allow(dead_code)]
    close_tx: tokio::sync::watch::Sender<bool>,
}

// ---------------------------------------------------------------------------
// AdbBridge
// ---------------------------------------------------------------------------

/// Tauri-managed state object that owns all active ADB connections.
///
/// Works on all platforms including Android, which is expected to be running
/// a custom adbd instance.
#[derive(Default)]
pub struct AdbBridge {
    connections: Arc<tokio::sync::Mutex<std::collections::HashMap<String, ConnectionState>>>,
}

/// Returns `true` when `winget` is available in the current environment.
#[cfg(windows)]
fn is_winget_available() -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("winget")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Handles the "no embedded ADB" error case.
///
/// On Windows, if `winget` is available the user is offered the choice to
/// install Google Platform Tools (`winget install --id Google.PlatformTools`).
/// If installation succeeds and ADB starts, the live `TcpStream` is returned.
///
/// On every other platform (or when the user declines / winget is absent) a
/// modal error dialog is shown and `None` is returned.
#[cfg(not(target_os = "android"))]
async fn handle_no_adb() -> Option<tokio::net::TcpStream> {
    use rfd::{MessageButtons, MessageDialog, MessageLevel};

    // ── Windows: offer to install via winget ────────────────────────────
    #[cfg(windows)]
    if is_winget_available() {
        use rfd::MessageDialogResult;
        let wants_install = tokio::task::spawn_blocking(|| {
            MessageDialog::new()
                .set_title("Install ADB?")
                .set_description(
                    "ADB (Android Debug Bridge) is required but could not be started.\n\n\
                    Would you like to install Google Platform Tools (ADB) \
                    using Windows Package Manager (winget)?",
                )
                .set_level(MessageLevel::Warning)
                .set_buttons(MessageButtons::YesNo)
                .show()
                == MessageDialogResult::Yes
        })
        .await
        .unwrap_or(false);

        if !wants_install {
            // User explicitly declined – respect the choice and return.
            return None;
        }

        let installed = tokio::task::spawn_blocking(|| {
            std::process::Command::new("winget")
                .args(&[
                    "install",
                    "--id",
                    "Google.PlatformTools",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);

        if installed {
            if crate::adb::adb_start("adb").await.is_ok() {
                if let Ok(stream) = crate::adb::adb_connect_retry().await {
                    return Some(stream);
                }
            }
        }
        // Installation failed or ADB still unreachable – fall through to
        // the generic error dialog below.
    }

    // ── Generic fallback: ask the user to install ADB manually ──────────
    tokio::task::spawn_blocking(|| {
        MessageDialog::new()
            .set_title("ADB Not Available")
            .set_description(
                "ADB could not be started automatically.\n\n\
                Please install ADB (Android Debug Bridge) and ensure it is \
                in your PATH, or start the ADB server manually before \
                launching this application.\n\n\
                Download: https://developer.android.com/studio/releases/platform-tools",
            )
            .set_level(MessageLevel::Error)
            .set_buttons(MessageButtons::Ok)
            .show();
    })
    .await
    .ok();

    None
}

impl AdbBridge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a new ADB connection identified by `id`.
    ///
    /// The connection state is inserted into the map **before** the
    /// `adb-connected` event is emitted, so `adb_write` is immediately
    /// available to the JS caller.
    ///
    /// Events are emitted only to the `window` that requested the connection,
    /// keeping multiple windows isolated from each other.
    pub async fn connect(&self, id: String, window: WebviewWindow) -> Result<(), String> {
        use tokio::io::AsyncReadExt;

        let connections = self.connections.clone();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(FLOW_WINDOW));
        let (close_tx, close_rx) = tokio::sync::watch::channel(false);
        let semaphore_clone = semaphore.clone();

        tauri::async_runtime::spawn(async move {
            // Attempt to acquire an ADB stream.  On Windows, when no embedded
            // ADB is available, `handle_no_adb` may offer a winget install and
            // return a live stream on success.
            let stream = match crate::adb::adb_connect_or_start().await {
                Ok(s) => Some(s),
                Err(e) if e.to_string() == "no-embedded-adb" => {
                    #[cfg(not(target_os = "android"))]
                    {
                        handle_no_adb().await
                    }
                    #[cfg(target_os = "android")]
                    {
                        let _ = e;
                        None
                    }
                }
                Err(_) => None,
            };

            let stream = match stream {
                Some(s) => s,
                None => {
                    let _ = window.emit(
                        "adb-connected",
                        AdbConnectedPayload {
                            id,
                            success: false,
                        },
                    );
                    return;
                }
            };

            let (mut reader, writer) = stream.into_split();

            // Insert before emitting so the write path is ready.
            connections.lock().await.insert(
                id.clone(),
                ConnectionState {
                    writer,
                    flow_semaphore: semaphore_clone.clone(),
                    close_tx,
                },
            );

            let _ = window.emit(
                "adb-connected",
                AdbConnectedPayload {
                    id: id.clone(),
                    success: true,
                },
            );

            let mut buf = vec![0u8; READ_BUFFER_SIZE];
            let mut close_rx = close_rx;

            loop {
                // ---- acquire a flow-control permit ----
                // Blocks when JS has not yet acknowledged FLOW_WINDOW chunks,
                // applying back-pressure on the ADB socket.
                let permit = tokio::select! {
                    p = semaphore_clone.acquire() => match p {
                        Ok(p) => p,
                        // Semaphore closed by adb_close – stop reading.
                        Err(_) => break,
                    },
                    // Cooperative shutdown signal.
                    _ = close_rx.changed() => break,
                };
                // Permit is released manually via adb_ack, not on drop.
                permit.forget();

                // ---- read next chunk ----
                let n = tokio::select! {
                    result = reader.read(&mut buf) => match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    },
                    _ = close_rx.changed() => break,
                };

                let _ = window.emit(
                    "adb-data",
                    AdbDataPayload {
                        id: id.clone(),
                        data: buf[..n].to_vec(),
                    },
                );
            }

            // Emit adb-closed only when the connection was not already removed
            // by an explicit adb_close call.
            let was_active = connections.lock().await.remove(&id).is_some();
            if was_active {
                let _ = window.emit("adb-closed", AdbClosedPayload { id });
            }
        });

        Ok(())
    }

    /// Writes raw bytes to an existing ADB connection.
    pub async fn write(&self, id: &str, data: &[u8]) -> Result<bool, String> {
        use tokio::io::AsyncWriteExt;
        let mut conns = self.connections.lock().await;
        if let Some(state) = conns.get_mut(id) {
            Ok(state.writer.write_all(data).await.is_ok())
        } else {
            Ok(false)
        }
    }

    /// Restores one flow-control permit, allowing the read loop to emit the
    /// next chunk.  Called by JS after it has finished processing a chunk.
    pub async fn ack(&self, id: &str) {
        let conns = self.connections.lock().await;
        if let Some(state) = conns.get(id) {
            state.flow_semaphore.add_permits(1);
        }
    }

    /// Closes an ADB connection.
    ///
    /// Removes the connection from the map (dropping the write half, which
    /// sends FIN), closes the semaphore (unblocking any pending acquire), and
    /// drops the watch sender (signalling the read loop to exit).
    pub async fn close(&self, id: &str) {
        let state = self.connections.lock().await.remove(id);
        if let Some(state) = state {
            // Unblock any acquire() waiting for a permit.
            state.flow_semaphore.close();
            // Dropping `state` here:
            //   - `writer` drop → FIN sent to ADB server
            //   - `close_tx` drop → watch receiver wakes with RecvError
        }
    }
}

