use serde::Serialize;
use std::sync::Arc;
use tauri::{Emitter, WebviewWindow};

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
        use crate::adb::adb_connect_or_start;
        use tokio::io::AsyncReadExt;

        let connections = self.connections.clone();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(FLOW_WINDOW));
        let (close_tx, close_rx) = tokio::sync::watch::channel(false);
        let semaphore_clone = semaphore.clone();

        tauri::async_runtime::spawn(async move {
            match adb_connect_or_start().await {
                Ok(stream) => {
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

                    // Emit adb-closed only when the connection was not
                    // already removed by an explicit adb_close call.
                    let was_active = connections.lock().await.remove(&id).is_some();
                    if was_active {
                        let _ = window.emit("adb-closed", AdbClosedPayload { id });
                    }
                }
                Err(_) => {
                    let _ = window.emit(
                        "adb-connected",
                        AdbConnectedPayload {
                            id,
                            success: false,
                        },
                    );
                }
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
