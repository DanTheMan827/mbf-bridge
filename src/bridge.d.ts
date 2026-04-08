/**
 * MBF Tauri ADB Bridge – TypeScript declarations
 *
 * `window.__mbfBridge` is defined when the app is running inside the Tauri
 * WebView.  Use `window.__mbfBridge?.isAvailable` to detect the environment.
 * Flow-control note
 * -----------------
 * The Rust read loop holds a semaphore with FLOW_WINDOW (8) permits.  Before
 * emitting each `adb-data` event it acquires one permit (blocking when all 8
 * are in-flight).  The bridge calls `adb_ack` automatically after every
 * `onData` callback resolves, restoring one permit.  This means:
 *   - Sync callbacks apply back-pressure immediately after processing.
 *   - Async callbacks stall the Rust read loop until the returned Promise settles.
 * Callers do NOT need to manage acknowledgements manually.
 */

// ---------------------------------------------------------------------------
// Connection handle
// ---------------------------------------------------------------------------
 
/** Handle to an open ADB TCP connection proxied through the Tauri IPC bridge. */
export interface MbfAdbConnection {
  /** Unique connection identifier (UUID). */
  readonly id: string;

  /** `true` once the connection has been closed from either side. */
  readonly closed: boolean;

  /**
   * Write raw bytes to the ADB connection.
   * @param data Bytes to send (Uint8Array or ArrayBuffer).
   * @returns Promise that resolves to `true` on success, `false` if the
   *          connection ID is unknown on the Rust side.
   */
  write(data: Uint8Array | ArrayBuffer): Promise<boolean>;

  /**
   * Register a callback for incoming data chunks.
   *
   * The callback receives one chunk per call.  It may be async; the bridge
   * awaits completion before acknowledging the chunk to Rust, so a slow
   * callback naturally throttles the data stream (back-pressure).
   *
   * @returns Unsubscribe function – call it to stop receiving data.
   */
  onData(callback: (data: Uint8Array) => void | Promise<void>): () => void;

  /**
   * Register a callback for connection close.
   * Fires when:
   *  - `connection.close()` is called by JS, or
   *  - The ADB server closes the connection.
   *
   * @returns Unsubscribe function.
   */
  onClose(callback: () => void): () => void;

  /**
   * Close the connection.
   * Fires `onClose` listeners immediately, then sends the IPC close command.
   * Safe to call multiple times; subsequent calls are no-ops.
   */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Bridge singleton
// ---------------------------------------------------------------------------

/**
 * MBF Tauri bridge API.
 *
 * Defined on `window.__mbfBridge` only when the page is loaded inside the
 * Tauri WebView.  Absent when loading in a regular browser.
 */
export interface MbfBridge {
  /** Always `true` – presence of this property confirms Tauri context. */
  readonly isAvailable: true;

  /**
   * `true` on all platforms.  On Android this assumes a custom adbd instance
   * is reachable on the configured ADB port.
   */
  readonly isAdbAvailable: boolean;

  /**
   * Open a new ADB TCP connection via the Tauri IPC bridge.
   *
   * The implementation:
   * 1. Ensures the three Tauri event listeners (`adb-connected`, `adb-data`,
   *    `adb-closed`) are registered before sending the IPC call, preventing
   *    the race condition where a fast connection emits events before JS is
   *    ready to receive them.
   * 2. Resolves once Rust confirms the ADB server accepted the connection.
   *
   * @throws If ADB is not available (Android) or the connection fails.
   */
  connect(): Promise<MbfAdbConnection>;
}

// ---------------------------------------------------------------------------
// Global augmentation
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    /**
     * MBF Tauri bridge.  Present only when running inside the Tauri WebView.
     * Check `window.__mbfBridge?.isAvailable` before use.
     */
    __mbfBridge?: MbfBridge;

    /**
     * Set by Rust before `bridge.js` runs.
     * `true` on desktop, `false` on Android.
     * @internal
     */
    __mbfIsAdbAvailable?: boolean;
  }
}

export {};
