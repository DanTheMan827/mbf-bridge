// MBF Tauri ADB Bridge – initialization script
// Injected into every WebView window before page content loads.
// Requires Tauri 2 with `withGlobalTauri: true`.
//
// Exposes `window.__mbfBridge` with the following API:
//   isAdbAvailable: boolean
//   connect(): Promise<MbfAdbConnection>
//
// `window.__mbfIsAdbAvailable` is injected by Rust at startup:
//   true  → desktop (Windows / macOS / Linux)
//   false → Android (ADB commands are unavailable on-device)

(function () {
  "use strict";

  if (window.__mbfBridge) return; // Guard against double-injection.

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Generate a random connection identifier.
   * Uses crypto.randomUUID when available (modern browsers / Tauri WebView).
   */
  function generateId() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return (
      Math.random().toString(36).slice(2) +
      Date.now().toString(36) +
      Math.random().toString(36).slice(2)
    );
  }

  // -------------------------------------------------------------------------
  // Runtime check
  // -------------------------------------------------------------------------

  var tauri = window.__TAURI__;
  if (!tauri) {
    // Not running inside a Tauri WebView – leave __mbfBridge undefined so
    // callers can detect the absence and fall back gracefully.
    return;
  }

  var invoke = tauri.core.invoke;
  var listen = tauri.event.listen;

  // -------------------------------------------------------------------------
  // Shared listener state
  // -------------------------------------------------------------------------

  /**
   * Map<id, { dataListeners: Set<fn>, closeListeners: Set<fn>, pendingConnect: {resolve,reject} | null }>
   */
  var connections = new Map();

  /**
   * Promise that resolves once all three Tauri event listeners are registered.
   * Ensures no events are missed before a connect() call can proceed.
   */
  var listenersReadyPromise = null;

  function ensureListeners() {
    if (listenersReadyPromise) return listenersReadyPromise;

    listenersReadyPromise = Promise.all([
      listen("adb-connected", function (event) {
        var payload = event.payload;
        var conn = connections.get(payload.id);
        if (!conn || !conn.pendingConnect) return;

        var pending = conn.pendingConnect;
        conn.pendingConnect = null;

        if (payload.success) {
          pending.resolve(createConnectionObject(payload.id, conn));
        } else {
          connections.delete(payload.id);
          pending.reject(new Error("ADB connection failed"));
        }
      }),

      listen("adb-data", function (event) {
        var payload = event.payload;
        var conn = connections.get(payload.id);
        if (!conn) return;

        var bytes = new Uint8Array(payload.data);
        var listeners = Array.from(conn.dataListeners);
        var idx = 0;

        // Invoke listeners sequentially, wait for async ones, then ack.
        function next() {
          if (idx >= listeners.length) {
            // All listeners processed – release one flow-control permit.
            invoke("adb_ack", { id: payload.id }).catch(function () {});
            return;
          }
          var result = listeners[idx++](bytes);
          if (result && typeof result.then === "function") {
            result.then(next, next);
          } else {
            next();
          }
        }
        next();
      }),

      listen("adb-closed", function (event) {
        var payload = event.payload;
        var conn = connections.get(payload.id);
        if (!conn) return;

        connections.delete(payload.id);
        conn.closeListeners.forEach(function (cb) {
          try { cb(); } catch (_) {}
        });
      }),
    ]);

    return listenersReadyPromise;
  }

  // -------------------------------------------------------------------------
  // Connection object factory
  // -------------------------------------------------------------------------

  function createConnectionObject(id, conn) {
    return {
      get id() { return id; },

      /** True once the connection has been closed (either side). */
      get closed() { return !connections.has(id); },

      /**
       * Write bytes to the ADB connection.
       * Accepts Uint8Array or ArrayBuffer.
       * @returns {Promise<boolean>} resolves to true on success
       */
      write: function (data) {
        if (!connections.has(id)) {
          return Promise.reject(new Error("Connection is closed"));
        }
        var arr;
        if (data instanceof Uint8Array) {
          arr = Array.from(data);
        } else if (data instanceof ArrayBuffer) {
          arr = Array.from(new Uint8Array(data));
        } else {
          return Promise.reject(new TypeError("data must be Uint8Array or ArrayBuffer"));
        }
        return invoke("adb_write", { id: id, data: arr });
      },

      /**
       * Register a callback for incoming data chunks.
       * The callback may return a Promise; the bridge waits for it to settle
       * before acknowledging the chunk to Rust (back-pressure enforcement).
       * @param {function(Uint8Array): void|Promise<void>} callback
       * @returns {function} unsubscribe function
       */
      onData: function (callback) {
        conn.dataListeners.add(callback);
        return function () { conn.dataListeners.delete(callback); };
      },

      /**
       * Register a callback for connection close (either side).
       * @param {function(): void} callback
       * @returns {function} unsubscribe function
       */
      onClose: function (callback) {
        conn.closeListeners.add(callback);
        return function () { conn.closeListeners.delete(callback); };
      },

      /**
       * Close the connection.  Fires onClose listeners synchronously before
       * the IPC call so callers see `closed === true` immediately.
       * @returns {Promise<void>}
       */
      close: function () {
        if (!connections.has(id)) return Promise.resolve();

        connections.delete(id);
        conn.closeListeners.forEach(function (cb) {
          try { cb(); } catch (_) {}
        });
        return invoke("adb_close", { id: id }).catch(function () {});
      },
    };
  }

  // -------------------------------------------------------------------------
  // Public bridge API
  // -------------------------------------------------------------------------

  Object.defineProperty(window, "__mbfBridge", {
    value: {
      /**
       * True when running inside the Tauri WebView.
       * Always true once this script is loaded (non-Tauri contexts return
       * early above and never set this property).
       */
      isAvailable: true,

      /**
       * True when ADB is accessible.  Always true — on Android this relies on
       * a custom adbd instance being reachable on the configured port.
       */
      isAdbAvailable: window.__mbfIsAdbAvailable === true,

      /**
       * Open a new ADB TCP connection to the locally running ADB server.
       *
       * Waits for all Tauri event listeners to be registered before sending
       * the connect IPC call, eliminating the adb-connected race condition.
       *
       * @returns {Promise<MbfAdbConnection>}
       */
      connect: function () {
        return ensureListeners().then(function () {
          return new Promise(function (resolve, reject) {
            var id = generateId();

            connections.set(id, {
              dataListeners: new Set(),
              closeListeners: new Set(),
              pendingConnect: { resolve: resolve, reject: reject },
            });

            invoke("adb_connect", { id: id }).catch(function (err) {
              var conn = connections.get(id);
              if (conn && conn.pendingConnect) {
                connections.delete(id);
                reject(err instanceof Error ? err : new Error(String(err)));
              }
            });
          });
        });
      },
    },
    writable: false,
    configurable: false,
    enumerable: true,
  });
})();
