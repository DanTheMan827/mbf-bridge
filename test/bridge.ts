/**
 * MBF Bridge TypeScript source
 *
 * This file documents the shape of `window.__mbfBridge` as TypeScript.
 * The equivalent JavaScript (without types) is injected into every Tauri
 * WebView window via an initialization script.
 *
 * To use this in a TypeScript project, either:
 *  1. Copy `src/bridge.d.ts` into your project (provides global augmentation).
 *  2. Import the types from this file if you bundle it.
 *
 * Flow-control note
 * -----------------
 * The Rust side maintains a semaphore of FLOW_WINDOW = 8 permits.
 * The bridge automatically calls `adb_ack` via Tauri `invoke` after each
 * `onData` callback resolves, restoring one permit.  This means:
 *  - Synchronous callbacks apply back-pressure immediately.
 *  - Async callbacks (returning a Promise) stall the Rust read loop until
 *    the Promise settles, propagating back-pressure all the way to the ADB
 *    TCP socket.
 *
 * Callers do NOT need to acknowledge chunks manually.
 */

// Re-export the type declarations so consumers can import them.
export type { MbfBridge, MbfAdbConnection } from "../src/bridge.d";

// ---------------------------------------------------------------------------
// Typed Tauri IPC helpers (type-only, not shipped at runtime)
// ---------------------------------------------------------------------------

interface TauriCore {
  invoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T>;
}

interface TauriEvent {
  listen<T = unknown>(
    event: string,
    handler: (event: { payload: T }) => void
  ): Promise<() => void>;
}

declare const window: Window & {
  __TAURI__?: { core: TauriCore; event: TauriEvent };
  __mbfIsAdbAvailable?: boolean;
  __mbfBridge?: import("../src/bridge.d").MbfBridge;
};

// ---------------------------------------------------------------------------
// Bridge implementation (TypeScript version of src/bridge.js)
// ---------------------------------------------------------------------------

(function () {
  "use strict";

  if (window.__mbfBridge) return;

  // -------------------------------------------------------------------------
  // Runtime check – bail out if not inside Tauri
  // -------------------------------------------------------------------------
  const tauri = window.__TAURI__;
  if (!tauri) return;

  const { invoke } = tauri.core;
  const { listen }  = tauri.event;

  // -------------------------------------------------------------------------
  // Types
  // -------------------------------------------------------------------------

  interface ConnState {
    dataListeners:  Set<(data: Uint8Array) => void | Promise<void>>;
    closeListeners: Set<() => void>;
    pendingConnect: { resolve: (conn: MbfAdbConnectionImpl) => void; reject: (err: Error) => void } | null;
  }

  interface AdbConnectedPayload  { id: string; success: boolean; }
  interface AdbDataPayload       { id: string; data: number[]; }
  interface AdbClosedPayload     { id: string; }

  // -------------------------------------------------------------------------
  // Connection map and lazy listener setup
  // -------------------------------------------------------------------------

  const connections = new Map<string, ConnState>();
  let listenersReadyPromise: Promise<void[]> | null = null;

  function ensureListeners(): Promise<void[]> {
    if (listenersReadyPromise) return listenersReadyPromise;

    listenersReadyPromise = Promise.all([
      // adb-connected --------------------------------------------------------
      listen<AdbConnectedPayload>("adb-connected", (event) => {
        const { id, success } = event.payload;
        const conn = connections.get(id);
        if (!conn?.pendingConnect) return;
        const pending = conn.pendingConnect;
        conn.pendingConnect = null;
        if (success) {
          pending.resolve(createConnectionObject(id, conn));
        } else {
          connections.delete(id);
          pending.reject(new Error("ADB connection failed"));
        }
      }),

      // adb-data -------------------------------------------------------------
      listen<AdbDataPayload>("adb-data", (event) => {
        const { id, data } = event.payload;
        const conn = connections.get(id);
        if (!conn) return;

        const bytes = new Uint8Array(data);
        const listeners = [...conn.dataListeners];
        let idx = 0;

        // Invoke listeners sequentially; wait for async ones; then ack.
        function next(): void {
          if (idx >= listeners.length) {
            invoke("adb_ack", { id }).catch(() => {});
            return;
          }
          const result = listeners[idx++](bytes);
          if (result instanceof Promise) {
            result.then(next, next);
          } else {
            next();
          }
        }
        next();
      }),

      // adb-closed -----------------------------------------------------------
      listen<AdbClosedPayload>("adb-closed", (event) => {
        const { id } = event.payload;
        const conn = connections.get(id);
        if (!conn) return;
        connections.delete(id);
        conn.closeListeners.forEach((cb) => { try { cb(); } catch (_) {} });
      }),
    ]) as Promise<void[]>;

    return listenersReadyPromise;
  }

  // -------------------------------------------------------------------------
  // Connection object
  // -------------------------------------------------------------------------

  interface MbfAdbConnectionImpl {
    readonly id: string;
    readonly closed: boolean;
    write(data: Uint8Array | ArrayBuffer): Promise<boolean>;
    onData(callback: (data: Uint8Array) => void | Promise<void>): () => void;
    onClose(callback: () => void): () => void;
    close(): Promise<void>;
  }

  function createConnectionObject(id: string, conn: ConnState): MbfAdbConnectionImpl {
    return {
      get id() { return id; },
      get closed() { return !connections.has(id); },

      write(data: Uint8Array | ArrayBuffer): Promise<boolean> {
        if (!connections.has(id)) {
          return Promise.reject(new Error("Connection is closed"));
        }
        let arr: number[];
        if (data instanceof Uint8Array) {
          arr = Array.from(data);
        } else if (data instanceof ArrayBuffer) {
          arr = Array.from(new Uint8Array(data));
        } else {
          return Promise.reject(new TypeError("data must be Uint8Array or ArrayBuffer"));
        }
        return invoke<boolean>("adb_write", { id, data: arr });
      },

      onData(callback: (data: Uint8Array) => void | Promise<void>): () => void {
        conn.dataListeners.add(callback);
        return () => conn.dataListeners.delete(callback);
      },

      onClose(callback: () => void): () => void {
        conn.closeListeners.add(callback);
        return () => conn.closeListeners.delete(callback);
      },

      close(): Promise<void> {
        if (!connections.has(id)) return Promise.resolve();
        connections.delete(id);
        conn.closeListeners.forEach((cb) => { try { cb(); } catch (_) {} });
        return invoke<void>("adb_close", { id }).catch(() => {});
      },
    };
  }

  // -------------------------------------------------------------------------
  // Generate a connection ID
  // -------------------------------------------------------------------------

  function generateId(): string {
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
  // Bridge singleton
  // -------------------------------------------------------------------------

  Object.defineProperty(window, "__mbfBridge", {
    value: {
      isAvailable:    true as const,
    isAdbAvailable: true as const,

      connect(): Promise<MbfAdbConnectionImpl> {
        return ensureListeners().then(() =>
          new Promise<MbfAdbConnectionImpl>((resolve, reject) => {
            const id = generateId();
            connections.set(id, {
              dataListeners:  new Set(),
              closeListeners: new Set(),
              pendingConnect: { resolve, reject },
            });
            invoke<void>("adb_connect", { id }).catch((err: unknown) => {
              const conn = connections.get(id);
              if (conn?.pendingConnect) {
                connections.delete(id);
                reject(err instanceof Error ? err : new Error(String(err)));
              }
            });
          })
        );
      },
    },
    writable: false,
    configurable: false,
    enumerable: true,
  });
})();
