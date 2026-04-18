// Type declarations for window globals injected by Rust/Tauri.

export {};

/** A single active ADB TCP connection exposed by the bridge. */
export interface AdbConnection {
  readonly id: string;
  readonly closed: boolean;
  write(data: Uint8Array | ArrayBuffer): Promise<boolean>;
  onData(cb: (data: Uint8Array) => void | Promise<void>): () => void;
  onClose(cb: () => void): () => void;
  close(): Promise<void>;
}

/** The public API surface of `window.__mbfBridge`. */
export interface MbfBridge {
  readonly isAvailable: true;
  readonly isAdbAvailable: boolean;
  connect(): Promise<AdbConnection>;
}

/** Tauri 2 global API (present when `withGlobalTauri: true`). */
export interface TauriApi {
  core: {
    invoke<T = unknown>(
      cmd: string,
      args?: Record<string, unknown>,
    ): Promise<T>;
  };
  event: {
    listen<T = unknown>(
      event: string,
      handler: (event: { payload: T }) => void,
    ): Promise<() => void>;
  };
}

declare global {
  interface Window {
    /** Injected by `bridge.js` once Tauri is available. */
    __mbfBridge?: MbfBridge;
    /**
     * Platform-specific modifier-key label for the launch-options window.
     * Injected via Tauri `initialization_script` before the page loads.
     * e.g. `"Shift"` (Windows/Linux) or `"Option (\u2325)"` (macOS).
     */
    __mbfModifierKey?: string;
    /** Tauri 2 global API surface (`withGlobalTauri: true`). */
    __TAURI__?: TauriApi;
  }
}
