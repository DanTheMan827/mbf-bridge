# AGENTS.md — ModsBeforeFriday Bridge

This document is the authoritative reference for AI agents (and human contributors) working in
this repository.  Read it fully before making any change.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Architecture](#3-architecture)
4. [Build System](#4-build-system)
5. [Rust Codebase](#5-rust-codebase)
6. [Frontend (UI)](#6-frontend-ui)
7. [Tauri Integration](#7-tauri-integration)
8. [ADB Bridge](#8-adb-bridge)
9. [Platform-Specific Behaviour](#9-platform-specific-behaviour)
10. [CI & Validation Requirements](#10-ci--validation-requirements)
11. [Development Tips](#11-development-tips)

---

## 1. Project Overview

**ModsBeforeFriday Bridge** is a cross-platform desktop/Android application built with
[Tauri 2](https://tauri.app/) (Rust backend) and a React/Vite frontend.

Its sole purpose is to provide the [ModsBeforeFriday](https://github.com/DanTheMan827/ModsBeforeFriday)
web app with a local ADB (Android Debug Bridge) connection.  It opens a WebView that loads
the MBF web app and injects `window.__mbfBridge` — a JavaScript API that routes ADB host-protocol
connections through Tauri IPC to a local ADB server.

**Key constraints:**
- ADB must be available before the main app window opens.  If it is not, the user must be
  prompted to install it (via winget on Windows, or instructed to install manually elsewhere).
  The main window must not open until ADB is confirmed working.
- The embedded `adb` binaries (behind the `embed-adb` Cargo feature, enabled by default) allow
  the app to start ADB automatically without requiring a system installation.

---

## 2. Repository Layout

```
mbf-bridge/
├── src/                   Rust source
│   ├── main.rs            Entry point, Tauri setup, CLI, window creation
│   ├── adb_bridge.rs      AdbBridge Tauri state + ADB connection lifecycle
│   ├── adb/mod.rs         Low-level ADB connect/start helpers, embedded-binary extraction
│   ├── bridge.js          JS init-script injected into every WebView (window.__mbfBridge)
│   ├── config.rs          Compile-time constants (DEFAULT_URL, DEFAULT_GAME_ID)
│   ├── console.rs         Windows-only AllocConsole helper
│   ├── jump_list.rs       Windows taskbar jump-list management (COM/Shell APIs)
│   └── tauri_windows.rs   Window-creation helpers (shift, help, test, winget-progress)
├── ui/                    React/Vite frontend (TypeScript)
│   ├── src/
│   │   ├── App.tsx        React Router root (<Routes>)
│   │   ├── main.tsx       ReactDOM entry
│   │   ├── bridge.js      (same file as src/bridge.js — see §8)
│   │   ├── pages/         One component per internal page
│   │   │   ├── ShiftPage.tsx           Launch-options window
│   │   │   ├── HelpPage.tsx            --help window
│   │   │   ├── TestPage.tsx            ADB smoke-test harness
│   │   │   └── WingetProgressPage.tsx  winget install progress
│   │   ├── connector/
│   │   │   └── MbfAdbServerConnector.ts  AdbServerClient.ServerConnector impl
│   │   ├── hooks/         React hooks (useLog, useDeviceScanner)
│   │   ├── styles/        Global CSS + shared CSS modules
│   │   └── types/
│   │       └── global.d.ts  Window globals (__mbfBridge, __TAURI__, etc.)
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
├── adb/                   Embedded ADB binaries (win/, linux/, and macOS bundle)
├── capabilities/          Tauri capability JSON files (per-window IPC permissions)
│   ├── default.json       ADB bridge commands — all windows
│   ├── shift.json         launch_with_args — shift window
│   ├── help.json          get_help_text — help window
│   └── winget-progress.json  close_winget_progress_window + open_main_window
├── build.rs               Cargo build script (runs npm build, then tauri-build)
├── Cargo.toml
├── tauri.conf.json
├── permissions/           Auto-generated Tauri permission stubs (do not edit by hand)
└── AGENTS.md              This file
```

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Tauri app process (Rust)                                │
│                                                          │
│  main()  ──startup──►  ADB check (adb_connect_or_start) │
│                │                                         │
│                ▼ (ADB OK)          ▼ (ADB unavailable)  │
│          create_app_window    handle_adb_unavailable     │
│               (main)          (winget / manual dialog)  │
│                                                          │
│  AdbBridge (Tauri state)                                 │
│    .connect(id, window)  ──►  TcpStream to adb server   │
│    .write / .ack / .close                                │
│                                                          │
│  serve_embedded (mbf:// protocol)                        │
│    └── include_dir!(ui/dist)  →  serves SPA assets      │
└──────────────────────────────────────────────────────────┘
           ▲ Tauri IPC (invoke / emit)
           │
┌──────────────────────────────────────────────────────────┐
│  WebView (React SPA at mbf://localhost/)                 │
│                                                          │
│  window.__mbfBridge  (injected by bridge.js)             │
│    .connect()  ──invoke("adb_connect")──►  Rust          │
│    .write()    ──invoke("adb_write")──►   Rust          │
│    .ack()      ──invoke("adb_ack")──►     Rust          │
│    .close()    ──invoke("adb_close")──►   Rust          │
│                                                          │
│  window.__TAURI__  (Tauri 2 global, withGlobalTauri:true)│
└──────────────────────────────────────────────────────────┘
           │ forwards to
           ▼
     ADB server (127.0.0.1:5037 by default)
           │
     Android device (USB/TCP)
```

### ADB flow control

The Rust read loop holds a semaphore with `FLOW_WINDOW = 8` permits.  Before emitting each
`adb-data` event it acquires one permit (blocking when the window is exhausted).  The JS
bridge calls `adb_ack` after every `onData` callback settles, restoring one permit.  This
propagates back-pressure from the JS callback all the way to the ADB TCP socket.

### SPA routing

The Vite `dist/` directory is embedded at compile time via `include_dir!`.  The `mbf://`
custom protocol handler in `serve_embedded` serves files by path and falls back to
`index.html` for all unrecognised paths, enabling React Router client-side routing.

Internal pages and their routes:

| Route               | Window label      | Page component         |
|---------------------|-------------------|------------------------|
| `/test`             | `test`            | TestPage               |
| `/shift`            | `shift`           | ShiftPage              |
| `/help`             | `help`            | HelpPage               |
| `/winget-progress`  | `winget-progress` | WingetProgressPage     |

---

## 4. Build System

### Prerequisites

| Tool | Required for |
|------|-------------|
| Rust (stable) | All platforms |
| Node.js 22 + npm | UI build |
| Visual Studio Build Tools | Windows targets |
| Xcode Command Line Tools | macOS targets |
| `libglib2.0-dev`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` | Linux targets |
| Android NDK r27c | Android targets |

### How the build works

1. **`build.rs`** runs before the Rust compile:
   - Installs npm dependencies (`npm install`) if `ui/node_modules/` is absent.
   - Builds the Vite frontend (`npm run build`), producing `ui/dist/`.
   - Calls `tauri_build::build()`.
   - **On Windows** uses `npm.cmd`; on Unix uses `npm`.
   - Re-runs when any file under `ui/src/`, `ui/index.html`, `ui/package.json`,
     `ui/vite.config.ts`, or `ui/tsconfig.app.json` changes.

2. **`cargo build`** compiles the Rust binary, embedding the `ui/dist/` directory via
   `include_dir!`.

### Cargo features

| Feature | Default | Effect |
|---------|---------|--------|
| `embed-adb` | ✅ yes | Includes ADB binaries for Windows, Linux, and macOS; auto-extracts and starts them when no system ADB is found. |
| *(none)* | — | Build without `--features embed-adb` / with `--no-default-features` to produce a binary that requires the user to have ADB in `PATH`. |

### Build commands

```sh
# Standard release build (embed-adb enabled, terser minification, no source maps)
cargo build --release

# Debug build (no minification, full source maps embedded in dist/)
cargo build

# Release build without embedded ADB
cargo build --release --no-default-features

# Cross-compile for a specific target (e.g. on macOS for Intel)
cargo build --release --target x86_64-apple-darwin

# Frontend only — release (terser, no source maps)
cd ui && npm install && npm run build

# Frontend only — debug (no minification, full source maps)
cd ui && npm run build:debug
```

---

## 5. Rust Codebase

### `src/main.rs`

- Defines and parses CLI arguments with `clap` (`--url`, `--dev`, `--adb-port`,
  `--game-id`, `--ignore-package-id`, `--console`, `--test`, `--help`).
- Detects the "launch options" modifier key at startup (Shift on Windows/Linux, Option ⌥ on
  macOS) and opens the shift window if held.
- **Startup ADB gate**: before creating the main app window, the app verifies ADB is
  reachable.  If not, `handle_adb_unavailable` is called.  The main window must **never**
  open unless ADB is confirmed working.
- Stores `PendingMainWindow` in Tauri app state so the `open_main_window` command (called by
  the winget-progress page after a successful install) can create the main window.
- Serves the embedded SPA via the `mbf://` custom protocol (`serve_embedded`).
- Registers the Windows taskbar jump list (`jump_list::prepend_task`) whenever `--url`,
  `--dev`, or `--game-id` differ from their defaults.

#### Tauri commands (desktop only)

| Command | Callable from | Description |
|---------|--------------|-------------|
| `adb_connect` | all windows | Open a new ADB connection |
| `adb_write` | all windows | Write bytes to an ADB connection |
| `adb_ack` | all windows | Release one flow-control permit |
| `adb_close` | all windows | Close an ADB connection |
| `get_help_text` | help window | Return clap help text |
| `launch_with_args` | shift window | Re-launch the process with new arguments |
| `close_winget_progress_window` | winget-progress window | Destroy the progress window and exit the app (used on install failure) |
| `open_main_window` | winget-progress window | Destroy the progress window and open the main app window (used on install success) |

### `src/adb_bridge.rs`

- Defines `AdbBridge` (Tauri-managed state), `ConnectionState`, and event payload types
  (`AdbConnectedPayload`, `AdbDataPayload`, `AdbClosedPayload`).
- `AdbBridge::connect` spawns a Tokio task that calls `adb::adb_connect_or_start()` and
  manages the full read/write lifecycle.
- `is_winget_available()` (Windows only) — probes for `winget --version`.
- `handle_adb_unavailable(app)` — called at startup when ADB is not available:
  - **Windows + winget present**: offers "Install via winget?" dialog; if accepted, opens the
    `winget-progress` window, runs `winget install --id Google.PlatformTools`, streams
    stdout/stderr as `winget-output` events, and emits `winget-done` when complete.
  - **User declined winget, or winget absent, or non-Windows**: shows a "please install
    manually" error dialog, then calls `app.exit(1)`.

### `src/adb/mod.rs`

| Function | Description |
|----------|-------------|
| `adb_connect()` | Single TCP connect attempt to `127.0.0.1:<ADB_PORT>` |
| `adb_connect_retry()` | Retries connect up to 10 times with 50 ms delays |
| `adb_start(path)` | Spawns `<path> server nodaemon -P <port>` |
| `adb_connect_or_start()` | Try connect → try system `adb` → extract embedded binary (if feature enabled) → `Err("no-embedded-adb")` |
| `embedded_adb_available()` | Returns `true` when the `embed-adb` feature is enabled and the platform has a binary |
| `extract_adb_binaries_windows()` | Extracts `adb.exe`, `AdbWinApi.dll`, `AdbWinUsbApi.dll` to a temp UUID dir |
| `extract_adb_binaries_linux()` | Extracts `adb` binary to a temp UUID dir with `755` permissions |

`ADB_PORT` is a `OnceLock<u16>` initialised from `--adb-port` (default 5037).

### `src/tauri_windows.rs`

Provides `create_internal_window` / `create_internal_window_from_handle` (generic over
`tauri::Manager<Wry>`) and convenience wrappers:

| Function | Window label | URL |
|----------|-------------|-----|
| `create_shift_window` | `shift` | `mbf://localhost/shift` |
| `create_help_window` | `help` | `mbf://localhost/help` |
| `create_test_window` | `test` | `mbf://localhost/test` |
| `create_winget_progress_window` | `winget-progress` | `mbf://localhost/winget-progress` |

The winget-progress window is created with `closable(false)` — the OS close button is
disabled; the window must be closed programmatically via the `close_winget_progress_window`
or `open_main_window` commands.

### `src/jump_list.rs` (Windows only)

Persists a list of recent launch-argument combinations to
`%LOCALAPPDATA%\DanTheMan827\mbf-bridge\jump_tasks.json` and syncs them to the Windows
taskbar jump list via COM/Shell APIs (`ICustomDestinationList`, `IShellLinkW`).

### `src/bridge.js`

Vanilla-JS init script injected into every WebView before page load.  Reads
`window.__mbfIsAdbAvailable` (set by Rust) and exposes `window.__mbfBridge` with:

- `isAvailable: true`
- `isAdbAvailable: boolean`
- `connect() → Promise<AdbConnection>` — wraps the `adb_connect` / `adb-connected` IPC pair

Flow: `connect()` → `ensureListeners()` (registers `adb-connected`, `adb-data`,
`adb-closed` listeners once) → `invoke("adb_connect", { id })` → waits for `adb-connected`
event → resolves/rejects.

---

## 6. Frontend (UI)

**Stack**: React 18, TypeScript, Vite 8 (Rolldown bundler), React Router 6, xterm.js (`@xterm/xterm`),
`@yume-chan/adb`.

**Output**: `ui/dist/` — static files embedded into the Rust binary at compile time.

**Build modes** (selected by `--mode` flag, driven automatically from `build.rs` via the
`PROFILE` env var):

| Mode | npm script | Minifier | Source maps |
|------|-----------|----------|-------------|
| production (default / `cargo build --release`) | `build` | terser, 2 passes | none |
| debug (`cargo build`) | `build:debug` | none | full (`.map` files) |

**Terser release options**: `passes: 2`, `drop_console`, `drop_debugger`, `ecma: 2020`,
`module: true`, `unsafe_arrows`, `unsafe_methods`, `toplevel`, all comments stripped,
top-level name mangling.  Module preload polyfill is omitted (`modulePreload.polyfill: false`).
Rolldown tree-shaking uses `moduleSideEffects: 'no-external'`.

### Pages

| Page | Route | Purpose |
|------|-------|---------|
| `TestPage` | `/test` | Full ADB smoke-test harness with device scanner and protocol explorer |
| `ShiftPage` | `/shift` | Launch-options window; shows modifier-key hint, custom args textarea, and a Launch button that calls `launch_with_args` |
| `HelpPage` | `/help` | Displays the clap help text (from `get_help_text` command) |
| `WingetProgressPage` | `/winget-progress` | xterm.js terminal streaming winget output; shows "Continue" (calls `open_main_window`) on success or "Close" (calls `close_winget_progress_window`) on failure |

### `connector/MbfAdbServerConnector.ts`

Implements `AdbServerClient.ServerConnector` from `@yume-chan/adb`, bridging the
`window.__mbfBridge.connect()` API to the yume-chan ADB stack used by `TestPage`.

### Global types (`types/global.d.ts`)

Declares `window.__mbfBridge` (`MbfBridge`), `window.__mbfModifierKey` (string),
`window.__TAURI__` (`TauriApi`), and `AdbConnection`.

---

## 7. Tauri Integration

### `tauri.conf.json`

- `withGlobalTauri: true` — exposes `window.__TAURI__` with `core.invoke` and
  `event.listen`/`event.unlisten`.
- No pre-declared windows (`"windows": []`) — all windows are created dynamically from Rust.
- CSP is `null` (unrestricted) for the embedded SPA.

### Capabilities

Each capability file scopes IPC permissions to specific window labels and/or origins:

| File | Windows | Key permissions |
|------|---------|-----------------|
| `default.json` | `*` (all) | ADB bridge commands (`adb_connect`, `adb_write`, `adb_ack`, `adb_close`) |
| `shift.json` | `*` at `mbf://localhost/shift` | `launch_with_args` |
| `help.json` | `*` at `mbf://*` | `get_help_text` |
| `winget-progress.json` | `winget-progress` | `close_winget_progress_window`, `open_main_window` |

When adding a new Tauri command, you must:
1. Annotate the Rust function with `#[tauri::command]`.
2. Register it in `tauri::generate_handler![]` in `main.rs`.
3. Add the corresponding `allow-<command-name>` permission to the relevant capability file.
   (Permissions are auto-generated by `tauri-build` from the function name.)

---

## 8. ADB Bridge

### Connection lifecycle (Rust side)

```
JS: __mbfBridge.connect()
  → invoke("adb_connect", { id })
  → AdbBridge::connect(id, window)
      → adb_connect_or_start()  [try connect → try start → extract embedded]
      → insert ConnectionState into HashMap
      → emit "adb-connected" { id, success: true }
      → read loop:
          acquire semaphore permit (blocks at FLOW_WINDOW=8)
          read chunk → emit "adb-data" { id, data }
          ← JS calls adb_ack → semaphore.add_permits(1)
      → on EOF/close: emit "adb-closed" { id }
```

### Events emitted by Rust

| Event | Payload | Description |
|-------|---------|-------------|
| `adb-connected` | `{ id, success }` | Connection attempt result |
| `adb-data` | `{ id, data: number[] }` | Raw bytes from the device |
| `adb-closed` | `{ id }` | Connection was closed from the device/server side |
| `winget-output` | `{ data: number[] }` | Raw stdout/stderr bytes from the winget process |
| `winget-done` | `{ success: bool }` | winget install finished |

---

## 9. Platform-Specific Behaviour

### Windows

- App User Model ID is set to `com.DanTheMan827.mbf-bridge` for taskbar grouping.
- `--console` flag (hidden in release builds) allocates a console via `AllocConsole`.
- Modifier key for shift window: **Shift** (detected via `GetAsyncKeyState(VK_SHIFT)`).
- Embedded ADB: `adb.exe`, `AdbWinApi.dll`, `AdbWinUsbApi.dll` extracted to `%TEMP%\<uuid>\`.
- Winget install: `winget install --id Google.PlatformTools --accept-package-agreements ...`
  runs with `CREATE_NO_WINDOW`.
- All `std::process::Command` calls that shouldn't show a console must set
  `.creation_flags(0x08000000)`.
- Jump list stored in `%LOCALAPPDATA%\DanTheMan827\mbf-bridge\jump_tasks.json`.

### macOS

- Runs as an "accessory" app (`ActivationPolicy::Accessory`) — no Dock icon.
- Modifier key for shift window: **Option ⌥** (detected via `CGEventSourceFlagsState`).
- Embedded ADB: bundled `adb` binary placed next to the app executable; not used if the
  macOS App Sandbox is active (`APP_SANDBOX_CONTAINER_ID` env var present).
- Universal binary produced by CI via `lipo` from separate Intel + ARM builds.

### Linux

- Modifier key for shift window: **Shift** (detected via X11 `XQueryKeymap`).
- Embedded ADB: extracted to `$TMPDIR/<uuid>/adb`, permissions set to `0o755`.
- Build requires: `libglib2.0-dev`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`,
  `libayatana-appindicator3-dev`, `librsvg2-dev`.

### Android

- ADB bridge commands are available on Android (custom `adbd` on-device).
- `embed-adb` feature is irrelevant; `adb_connect_or_start` connects to the local adbd.
- Desktop-only code is gated with `#[cfg(not(target_os = "android"))]` or `#[cfg(desktop)]`.
- The winget / modifier-key / jump-list / file-download code paths are all excluded.
- OpenSSL is vendored (`openssl = { features = ["vendored"] }`).

---

## 10. CI & Validation Requirements

These requirements are **mandatory**.  Any change that breaks them must be fixed before
the work is considered complete.

### Platforms

The CI matrix builds for all 7 targets.  Every change must not introduce compile errors on
**any** of them:

| Runner | Target triple | Artifact |
|--------|--------------|----------|
| `windows-latest` | `i686-pc-windows-msvc` | Windows x86 |
| `windows-latest` | `x86_64-pc-windows-msvc` | Windows x64 |
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | Linux x64 |
| `ubuntu-latest` | `aarch64-linux-android` | Android arm64 |
| `ubuntu-latest` | `x86_64-linux-android` | Android x86_64 |
| `macos-latest` | `x86_64-apple-darwin` | macOS Intel |
| `macos-latest` | `aarch64-apple-darwin` | macOS ARM |

### Mandatory pre-commit checks

Before committing any Rust change, verify that `cargo check` passes for every CI target.
You can't cross-compile natively in the sandbox, but you can check the current host target
and rely on careful use of `cfg` guards.  Pay particular attention to:

- `#[cfg(windows)]` — code only compiled on Windows targets.
- `#[cfg(not(target_os = "android"))]` — excluded from Android.
- `#[cfg(desktop)]` — Tauri alias for non-Android desktop.
- `#[cfg(all(feature = "embed-adb", ...))]` — conditional on the feature flag.
- Imports from `tauri::Manager` must be in scope wherever `.app_handle()`,
  `.get_webview_window()`, or `.webview_windows()` are called.

Before committing any frontend change, verify the UI build passes:

```sh
cd ui && npm run build
```

This compiles TypeScript (`tsc -b`) and runs the Vite build.  Errors here break the Rust
build because `build.rs` invokes it.

### Common cross-platform pitfalls

- `tauri::Manager` trait must be **imported** (`use tauri::Manager;`) before calling
  `.app_handle()`, `.get_webview_window()`, etc. — the trait is not in the Tauri prelude.
- A bare `None` (or any non-`()` expression) as the last expression inside an `if` block
  **without an `else` arm** is a type error — use `return None;` instead.
- `win.destroy()` returns `Result<(), _>`; assigning it to `let _ = ...` requires the
  compiler to infer the error type.  Use `let _ = win.destroy().ok();` to avoid E0282.
- Windows-only `std::process::Command` extensions (`.creation_flags()`) require
  `use std::os::windows::process::CommandExt;` inside the `#[cfg(windows)]` block.
- On Windows, the npm wrapper is `npm.cmd`; on Unix it is `npm` — see `build.rs:7–9`.

### Adding a new Tauri command

1. Write the `#[tauri::command]` function in `src/main.rs` (or the relevant module).
2. Add it to `tauri::generate_handler![]`.
3. Add `"allow-<kebab-case-name>"` to the appropriate capability file under `capabilities/`.
4. If needed, add it to `capabilities/*.json` for the window(s) that need access.
5. Update this document's command table in §7.

---

## 11. Development Tips

### Local iteration

```sh
# Check compilation without a full build (fast)
cargo check --no-default-features

# Run in debug mode (console always visible, devtools enabled)
cargo run

# Rebuild only the frontend
cd ui && npm run build

# Watch frontend for changes (does not hot-reload the Tauri window)
cd ui && npm run dev
```

### Adding a new internal page

1. Create `ui/src/pages/MyPage.tsx` (and optional `.module.css`).
2. Add a `<Route path="/my-page" element={<MyPage />} />` in `App.tsx`.
3. Add the URL constant to `tauri_windows::internal_pages`.
4. Add a `create_my_window` helper in `tauri_windows.rs`.
5. If the page needs specific commands, create a capability file in `capabilities/`.
6. Call the helper from the appropriate place in `main.rs`.

### Cargo feature interaction

- `--no-default-features` disables `embed-adb`.  In this mode:
  - `embedded_adb_available()` returns `false`.
  - `adb_connect_or_start()` returns `Err("no-embedded-adb")` when no system ADB is found.
  - The winget install flow (Windows) or manual-install dialog (all platforms) is triggered.
- Default builds always have `embed-adb` enabled.  CI tests both configurations for
  non-macOS targets.

### Event naming convention

All Tauri events emitted by Rust use kebab-case: `adb-connected`, `adb-data`, `adb-closed`,
`winget-output`, `winget-done`.  JavaScript listeners use the same strings verbatim.

### Window labels

Window labels are stable identifiers used in capabilities and `get_webview_window()`.
Current labels: `main`, `shift`, `help`, `test`, `winget-progress`.  Do not change them
without updating every reference.
