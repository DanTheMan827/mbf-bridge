#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! # ModsBeforeFriday Bridge (Tauri 2)
//!
//! Opens a WebView window that loads the MBF web app and injects a JavaScript
//! bridge (`window.__mbfBridge`) for communicating with the ADB server via
//! Tauri IPC rather than a network socket.
//!
//! ## ADB bridge flow control
//! The Rust read loop holds a semaphore of `FLOW_WINDOW` (8) permits.  Before
//! each `adb-data` emission it acquires a permit; JS releases it via
//! `adb_ack` after the `onData` callback settles, providing end-to-end
//! back-pressure from the device all the way to the JS callback.
//!
//! ## Launch-options window
//! If the modifier key (Shift on Windows/Linux, Option ⌥ on macOS) is held
//! when the application starts, a compact "launch options" window opens
//! instead of the main MBF window.  The user can review the available
//! command-line arguments, enter custom ones, and re-launch with those
//! arguments.  Arguments are persisted in `localStorage` so they are recalled
//! the next time the window opens.

mod adb;
mod adb_bridge;
mod config;
mod console;

use adb_bridge::AdbBridge;
use clap::{CommandFactory, Parser};
use config::{DEFAULT_GAME_ID, DEFAULT_URL};
use lazy_static::lazy_static;
use urlencoding::encode as url_encode;

#[cfg(not(target_os = "android"))]
use single_instance::SingleInstance;

#[cfg(not(target_os = "android"))]
use rfd::FileDialog;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, disable_help_flag = true)]
struct Args {
    /// Specify a custom URL for the MBF app
    #[arg(long, default_value_t = DEFAULT_URL.to_owned())]
    url: String,

    /// Allocate a console window to display logs (Windows only)
    #[arg(long, default_value_t = false, hide = cfg!(not(windows)) || cfg!(debug_assertions))]
    console: bool,

    /// Open the built-in test page instead of the MBF app
    #[arg(long, default_value_t = false, help_heading = "Development Options")]
    test: bool,

    /// The port that the ADB server is running on
    #[arg(long, default_value_t = 5037)]
    adb_port: u16,

    /// Enable MBF development mode
    #[arg(long = "dev", default_value_t = false, help_heading = "Development Options")]
    dev_mode: bool,

    /// Specify a custom game ID for the MBF app
    #[arg(long, default_value_t = DEFAULT_GAME_ID.to_owned(), help_heading = "Development Options")]
    game_id: String,

    /// Ignore the package ID check during qmod installation
    #[arg(long, default_value_t = false, help_heading = "Development Options")]
    ignore_package_id: bool,

    /// Print help
    #[arg(long, short)]
    help: bool,
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
}

// ---------------------------------------------------------------------------
// Single-instance guard (desktop only)
// ---------------------------------------------------------------------------

/// Holds the `SingleInstance` guard for the lifetime of the application so
/// that the named mutex / lock-file is not released prematurely.
///
/// The inner `Option` lets `launch_with_args` explicitly release the guard
/// before spawning the new process, eliminating the race window where both
/// instances briefly hold the same lock.
#[cfg(not(target_os = "android"))]
struct SingleInstanceState(std::sync::Mutex<Option<SingleInstance>>);

// ---------------------------------------------------------------------------
// Modifier-key detection (desktop only)
// ---------------------------------------------------------------------------

/// Returns `true` when the "launch options" modifier key is held at startup.
///
/// Platform conventions:
/// - **macOS** – Option (⌥)
/// - **Windows / Linux** – Shift
#[cfg(not(target_os = "android"))]
fn is_launch_modifier_held() -> bool {
    #[cfg(windows)]
    {
        use winapi::um::winuser::GetAsyncKeyState;
        // VK_SHIFT = 0x10; high bit set → key is down.
        return unsafe { (GetAsyncKeyState(0x10) as u16 & 0x8000) != 0 };
    }

    #[cfg(target_os = "macos")]
    {
        // CGEventSourceFlagsState returns the current modifier-key flags.
        // kCGEventSourceStateCombinedSessionState = 1
        // kCGEventFlagMaskAlternate (Option / ⌥) = 0x00080000
        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGEventSourceFlagsState(stateID: i32) -> u64;
        }
        const K_CG_EVENT_FLAG_MASK_ALTERNATE: u64 = 0x0008_0000;
        return unsafe { CGEventSourceFlagsState(1) & K_CG_EVENT_FLAG_MASK_ALTERNATE != 0 };
    }

    #[allow(unreachable_code)]
    false
}

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

fn build_browser_url() -> String {
    let app_url = ARGS.url.as_str();
    let mut query: Vec<(&str, String)> = Vec::new();

    if ARGS.dev_mode {
        query.push(("dev", "true".into()));
    }
    if ARGS.game_id != DEFAULT_GAME_ID {
        query.push(("game_id", url_encode(&ARGS.game_id).into_owned()));
    }
    if ARGS.ignore_package_id {
        query.push(("ignore_package_id", "true".into()));
    }

    if query.is_empty() {
        return app_url.to_string();
    }

    let qs = query
        .iter()
        .map(|(k, v)| format!("{}={}", k, url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("{}?{}", app_url, qs)
}

// ---------------------------------------------------------------------------
// Tauri commands – ADB bridge
// ---------------------------------------------------------------------------

#[tauri::command]
async fn adb_connect(
    id: String,
    window: tauri::WebviewWindow,
    bridge: tauri::State<'_, AdbBridge>,
) -> Result<(), String> {
    bridge.connect(id, window).await
}

#[tauri::command]
async fn adb_write(
    id: String,
    data: Vec<u8>,
    bridge: tauri::State<'_, AdbBridge>,
) -> Result<bool, String> {
    bridge.write(&id, &data).await
}

#[tauri::command]
async fn adb_ack(id: String, bridge: tauri::State<'_, AdbBridge>) -> Result<(), ()> {
    bridge.ack(&id).await;
    Ok(())
}

#[tauri::command]
async fn adb_close(id: String, bridge: tauri::State<'_, AdbBridge>) -> Result<(), ()> {
    bridge.close(&id).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tauri commands – launch-options window (desktop only)
// ---------------------------------------------------------------------------

/// Returns the formatted clap help text.
///
/// Access is restricted to the `shift` window via
/// `capabilities/shift_launch.json` — it is not callable from the main MBF
/// app or any external origin.
#[cfg(not(target_os = "android"))]
#[tauri::command]
fn get_help_text() -> String {
    let mut cmd = Args::command();
    cmd.render_help().to_string()
}

/// Re-launches the application with the provided shell-style argument string.
///
/// The single-instance guard is explicitly released before the child process
/// is spawned so the new instance can acquire the lock without racing against
/// this process's exit.
///
/// Access is restricted to the `shift` window via
/// `capabilities/shift_launch.json`.
#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn launch_with_args(
    args: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    use tauri::Manager;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;

    let parsed: Vec<String> = if args.trim().is_empty() {
        Vec::new()
    } else {
        shlex::split(&args).unwrap_or_default()
    };

    // Release the single-instance guard before spawning the child process so
    // the new instance can acquire the lock immediately without a race.
    {
        let state = app.state::<SingleInstanceState>();
        let mut guard = state.0.lock().unwrap();
        *guard = None;
    }

    std::process::Command::new(&exe)
        .args(&parsed)
        .spawn()
        .map_err(|e| e.to_string())?;

    app.exit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Window creation helpers
// ---------------------------------------------------------------------------

fn create_app_window(
    app: &tauri::App,
    url: tauri::WebviewUrl,
    init_script: &str,
) -> tauri::Result<tauri::WebviewWindow> {
    let main_url = url.clone();
    let builder = tauri::WebviewWindowBuilder::new(app, "main", url)
        .initialization_script(init_script);

    // title, inner_size and min_inner_size are desktop-only APIs.
    #[cfg(desktop)]
    let builder = builder
        .title("ModsBeforeFriday")
        .inner_size(1280.0, 800.0)
        .min_inner_size(800.0, 600.0)
        .on_download(|_window, download| {
            if let tauri::webview::DownloadEvent::Requested { url, destination } = download {
                // Extract the suggested filename from the URL path, decode any
                // percent-encoded characters, and fall back to "download" when
                // the URL has no useful file segment.
                let raw_name = url
                    .path_segments()
                    .and_then(|s| s.last())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("download");
                let suggested = urlencoding::decode(raw_name)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| raw_name.to_owned());

                let chosen = FileDialog::new()
                    .set_title("Save File")
                    .set_file_name(&suggested)
                    .save_file();

                match chosen {
                    Some(path) => {
                        *destination = path;
                        return true;
                    }
                    None => return false, // User cancelled
                }
            }
            true
        })
        .on_navigation(move |nav_url| {
            let url_str = nav_url.as_str();
            let main_url = main_url.to_string();
            let main_url = main_url.as_str();
            if url_str.starts_with(main_url) {
                return true;
            }
            
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                // Open external links in the default browser.
                let _ = open::that(url_str);
                return false;
            }
            
            return false;
        })
        .on_new_window(move |nav_url, _features| {
            let url_str = nav_url.as_str();
            
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                // Open external links in the default browser.
                let _ = open::that(url_str);
            }
            
            tauri::webview::NewWindowResponse::Deny
        });

    builder.devtools(true).zoom_hotkeys_enabled(true).build()
}

/// Creates the launch-options window (label = `"shift"`).
///
/// The `modifier_key` string is injected as `window.__mbfModifierKey` so the
/// page can display the correct key name for the current platform.
#[cfg(not(target_os = "android"))]
fn create_shift_window(
    app: &tauri::App,
    modifier_key: &str,
) -> tauri::Result<tauri::WebviewWindow> {
    // Encode the modifier key label as a JS string literal.
    let modifier_key_json = format!(
        "\"{}\"",
        modifier_key.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let init_script = format!("window.__mbfModifierKey={};", modifier_key_json);

    tauri::WebviewWindowBuilder::new(
        app,
        "shift",
        tauri::WebviewUrl::CustomProtocol(
            url::Url::parse("mbfshift://localhost/").unwrap(),
        ),
    )
    .initialization_script(&init_script)
    .title("ModsBeforeFriday Bridge – Launch Options")
    .inner_size(820.0, 640.0)
    .min_inner_size(600.0, 400.0)
    .resizable(true)
    .devtools(cfg!(debug_assertions))
    .build()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // Windows: allocate a console in release builds when --console is passed.
    #[cfg(all(not(debug_assertions), windows))]
    let _allocated_console = (ARGS.console || ARGS.help) && console::allocate_console();

    // Early help output.
    if ARGS.help {
        let mut cmd = Args::command();
        println!("{}", cmd.render_help());
        #[cfg(all(not(debug_assertions), windows))]
        {
            use std::io;
            println!("Press Enter to exit...");
            let _ = io::stdin().read_line(&mut String::new());
        }
        return;
    }

    // Set the ADB port.
    let _ = adb::ADB_PORT.set(ARGS.adb_port);

    // Single-instance guard (desktop only).  Stored in Tauri state so the
    // lock is held for the full lifetime of the process and can be explicitly
    // released by `launch_with_args` before spawning a child.
    #[cfg(not(target_os = "android"))]
    let single_instance = {
        let single = SingleInstance::new("ModsBeforeFriday Bridge").unwrap();
        if !single.is_single() {
            println!("Another instance is already running.");
            return;
        }
        single
    };

    // Detect the launch-options modifier key (desktop only).
    #[cfg(not(target_os = "android"))]
    let open_shift_window = !ARGS.test && is_launch_modifier_held();

    let browser_url = build_browser_url();

    // Prefix the init script with the ADB-available flag so bridge.js can
    // expose `isAdbAvailable` without an extra IPC round-trip.
    let init_script = format!(
        "window.__mbfIsAdbAvailable=true;\n{}",
        include_str!("bridge.js")
    );

    // Human-readable modifier key label injected into the shift-launch page.
    #[cfg(target_os = "macos")]
    let modifier_key_label = "Option (\u{2325})"; // ⌥
    #[cfg(all(not(target_os = "android"), not(target_os = "macos")))]
    let modifier_key_label = "Shift";

    let builder = tauri::Builder::default()
        .manage(AdbBridge::new())
        // Serve the embedded test page at mbftest://localhost/
        .register_uri_scheme_protocol("mbftest", |_app, _req| {
            tauri::http::Response::builder()
                .header("Content-Type", "text/html; charset=utf-8")
                .status(200)
                .body(include_bytes!("../test/index.html").to_vec())
                .unwrap()
        })
        // Serve the launch-options page at mbfshift://localhost/
        .register_uri_scheme_protocol("mbfshift", |_app, _req| {
            tauri::http::Response::builder()
                .header("Content-Type", "text/html; charset=utf-8")
                .status(200)
                .body(include_bytes!("shift_launch.html").to_vec())
                .unwrap()
        })
        .setup(move |app| {
            // macOS: run as an accessory app (no Dock icon) so the app lives
            // exclusively in the menu bar.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Create the appropriate window (Android manages its own activity).
            #[cfg(not(target_os = "android"))]
            {
                if open_shift_window {
                    create_shift_window(app, modifier_key_label)?;
                } else {
                    // Pre-warm the ADB connection in the background.
                    tauri::async_runtime::spawn(async {
                        let _ = crate::adb::adb_connect_or_start().await;
                    });

                    let url = if ARGS.test {
                        tauri::WebviewUrl::CustomProtocol(
                            url::Url::parse("mbftest://localhost/").unwrap(),
                        )
                    } else {
                        url::Url::parse(&browser_url)
                            .map(tauri::WebviewUrl::External)
                            .map_err(|e| e.to_string())?
                    };
                    create_app_window(app, url, &init_script)?;
                }
            }

            Ok(())
        });

    // Manage single-instance guard and register all commands (desktop only).
    #[cfg(not(target_os = "android"))]
    let builder = builder
        .manage(SingleInstanceState(std::sync::Mutex::new(Some(
            single_instance,
        ))))
        .invoke_handler(tauri::generate_handler![
            adb_connect,
            adb_write,
            adb_ack,
            adb_close,
            get_help_text,
            launch_with_args,
        ]);

    #[cfg(target_os = "android")]
    let builder = builder.invoke_handler(tauri::generate_handler![
        adb_connect,
        adb_write,
        adb_ack,
        adb_close,
    ]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
