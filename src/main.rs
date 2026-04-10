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
// Tauri commands
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
// Window creation helper
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
        .on_download(|_window, _download| {
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

    // Single-instance guard (desktop only).
    #[cfg(not(target_os = "android"))]
    {
        let single = SingleInstance::new("ModsBeforeFriday Bridge").unwrap();
        if !single.is_single() {
            println!("Another instance is already running.");
            return;
        }
    }

    let browser_url = build_browser_url();

    // Prefix the init script with the ADB-available flag so bridge.js can
    // expose `isAdbAvailable` without an extra IPC round-trip.
    // ADB is available on all platforms (Android runs a custom adbd instance).
    let init_script = format!(
        "window.__mbfIsAdbAvailable=true;\n{}",
        include_str!("bridge.js")
    );

    tauri::Builder::default()
        .manage(AdbBridge::new())
        // Serve the embedded test page at mbftest://localhost/
        .register_uri_scheme_protocol("mbftest", |_app, _req| {
            tauri::http::Response::builder()
                .header("Content-Type", "text/html; charset=utf-8")
                .status(200)
                .body(include_bytes!("../test/index.html").to_vec())
                .unwrap()
        })
        .setup(move |app| {
            // Pre-warm the ADB connection in the background.
            tauri::async_runtime::spawn(async {
                let _ = crate::adb::adb_connect_or_start().await;
            });

            // macOS: run as an accessory app (no Dock icon) so the app lives
            // exclusively in the menu bar.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Create the main window (Android manages its own activity window).
            #[cfg(not(target_os = "android"))]
            {
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

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            adb_connect,
            adb_write,
            adb_ack,
            adb_close,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
