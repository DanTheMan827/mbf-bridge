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
use clap::{arg, command, CommandFactory, Parser};
use config::{AUTO_START_ARG, DEFAULT_GAME_ID, DEFAULT_URL};
use lazy_static::lazy_static;
use serde::Serialize;
use urlencoding::encode as url_encode;

#[cfg(not(target_os = "android"))]
use auto_launch::AutoLaunchBuilder;

#[cfg(not(target_os = "android"))]
use single_instance::SingleInstance;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug, Serialize, Clone)]
#[command(version, about, long_about = None, disable_help_flag = true)]
struct Args {
    /// Specify a custom URL for the MBF app
    #[arg(long, default_value_t = DEFAULT_URL.to_owned())]
    url: String,

    /// Allocate a console window to display logs (Windows only)
    #[arg(long, default_value_t = false, hide = cfg!(not(windows)) || cfg!(debug_assertions))]
    console: bool,

    /// Start without opening the WebView window (tray-only mode)
    #[arg(long = "no-browser", hide = cfg!(target_os = "android"),
          default_value_t = cfg!(target_os = "android"))]
    no_browser: bool,

    /// Open the built-in test page instead of the MBF app
    #[arg(long, default_value_t = false, help_heading = "Development Options")]
    test: bool,

    /// The port that the ADB server is running on
    #[arg(long, default_value_t = 5037)]
    adb_port: u16,

    /// Output startup information as JSON
    #[arg(long, default_value_t = false, help_heading = "Development Options")]
    output_json: bool,

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

// ---------------------------------------------------------------------------
// JSON output helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
struct Message<T> {
    message_type: String,
    payload: T,
}

impl<T> Message<T> {
    fn new(payload: T) -> Self {
        Self {
            message_type: std::any::type_name::<T>()
                .to_string()
                .trim_start_matches("mbf_bridge::")
                .to_string(),
            payload,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct ErrorMessage {
    message: String,
}

#[derive(Debug, Serialize, Clone)]
struct StandardMessage {
    message: String,
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
}

pub fn eprint_message(message: &str) {
    if ARGS.output_json {
        let json = serde_json::to_string(&Message::new(ErrorMessage {
            message: message.to_string(),
        }))
        .unwrap();
        println!("{}", json);
    } else {
        eprintln!("{}", message);
    }
}

pub fn print_message(message: &str) {
    if ARGS.output_json {
        let json = serde_json::to_string(&Message::new(StandardMessage {
            message: message.to_string(),
        }))
        .unwrap();
        println!("{}", json);
    } else {
        println!("{}", message);
    }
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
    let builder = tauri::WebviewWindowBuilder::new(app, "main", url)
        .initialization_script(init_script);

    // title, inner_size and min_inner_size are desktop-only APIs.
    #[cfg(desktop)]
    let builder = builder
        .title("ModsBeforeFriday")
        .inner_size(1280.0, 800.0)
        .min_inner_size(800.0, 600.0);

    builder.devtools(true).zoom_hotkeys_enabled(true).build()
}

// ---------------------------------------------------------------------------
// Tray icon (desktop only)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "android"))]
fn setup_tray(
    app: &tauri::App,
    browser_url: String,
    init_script: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use tauri::{
        image::Image,
        menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        Manager,
    };

    let app_handle_open = app.handle().clone();
    let app_handle_quit = app.handle().clone();
    let app_handle_click = app.handle().clone();
    let browser_url_open = browser_url.clone();
    let browser_url_click = browser_url.clone();
    let init_script_open = init_script.clone();
    let init_script_click = init_script.clone();

    // Build auto-launch configuration with the no-browser flag so the app
    // starts in tray-only mode at login.
    let mut auto_launch_args: Vec<String> = env::args()
        .skip(1)
        .filter(|a| a != config::AUTO_START_ARG)
        .collect();
    auto_launch_args.push(config::AUTO_START_ARG.to_string());

    let app_exe = env::current_exe()?;
    let auto_launch = AutoLaunchBuilder::new()
        .set_app_name("ModsBeforeFriday Bridge")
        .set_app_path(app_exe.to_str().unwrap())
        .set_args(&auto_launch_args)
        .set_use_launch_agent(true)
        .build()?;

    let auto_launch_enabled = auto_launch.is_enabled().unwrap_or(false);

    let open_item = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
    let auto_run_item = CheckMenuItem::with_id(
        app,
        "auto_run",
        "Run at startup",
        true,
        auto_launch_enabled,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &open_item,
            &auto_run_item,
            &PredefinedMenuItem::separator(app)?,
            &quit_item,
        ],
    )?;

    let icon = Image::from_bytes(include_bytes!("../mbf.png"))?;

    /// Open or focus the main window, creating it if needed.
    fn open_or_focus(
        handle: &tauri::AppHandle,
        url_str: &str,
        init_script: &str,
    ) {
        if let Some(w) = handle.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        } else if let Ok(parsed) = url::Url::parse(url_str) {
            let _ = tauri::WebviewWindowBuilder::new(
                handle,
                "main",
                tauri::WebviewUrl::External(parsed),
            )
            .title("ModsBeforeFriday")
            .inner_size(1280.0, 800.0)
            .min_inner_size(800.0, 600.0)
            .initialization_script(init_script)
            .devtools(true)
            .zoom_hotkeys_enabled(true)
            .build();
        }
    }

    TrayIconBuilder::new()
        .icon(icon)
        .tooltip("ModsBeforeFriday Bridge")
        .menu(&menu)
        .on_menu_event(move |_app, event| match event.id.as_ref() {
            "open" => {
                let url = browser_url_open.clone();
                let script = init_script_open.clone();
                let handle = app_handle_open.clone();
                open_or_focus(&handle, &url, &script);
            }
            "auto_run" => {
                if auto_launch.is_enabled().unwrap_or(false) {
                    let _ = auto_launch.disable();
                } else {
                    let _ = auto_launch.enable();
                }
                let _ = auto_run_item.set_checked(auto_launch.is_enabled().unwrap_or(false));
            }
            "quit" => {
                app_handle_quit.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(move |_tray, event| {
            // Single left-click on Windows opens / focuses the window.
            #[cfg(windows)]
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let url = browser_url_click.clone();
                let script = init_script_click.clone();
                let handle = app_handle_click.clone();
                open_or_focus(&handle, &url, &script);
            }
            // Suppress unused-variable warnings on non-Windows.
            #[cfg(not(windows))]
            let _ = (event, &browser_url_click, &init_script_click, &app_handle_click);
        })
        .build(app)?;

    Ok(())
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
        print_message(&cmd.render_help().to_string());
        #[cfg(all(not(debug_assertions), windows))]
        {
            use std::io;
            print_message("Press Enter to exit...");
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
            print_message("Another instance is already running.");
            return;
        }
    }

    let browser_url = build_browser_url();

    // Prefix the init script with the ADB-available flag so bridge.js can
    // expose `isAdbAvailable` without an extra IPC round-trip.
    // ADB is available on all platforms (Android runs a custom adbd instance).
    let adb_available = true;
    let init_script = format!(
        "window.__mbfIsAdbAvailable={};\n{}",
        adb_available,
        include_str!("bridge.js")
    );

    let open_window = !ARGS.no_browser;
    let use_test_page = ARGS.test;
    let browser_url_setup = browser_url.clone();
    let init_script_setup = init_script.clone();

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

            if open_window {
                let url = if use_test_page {
                    tauri::WebviewUrl::CustomProtocol(
                        url::Url::parse("mbftest://localhost/").unwrap(),
                    )
                } else {
                    url::Url::parse(&browser_url_setup)
                        .map(tauri::WebviewUrl::External)
                        .map_err(|e| e.to_string())?
                };
                create_app_window(app, url, &init_script_setup)?;
            }

            // Tray icon is desktop-only.
            #[cfg(not(target_os = "android"))]
            setup_tray(app, browser_url_setup, init_script_setup)?;

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
