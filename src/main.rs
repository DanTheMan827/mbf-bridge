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
mod jump_list;

use adb_bridge::AdbBridge;
use clap::{CommandFactory, Parser};
use config::{DEFAULT_GAME_ID, DEFAULT_URL};
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use urlencoding::encode as url_encode;

#[cfg(not(target_os = "android"))]
use rfd::FileDialog;

/// The entire compiled Vite `dist/` folder embedded at compile time.
/// Served via the `mbf://` custom protocol so the app can run offline.
static UI_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/ui/dist");

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

    #[cfg(target_os = "linux")]
    {
        // Use X11's XQueryKeymap to sample the current keyboard state.
        // Keycodes for Shift: Left Shift = 50, Right Shift = 62.
        use x11::xlib::{Display, XCloseDisplay, XOpenDisplay, XQueryKeymap};
        struct DisplayGuard(*mut Display);
        impl Drop for DisplayGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { XCloseDisplay(self.0) };
                }
            }
        }
        unsafe {
            let guard = DisplayGuard(XOpenDisplay(std::ptr::null()));
            if guard.0.is_null() {
                return false;
            }
            let mut keys = [0i8; 32];
            XQueryKeymap(guard.0, keys.as_mut_ptr());
            // Each bit in `keys` represents one keycode: keys[kc/8] bit (kc%8).
            let left_shift = (keys[50 / 8] >> (50 % 8)) & 1;
            let right_shift = (keys[62 / 8] >> (62 % 8)) & 1;
            return left_shift != 0 || right_shift != 0;
        }
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
/// Access is restricted to the `shift` and `help` windows via their
/// respective capability files — it is not callable from the main MBF app
/// or any external origin.
#[cfg(not(target_os = "android"))]
#[tauri::command]
fn get_help_text() -> String {
    let mut cmd = Args::command();
    cmd.render_help().to_string()
}

/// Re-launches the application with the provided shell-style argument string.
///
/// Also records the launch command in the Windows taskbar jump list so the
/// user can re-run it quickly without opening the shift window again.
///
/// A jump list entry is keyed on the **combination** of `--url`, `--dev`, and
/// `--game-id`.  Whenever at least one of those three values differs from its
/// compiled-in default, an entry is added whose argument string is built from
/// only those three flags (other flags like `--adb-port` are intentionally
/// excluded so that the jump list stays focused on "launch this specific MBF
/// configuration").
///
/// Access is restricted to the `shift` window via
/// `capabilities/shift_launch.json`.
#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn launch_with_args(
    args: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;

    let parsed: Vec<String> = if args.trim().is_empty() {
        Vec::new()
    } else {
        shlex::split(&args).unwrap_or_default()
    };

    // Extract the three jump-list key values from the parsed argument vector.
    #[cfg(windows)]
    {
        /// Walk a `&[String]` looking for `--flag <value>` and return the value.
        fn extract_flag<'a>(parsed: &'a [String], flag: &str) -> Option<&'a str> {
            parsed
                .windows(2)
                .find(|w| w[0] == flag)
                .map(|w| w[1].as_str())
        }
    }

    std::process::Command::new(&exe)
        .args(&parsed)
        .spawn()
        .map_err(|e| e.to_string())?;

    app.exit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom protocol handler – embedded Vite SPA
// ---------------------------------------------------------------------------

fn serve_embedded(req: &tauri::http::Request<Vec<u8>>) -> tauri::http::Response<Vec<u8>> {
    // Strip the scheme + authority to get a relative path.
    // e.g. "mbf://localhost/assets/index.js" → "assets/index.js"
    let url = req.uri().path().trim_start_matches('/');

    // Look up the file in the embedded dist directory.  Fall back to
    // `index.html` for any unrecognised path so React Router can handle it.
    let (body, mime) = match UI_DIR.get_file(url) {
        Some(f) => {
            let mime = mime_guess::from_path(url)
                .first_raw()
                .unwrap_or("application/octet-stream");
            (f.contents().to_vec(), mime)
        }
        None => {
            let html = UI_DIR
                .get_file("index.html")
                .map(|f| f.contents().to_vec())
                .unwrap_or_default();
            (html, "text/html; charset=utf-8")
        }
    };

    tauri::http::Response::builder()
        .header("Content-Type", mime)
        .status(200)
        .body(body)
        .unwrap()
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
                    None => return false,
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
                let _ = open::that(url_str);
                return false;
            }
            false
        })
        .on_new_window(move |nav_url, _features| {
            let url_str = nav_url.as_str();
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                let _ = open::that(url_str);
            }
            tauri::webview::NewWindowResponse::Deny
        });

    builder.devtools(true).zoom_hotkeys_enabled(true).build()
}

/// Creates the launch-options window (label = `"shift"`).
#[cfg(not(target_os = "android"))]
fn create_shift_window(
    app: &tauri::App,
    modifier_key: &str,
) -> tauri::Result<tauri::WebviewWindow> {
    let modifier_key_json = format!(
        "\"{}\"",
        modifier_key.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let init_script = format!("window.__mbfModifierKey={};", modifier_key_json);

    tauri::WebviewWindowBuilder::new(
        app,
        "shift",
        tauri::WebviewUrl::CustomProtocol(
            url::Url::parse("mbf://localhost/shift").unwrap(),
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

/// Creates the help window (label = `"help"`).
#[cfg(not(target_os = "android"))]
fn create_help_window(app: &tauri::App) -> tauri::Result<tauri::WebviewWindow> {
    tauri::WebviewWindowBuilder::new(
        app,
        "help",
        tauri::WebviewUrl::CustomProtocol(
            url::Url::parse("mbf://localhost/help").unwrap(),
        ),
    )
    .title("ModsBeforeFriday Bridge – Help")
    .inner_size(760.0, 600.0)
    .min_inner_size(500.0, 400.0)
    .resizable(true)
    .devtools(cfg!(debug_assertions))
    .build()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    #[cfg(windows)]
    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

    unsafe {
        #[cfg(windows)]
        let _ = SetCurrentProcessExplicitAppUserModelID(windows::core::w!("YourApp.Id"));
    }

    // Windows: allocate a console in release builds when --console is passed.
    #[cfg(all(not(debug_assertions), windows))]
    let _allocated_console = (ARGS.console || ARGS.help) && console::allocate_console();

    // --help: open a React help window instead of printing to a console.
    // On debug builds (where the console is always present) we also print to
    // stdout for convenience.
    #[cfg(debug_assertions)]
    if ARGS.help {
        let mut cmd = Args::command();
        println!("{}", cmd.render_help());
    }

    // Set the ADB port.
    let _ = adb::ADB_PORT.set(ARGS.adb_port);

    // Detect the launch-options modifier key (desktop only).
    #[cfg(not(target_os = "android"))]
    let open_shift_window = !ARGS.test && !ARGS.help && is_launch_modifier_held();

    let browser_url = build_browser_url();
    
    // Add a jump list entry whenever the combination differs from defaults.
    let url_changed     = ARGS.url     != DEFAULT_URL;
    let dev_changed     = ARGS.dev_mode;
    let game_id_changed = ARGS.game_id != DEFAULT_GAME_ID;

    if url_changed || dev_changed || game_id_changed {
        // Build canonical args string from only the three key flags.
        let mut entry_args: Vec<String> = Vec::new();
        if url_changed {
            if let Ok(url) = shlex::try_quote(&ARGS.url) {
                entry_args.push(format!("--url {}", url));
            }
        }
        if dev_changed {
            entry_args.push("--dev".to_owned());
        }
        if game_id_changed {
            if let Ok(game_id) = shlex::try_quote(&ARGS.game_id) {
            entry_args.push(format!("--game-id {}", game_id));
            }
        }
        let entry_arg_str = entry_args.join(" ");

        // Build a human-readable title: URL (or default label) + badges.
        let url_label = if url_changed {
            // Keep only the host + first path segment for brevity.
            url::Url::parse(&ARGS.url)
                .ok()
                .and_then(|u| {
                    let host = u.host_str().unwrap_or(&ARGS.url).to_owned();
                    let first_seg = u.path_segments()
                        .and_then(|mut s| s.next().filter(|p| !p.is_empty()))
                        .unwrap_or("");
                    if first_seg.is_empty() {
                        Some(host)
                    } else {
                        Some(format!("{}/{}", host, first_seg))
                    }
                })
                .unwrap_or_else(|| ARGS.url.to_owned())
        } else {
            "MBF".to_owned()
        };

        let mut badges: Vec<&str> = Vec::new();
        if dev_changed     { badges.push("dev"); }
        if game_id_changed { badges.push(&ARGS.game_id); }

        let title = if badges.is_empty() {
            url_label
        } else {
            format!("{} [{}]", url_label, badges.join(", "))
        };

        // Truncate to 60 chars to stay within jump list display limits.
        let short_title = if title.chars().count() > 60 {
            format!("{}…", title.chars().take(59).collect::<String>())
        } else {
            title
        };

        jump_list::prepend_task(&short_title, &entry_arg_str);
    }

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
        // Serve the embedded React SPA at mbf://localhost/<path>.
        // The dist/ directory is embedded via `include_dir!` so every file is
        // available.  Unrecognised paths fall back to index.html so that React
        // Router can handle client-side routing (/test, /shift, /help …).
        .register_uri_scheme_protocol("mbf", |_app, req| serve_embedded(&req))
        .setup(move |app| {
            // macOS: run as an accessory app (no Dock icon).
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Create the appropriate window (Android manages its own activity).
            #[cfg(not(target_os = "android"))]
            {
                if ARGS.help {
                    create_help_window(app)?;
                } else if open_shift_window {
                    create_shift_window(app, modifier_key_label)?;
                } else {
                    // Pre-warm the ADB connection in the background.
                    tauri::async_runtime::spawn(async {
                        let _ = crate::adb::adb_connect_or_start().await;
                    });

                    let url = if ARGS.test {
                        tauri::WebviewUrl::CustomProtocol(
                            url::Url::parse("mbf://localhost/test").unwrap(),
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

    // Register all commands (desktop only).
    #[cfg(not(target_os = "android"))]
    let builder = builder.invoke_handler(tauri::generate_handler![
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

