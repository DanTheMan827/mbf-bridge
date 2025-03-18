#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! # ModsBeforeFriday Bridge
//!
//! This application sets up a local Axum-based server to act as a bridge between the
//! MBF application and ADB. It spawns the ADB server if needed, establishes websocket
//! connections, and also provides a tray icon with additional functionalities.
//!
//! ## Key Features
//! - Start and connect to an ADB server (with auto-extraction of ADB binaries into a temporary folder).
//! - Provide a websocket bridge for communication.
//! - Launch a browser with query parameters derived from command-line options.
//! - System tray integration with options for opening the browser, auto-run at startup, and quit.
//!
//! ## ADB Extraction
//! For Windows and Linux, if ADB isn’t already running, the corresponding binary (and related DLLs on Windows)
//! is extracted to a subfolder in the temporary directory. This subfolder is named using a randomly generated UUID.
//!
//! **Note:** Currently, the UUID is generated using `Uuid::new_v4()`. Replace this with a UUID v7 generator if available.

use std::{
    env, path::{Path, PathBuf}, process::{exit, Stdio}, sync::{Arc, Mutex, OnceLock}, time::{Duration, Instant}
};

use auto_launch::AutoLaunchBuilder;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Request,
    },
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use http::{Method, StatusCode};
use reqwest::Url;
use tao::event_loop::EventLoopBuilder;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command
};
use tower_http::cors::CorsLayer;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem}, TrayIcon, TrayIconBuilder, TrayIconEvent
};

use uuid::Uuid;

/// Starts the ADB server using the provided executable path.
///
/// This function spawns the ADB server with arguments `server nodaemon` and the environment variable
/// `ADB_MDNS_OPENSCREEN` set to 1. It detaches stdout and stderr.
///
/// # Arguments
///
/// * `path` - Path to the ADB executable.
///
/// # Returns
///
/// A `tokio::io::Result<()>` indicating success or failure.
async fn adb_start(path: &str) -> tokio::io::Result<()> {
    let mut command = Command::new(path);
    command.args(&["server", "nodaemon"]);
    command.env("ADB_MDNS_OPENSCREEN", "1");
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW

    let mut process = command.spawn()?;
    // Spawn a background task to wait for the process (avoid blocking)
    tokio::spawn(async move {
        let _ = process.wait().await;
    });
    Ok(())
}

/// Connects to the ADB server.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the connection to the ADB server.
async fn adb_connect() -> tokio::io::Result<TcpStream> {
    TcpStream::connect("127.0.0.1:5037").await
}

/// Retries the connection to the ADB server up to 10 times with short delays.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the successful connection or an error.
async fn adb_connect_retry() -> tokio::io::Result<TcpStream> {
    let mut attempts = 0;
    loop {
        match adb_connect().await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if attempts == 10 {
                    return Err(err);
                }
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Extracts ADB binaries for Windows into a temporary subfolder and returns the path to the ADB executable.
///
/// The subfolder is named with a randomly generated UUID (using v4 as a placeholder for v7).
#[cfg(windows)]
async fn extract_adb_binaries_windows() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb.exe");
    write(&adb_path, include_bytes!("../adb/win/adb.exe")).await?;
    write(
        adb_subfolder.join("AdbWinApi.dll"),
        include_bytes!("../adb/win/AdbWinApi.dll"),
    )
    .await?;
    write(
        adb_subfolder.join("AdbWinUsbApi.dll"),
        include_bytes!("../adb/win/AdbWinUsbApi.dll"),
    )
    .await?;
    Ok(adb_path)
}

/// Extracts ADB binaries for Linux into a temporary subfolder and returns the path to the ADB executable.
///
/// The subfolder is named with a randomly generated UUID (using v4 as a placeholder for v7).
#[cfg(target_os = "linux")]
async fn extract_adb_binaries_linux() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use tokio::fs::{create_dir_all, write};

    let temp_dir = env::temp_dir();
    let adb_subfolder = temp_dir.join(Uuid::new_v4().to_string());
    create_dir_all(&adb_subfolder).await?;

    let adb_path = adb_subfolder.join("adb");
    write(&adb_path, include_bytes!("../adb/linux/adb")).await?;
    // Set executable permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&adb_path, std::fs::Permissions::from_mode(0o755))?;
    Ok(adb_path)
}

/// Ensures a connection to the ADB server, starting it if necessary.
///
/// On Windows and Linux, if ADB is not running, the binaries are extracted into a temporary
/// subfolder (named with a random UUID) and then started.
///
/// # Returns
///
/// A `tokio::io::Result<TcpStream>` representing the ADB connection.
async fn adb_connect_or_start() -> tokio::io::Result<TcpStream> {
    // Try to connect first.
    if let Ok(stream) = adb_connect().await {
        return Ok(stream);
    }

    // Attempt to start ADB normally using system-installed "adb".
    if adb_start("adb").await.is_ok() {
        return adb_connect_retry().await;
    }

    // Fallback extraction logic depending on the operating system.
    #[cfg(windows)]
    {
        let adb_path = extract_adb_binaries_windows().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        adb_connect_retry().await
    }

    #[cfg(target_os = "linux")]
    {
        let adb_path = extract_adb_binaries_linux().await.unwrap();
        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        adb_connect_retry().await
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, assume ADB is located alongside the executable.
        let adb_exe = env::current_exe().unwrap().parent().unwrap().join("adb");
        adb_start(adb_exe.to_str().unwrap()).await.unwrap();
        adb_connect_retry().await
    }
}

/// Attempts to locate an executable by checking direct paths, the PATH variable,
/// and the App Paths registry on Windows.
fn lookup_executable(command: &str) -> Option<String> {
    // Step 1: If the command is a direct path, check if it exists.
    let command_path = Path::new(command);
    if command_path.exists() && command_path.is_file() {
        return Some(command_path.to_string_lossy().to_string());
    }

    // If the command doesn't have an extension, consider adding ".exe"
    let candidate_names: Vec<String> = if Path::new(command).extension().is_none() {
        vec![command.to_string(), format!("{}.exe", command)]
    } else {
        vec![command.to_string()]
    };

    // Step 2: Look through each directory in the PATH environment variable.
    if let Ok(paths) = env::var("PATH") {
        for path in env::split_paths(&paths) {
            for candidate in &candidate_names {
                let full_path = path.join(candidate);
                if full_path.exists() && full_path.is_file() {
                    return Some(full_path.to_string_lossy().to_string());
                }
            }
        }
    }

    // Step 3: Check the App Paths registry (Windows-specific)
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        // Open the registry key for App Paths.
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(app_paths) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths") {
            for candidate in &candidate_names {
                if let Ok(subkey) = app_paths.open_subkey(candidate) {
                    // The default value usually contains the full path to the executable.
                    if let Ok(path_str) = subkey.get_value::<String, _>("") {
                        let candidate_path = PathBuf::from(path_str);
                        if candidate_path.exists() && candidate_path.is_file() {
                            return Some(candidate_path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }

    // No method succeeded, so return None.
    None
}

fn start_chromium_app(binary: &Option<String>, url: &str) -> bool {
    if let Some(executable) = binary {
        // Launch the chromium-based browse in app mode with our url.
        let mut command = Command::new(executable);
        command.args(&["--new-window", format!("--app={}", url).as_str()]);

        tokio::spawn(async move { command.spawn() });

        return true;
    }

    return false;
}

static EDGE_PATH: OnceLock<Option<String>> = OnceLock::new();
static CHROME_PATH: OnceLock<Option<String>> = OnceLock::new();
static GOOGLE_CHROME_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Opens the default browser with the specified URL.
///
/// # Arguments
///
/// * `url` - The URL to open.
fn start_browser(url: &Arc<String>) {
    let url = Arc::clone(&url);

    let _ = tokio::spawn(async move {
        if start_chromium_app(EDGE_PATH.get_or_init(|| lookup_executable("msedge")), url.as_ref()) {
            return;
        }

        if start_chromium_app(CHROME_PATH.get_or_init(|| lookup_executable("chrome")), url.as_ref()) {
            return;
        }

        if start_chromium_app(GOOGLE_CHROME_PATH.get_or_init(|| lookup_executable("google-chrome")), url.as_ref()) {
            return;
        }

        open::that_detached(url.as_ref()).unwrap();
    });
}

/// Handles incoming websocket connections and proxies data to/from the ADB server.
async fn handle_websocket(ws: WebSocket) {
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Connect to (or start) ADB and split the connection.
    let (mut adb_reader, mut adb_writer) = adb_connect_or_start().await.unwrap().into_split();

    // Run both directions concurrently.
    tokio::join!(
        async {
            // Forward binary messages from the websocket to ADB.
            while let Some(Ok(message)) = ws_reader.next().await {
                if let Message::Binary(packet) = message {
                    adb_writer.write_all(&packet).await.unwrap();
                }
            }
            adb_writer.shutdown().await.unwrap();
        },
        async {
            // Read data from ADB and send as binary messages over the websocket.
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match adb_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        ws_writer.close().await.unwrap();
                        break;
                    }
                    Ok(n) => {
                        ws_writer
                            .send(Message::binary(buf[..n].to_vec()))
                            .await
                            .unwrap();
                    }
                }
            }
        }
    );
}

/// Global proxy host used for redirection.
static PROXY_HOST: OnceLock<String> = OnceLock::new();

/// Global HTTP client.
static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Handles proxying of HTTP requests to the configured proxy host.
///
/// This function takes an incoming HTTP request, modifies it to include the appropriate
/// headers and target URL, and forwards it to the configured proxy host. The response
/// from the proxy host is then returned to the client.
///
/// # Arguments
///
/// * `request` - The incoming HTTP request to be proxied.
///
/// # Returns
///
/// A `Result<Response, Response>` where:
/// - `Ok(Response)` contains the successful response from the proxy host.
/// - `Err(Response)` contains an error response if the request could not be processed.
///
/// # Behavior
///
/// - The function reads the global `PROXY_HOST` to determine the base URL for the proxy.
/// - It modifies the incoming request's headers to include the `Host` header of the proxy host.
/// - The request body is wrapped as a stream and forwarded to the proxy host.
/// - If the request fails to parse or the proxy host is unreachable, appropriate HTTP error
///   responses are returned (`400 Bad Request` or `502 Bad Gateway`).
///
/// # Errors
///
/// - Returns `400 Bad Request` if the request URI cannot be parsed.
/// - Returns `502 Bad Gateway` if the proxy host is unreachable.
#[axum::debug_handler]
async fn proxy_request(request: Request) -> Result<Response, Response> {
    println!("proxy_request: {} {}", request.method(), request.uri());

    let url = Url::options()
        .base_url(Some(&Url::parse(PROXY_HOST.get().unwrap()).unwrap()))
        .parse(&request.uri().to_string())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Bad Request").into_response())?;

    let mut headers = request.headers().clone();
    headers.insert("Host", url.host_str().unwrap().parse().unwrap());

    let (client, request) = CLIENT
        .get_or_init(|| reqwest::Client::new())
        .request(request.method().clone(), url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(
            request.into_body().into_data_stream(),
        ))
        .build_split();

    let request = request.map_err(|_| (StatusCode::BAD_REQUEST, "Bad Request").into_response())?;

    let response = client
        .execute(request)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response())?;

    Ok((
        response.status(),
        response.headers().clone(),
        axum::body::Body::new(reqwest::Body::from(response)),
    )
        .into_response())
}

/// URL encodes a string.
fn url_encode(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            // Alphanumeric and safe characters
            0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A | 0x2D | 0x2E | 0x5F | 0x7E => {
                output.push(byte as char)
            }
            _ => {
                output.push('%');
                output.push_str(&format!("{:02X}", byte));
            }
        }
    }
    output
}

/// Extracts the origin (scheme and host) from a given URL string.
///
/// Returns `Some(String)` if successful, otherwise `None`.
fn extract_origin(app_url: &str) -> Option<String> {
    let url_parts: Vec<&str> = app_url.split("//").collect();
    if url_parts.len() == 2 {
        let scheme = url_parts[0]; // e.g. "http:" or "https:"
        let host_and_port = url_parts[1].split('/').next()?; // Extract host and port
        return Some(format!("{}//{}", scheme, host_and_port));
    }
    None
}

const DEFAULT_PORT: u16 = 25037;
const DEFAULT_URL: &str = "https://dantheman827.github.io/ModsBeforeFriday/";
const DEFAULT_GAME_ID: &str = "com.beatgames.beatsaber";

/// Entry point of the application.
#[tokio::main]
async fn main() {
    // ------------------------------
    // Configuration and Command-Line Parsing
    // ------------------------------
    let args: Vec<String> = env::args().collect();
    let launch_args: Vec<String> = args.iter().skip(1).cloned().collect();

    let mut port = DEFAULT_PORT;
    let run_persistent = !args.contains(&"--auto-close".to_string());
    let mut app_url = DEFAULT_URL;
    let dev_mode = args.contains(&"--dev".to_string());
    let mut game_id = DEFAULT_GAME_ID;
    let mut open_browser = args.contains(&"--open-browser".to_string());
    let proxy_requests = args.contains(&"--proxy".to_string());

    // Display help message if requested.
    if args.contains(&"--help".to_string()) {
        let help_message = [
            format!(
                "Usage: {} [OPTIONS]",
                env::current_exe()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
            )
            .as_str(),
            "",
            "Options:",
            "  --help              Show this help message",
            format!("  --port <PORT>       Specify a custom port for the server (default: {}, or 0 if not persistent)", DEFAULT_PORT).as_str(),
            "  --auto-close        Automatically exit the bridge after 10 seconds of inactivity",
            format!("  --url <URL>         Specify a custom URL for the MBF app (default: {})", DEFAULT_URL).as_str(),
            "  --open-browser      Open the browser automatically after starting the server (implied if not persistent)",
            #[cfg(not(target_os = "macos"))]
            "  --proxy             Proxy requests through the internal server to avoid mixed content errors",
            #[cfg(windows)]
            "  --console           Allocate a console window to display logs",
            "",
            "Development Options:",
            "  --dev               Enable MBF development mode",
            "  --game <ID>         Specify a custom game ID for the MBF app (default: com.beatgames.beatsaber)",
            "",
            "Behavior:",
            "  If --auto-close is specified:",
            "    - The server will shut down after 10 seconds of inactivity.",
            "    - The browser will open automatically (--open-browser is implied).",
            "    - The server will use a random port (--port 0 is implied).",
        ]
        .join("\n");

        #[cfg(not(windows))]
        {
            println!("{}", help_message);
        }

        #[cfg(windows)]
        {
            use std::ptr::null_mut;
            use winapi::shared::ntdef::LPCWSTR;
            use winapi::um::winuser::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

            // Convert Rust string to a wide string (UTF-16)
            let wide_message: Vec<u16> = help_message.encode_utf16().chain(Some(0)).collect();
            let wide_title: Vec<u16> = "Help".encode_utf16().chain(Some(0)).collect();
            unsafe {
                MessageBoxW(
                    null_mut(),
                    wide_message.as_ptr() as LPCWSTR,
                    wide_title.as_ptr() as LPCWSTR,
                    MB_OK | MB_ICONINFORMATION,
                );
            }
        }
        return;
    }

    #[cfg(target_os = "macos")]
    {
        proxy_requests = true; // Always proxy on macOS to avoid mixed content errors
    }

    // Parse custom URL, port, and game ID arguments.
    if let Some(url_index) = args.iter().position(|x| x == "--url") {
        if let Some(url_str) = args.get(url_index + 1) {
            app_url = url_str;
        }
    }
    if let Some(port_index) = args.iter().position(|x| x == "--port") {
        if let Some(port_str) = args.get(port_index + 1) {
            if let Ok(port_num) = port_str.parse::<u16>() {
                port = port_num;
            }
        }
    }
    if let Some(game_index) = args.iter().position(|x| x == "--game") {
        if let Some(game_str) = args.get(game_index + 1) {
            game_id = game_str;
        }
    }

    // If running in auto-close mode, force browser open and use a random port.
    if !run_persistent {
        open_browser = true;
        port = 0;
    }

    // ------------------------------
    // ADB Server Setup
    // ------------------------------
    // Spawn a background task to ensure ADB is running.
    tokio::spawn(async {
        let _ = adb_connect_or_start().await;
    });

    // ------------------------------
    // Web Server Setup using Axum
    // ------------------------------
    // Track the time of the last request for auto-close.
    let last_request_time = Arc::new(Mutex::new(Instant::now()));
    let update_last_request_time = {
        let last_request_time = Arc::clone(&last_request_time);
        move |req: Request, next: axum::middleware::Next| {
            let last_request_time = Arc::clone(&last_request_time);
            async move {
                *last_request_time.lock().unwrap() = Instant::now();
                next.run(req).await
            }
        }
    };

    // Determine allowed origins for CORS.
    let mut allowed_origins = vec![
        "http://localhost:3000",
        "https://localhost:3000",
        "https://mbf.bsquest.xyz",
    ];
    let app_origin = extract_origin(app_url).unwrap();
    if !allowed_origins.contains(&app_origin.as_str()) {
        allowed_origins.push(app_origin.as_str());
    }
    println!("Allowed Origins: {:?}", allowed_origins);

    // Define the Axum router and nested routes.
    let app = Router::new()
        .nest(
            "/bridge",
            Router::new()
                .route("/ping", get(|| async { "OK" }))
                .route(
                    "/",
                    get(|ws: WebSocketUpgrade| async { ws.on_upgrade(handle_websocket) }),
                )
                .route_layer(
                    CorsLayer::new()
                        .allow_methods([Method::GET, Method::POST])
                        .allow_origin(
                            allowed_origins
                                .iter()
                                .map(|x| x.parse().unwrap())
                                .collect::<Vec<_>>(),
                        )
                        .allow_private_network(true),
                ),
        )
        .fallback(proxy_request)
        .layer(axum::middleware::from_fn(update_last_request_time));

    // Bind the server listener.
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    let local_addr = listener.local_addr().unwrap();
    let assigned_ip = local_addr.ip().to_string();
    let assigned_port = local_addr.port();
    let assigned_url = format!("http://{}:{}", assigned_ip, assigned_port);

    // Build query string parameters for the browser URL.
    let mut query_strings: Vec<(&str, String)> = Vec::new();
    if dev_mode {
        query_strings.push(("dev", "true".to_string()));
    }
    if game_id != DEFAULT_GAME_ID {
        query_strings.push(("game", url_encode(game_id)));
    }
    if assigned_port != DEFAULT_PORT {
        query_strings.push(("bridge", format!("{}:{}", assigned_ip, assigned_port)));
    }

    let mut browser_url = app_url.to_string();

    // If proxying requests, set browser URL to the local server with the path from app_url preserved.
    if proxy_requests {
        // Parse the app URL with the Url crate and extract the path
        let mut app_url = Url::parse(app_url).unwrap();
        app_url.set_scheme("http").unwrap();
        app_url.set_host(Some("127.0.0.1")).unwrap();
        app_url.set_port(Some(assigned_port)).unwrap();
        browser_url = app_url.to_string();
    }

    if !query_strings.is_empty() {
        browser_url.push('?');
        for (key, value) in query_strings {
            browser_url.push_str(key);
            browser_url.push('=');
            browser_url.push_str(&url_encode(&value));
            browser_url.push('&');
        }
        browser_url.pop(); // Remove trailing '&'
    }

    // Set the global proxy host.
    PROXY_HOST.get_or_init(|| app_url.to_string());
    println!("Server is running: {}", assigned_url);
    println!("Browser URL: {}", browser_url);

    let browser_url = Arc::new(browser_url);

    // Open browser if requested.
    if open_browser {
        start_browser(&browser_url);
    }

    let run_persistent = Arc::new(run_persistent);
    let event_loop_running = Arc::new(Mutex::new(true));

    let event_loop_check = {
        let event_loop_running = Arc::clone(&event_loop_running);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(16)).await;
                let event_loop_running = event_loop_running.as_ref().lock().unwrap();
                if *event_loop_running == false {
                    return;
                }
            }
        }
    };

    let shutdown_signal = {
        async move {
            use tokio::signal;

            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        }
    };

    let unix_hup_signal = {
        async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};

                let mut stream = signal(SignalKind::hangup()).unwrap();
                stream.recv().await;

                return;
            }

            loop {
                tokio::time::sleep(Duration::from_millis(16)).await;
            }
        }
    };

    // ------------------------------
    // Idle check for auto-close
    // ------------------------------
    let idle_check = {
        let run_persistent = Arc::clone(&run_persistent);
        let last_request_time = Arc::clone(&last_request_time);

        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;

                // If not running persistently, shut down after 10 seconds of inactivity.
                if !run_persistent.as_ref() {
                    let elapsed = last_request_time.lock().unwrap().elapsed();
                    if elapsed > Duration::from_secs(10) {
                        break;
                    }
                }
            }
        }
    };

    let _ = {
        let server = {
            tokio::spawn(async move {
                tokio::select! {
                    _ = axum::serve(listener, app) => {
                        println!("Server ended, this shouldn't happen.");
                        exit(1);
                    },
                    _ = shutdown_signal => println!("Shutdown signal received."),
                    _ = unix_hup_signal => println!("SIGHUP signal received."),
                    _ = idle_check => println!("No requests received in the last 10 seconds."),
                    _ = event_loop_check => println!("Event loop ended.")
                }
            })
        };

        {
            tokio::spawn(async move {
                let _ = server.await;

                println!("Exiting...");
                exit(0);
            })
        }
    };

    // ------------------------------
    // System Tray and Event Loop
    // ------------------------------
    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::new().build();

    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::EventLoopExtMacOS;

        // https://github.com/glfw/glfw/issues/1552
        event_loop.set_activation_policy(tao::platform::macos::ActivationPolicy::Accessory);
    }

    if !run_persistent.as_ref() {
        event_loop.run(move |_, _, control_flow| {
            *control_flow = tao::event_loop::ControlFlow::WaitUntil(
                Instant::now() + Duration::from_millis(16),
            );
        });
    }

    // Create the open menu item.
    let menu_open = MenuItem::new("Open", true, None);

    // Create the auto-launch configuration.
    let auto_launch = AutoLaunchBuilder::new()
        .set_app_name(format!("ModsBeforeFriday Bridge {:?}", launch_args).as_str())
        .set_app_path(env::current_exe().unwrap().to_str().unwrap())
        .set_args(&launch_args)
        .set_use_launch_agent(true)
        .build()
        .unwrap();

    // Create the auto-run menu item.
    let menu_auto_run = CheckMenuItem::new(
        "Run at startup",
        true,
        auto_launch.is_enabled().unwrap(),
        None,
    );

    // Create the quit menu item.
    let menu_quit = MenuItem::new("Quit", true, None);

    // Create the tray menu.
    let tray_menu = Menu::new();
    tray_menu
        .append_items(&[
            &menu_open,
            &menu_auto_run,
            &PredefinedMenuItem::separator(),
            &menu_quit,
        ])
        .unwrap();

    // Create the event receivers.
    let menu_receiver = MenuEvent::receiver();
    let tray_receiver = TrayIconEvent::receiver();

    // Create the tray icon.
    let tray_icon: OnceLock<Option<TrayIcon>> = OnceLock::new();

    println!("Starting main loop");
    event_loop.run(move |event, _, control_flow| {
        *control_flow =tao::event_loop::ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(16));

        if let tao::event::Event::Reopen { .. } = event {
            start_browser(&browser_url);
            return;
        }

        if let tao::event::Event::NewEvents(tao::event::StartCause::Init) = event {
            let image = image::load_from_memory_with_format(
                include_bytes!("../mbf.png"),
                image::ImageFormat::Png,
            )
            .unwrap()
            .into_rgba8();
            let (width, height) = image.dimensions();
            let rgba = image.into_raw();
            let icon = tray_icon::Icon::from_rgba(rgba, width, height).unwrap();

            let _ = tray_icon.get_or_init(|| {
                Some(
                    TrayIconBuilder::new()
                        .with_tooltip(format!("ModsBeforeFriday {:?}", launch_args).as_str())
                        .with_icon(icon)
                        .with_menu(Box::new(tray_menu.clone()))
                        .build()
                        .unwrap(),
                )
            });

            #[cfg(target_os = "macos")]
            unsafe {
                use core_foundation::runloop::{CFRunLoopGetMain, CFRunLoopWakeUp};
                let rl = CFRunLoopGetMain();
                CFRunLoopWakeUp(rl);
            }
        }

        if let Ok(event) = menu_receiver.try_recv() {
            if event.id == menu_open.id() {
                start_browser(&browser_url);
                return;
            }
            if event.id == menu_auto_run.id() {
                if auto_launch.is_enabled().unwrap() {
                    auto_launch.disable().unwrap();
                } else {
                    auto_launch.enable().unwrap();
                }
                menu_auto_run.set_checked(auto_launch.is_enabled().unwrap());
                return;
            }
            if event.id == menu_quit.id() {
                let mut event_loop_running = event_loop_running.as_ref().lock().unwrap();
                *event_loop_running = false;

                return;
            }
        }

        #[cfg(windows)]
        let _ = {
            if let Ok(TrayIconEvent::DoubleClick {
                id: _,
                position: _,
                rect: _,
                button: tray_icon::MouseButton::Left,
            }) = tray_receiver.try_recv()
            {
                start_browser(&browser_url);
                return;
            }
        };

        return;
    });
}
