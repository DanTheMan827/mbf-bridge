#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    env, io::{self, Write}, process::{exit, Stdio}, sync::{Arc, Mutex, OnceLock}, time::{Duration, Instant}
};

use auto_launch::AutoLaunchBuilder;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Request, WebSocketUpgrade,
    },
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use http::{Method, StatusCode};
use reqwest::Url;
use tao::event_loop::{EventLoopBuilder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command, signal,
};
use tower_http::cors::CorsLayer;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};

async fn adb_start(path: &str) -> tokio::io::Result<()> {
    let mut command = Command::new(path);
    command.args(&["server", "nodaemon"]);
    command.env("ADB_MDNS_OPENSCREEN", "1");
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let mut process = command.spawn()?;
    tokio::spawn(async move { process.wait().await });
    Ok(())
}

async fn adb_connect() -> tokio::io::Result<TcpStream> {
    TcpStream::connect("127.0.0.1:5037").await
}

async fn adb_connect_retry() -> tokio::io::Result<TcpStream> {
    let mut i = 0;
    loop {
        match adb_connect().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if i == 10 {
                    return Err(err);
                } else {
                    i += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

async fn adb_connect_or_start() -> tokio::io::Result<TcpStream> {
    if let Ok(stream) = adb_connect().await {
        return Ok(stream);
    }

    if adb_start("adb").await.is_ok() {
        return adb_connect_retry().await;
    }

    #[cfg(windows)]
    {
        use tokio::fs::write;

        let tmp_dir = env::temp_dir();
        let adb_path = tmp_dir.join("adb.exe");

        write(&adb_path, include_bytes!("../adb/win/adb.exe"))
            .await
            .unwrap();
        write(
            tmp_dir.join("AdbWinApi.dll"),
            include_bytes!("../adb/win/AdbWinApi.dll"),
        )
        .await
        .unwrap();
        write(
            tmp_dir.join("AdbWinUsbApi.dll"),
            include_bytes!("../adb/win/AdbWinUsbApi.dll"),
        )
        .await
        .unwrap();

        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        adb_connect_retry().await
    }

    #[cfg(target_os = "linux")]
    {
        use tokio::fs::write;

        let tmp_dir = env::temp_dir();
        let adb_path = tmp_dir.join("adb");

        use std::os::unix::fs::PermissionsExt;
        write(&adb_path, include_bytes!("../adb/linux/adb"))
            .await
            .unwrap();
        std::fs::set_permissions(&adb_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        adb_start(adb_path.to_str().unwrap()).await.unwrap();
        adb_connect_retry().await
    }

    #[cfg(target_os = "macos")]
    {
        adb_start(
            env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .join("adb")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        adb_connect_retry().await
    }
}

fn start_browser(url: String) {
    open::that_detached(url).unwrap();
}

async fn handle_websocket(ws: WebSocket) {
    let (mut ws_writer, mut ws_reader) = ws.split();

    let (mut adb_reader, mut adb_writer) = adb_connect_or_start().await.unwrap().into_split();

    tokio::join!(
        async {
            while let Some(Ok(message)) = ws_reader.next().await {
                // Don't merge with `if` above to ignore other message types
                if let Message::Binary(packet) = message {
                    adb_writer.write_all(packet.as_ref()).await.unwrap();
                }
            }
            adb_writer.shutdown().await.unwrap();
        },
        async {
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match adb_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        ws_writer.close().await.unwrap();
                        break;
                    }
                    Ok(n) => ws_writer
                        .send(Message::binary(buf[..n].to_vec()))
                        .await
                        .unwrap(),
                }
            }
        }
    );
}


static PROXY_HOST: OnceLock<String> = OnceLock::new();

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

#[axum::debug_handler]
async fn redirect_request(request: Request) -> Result<Response, Response> {
    // 302 Redirect to the PROXY_HOST
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", PROXY_HOST.get().unwrap())
        .body(axum::body::Body::empty())
        .unwrap();
    Ok(response)
}

/// URL encodes a string.
fn url_encode(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
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

fn extract_origin(app_url: &str) -> Option<String> {
    let url_parts: Vec<&str> = app_url.split("//").collect();
    if url_parts.len() == 2 {
        let scheme = url_parts[0]; // "http:" or "https:"
        let host_and_port = url_parts[1].split('/').next()?; // Extract host and port part
        return Some(format!("{}//{}", scheme, host_and_port));
    }
    None
}

const ARG_AUTO_RUN: &str = "--auto-run";

#[tokio::main]
async fn main() {

    let mut port = 25037;
    let mut run_persistent = true;
    let mut app_url = "https://dantheman827.github.io/ModsBeforeFriday/";
    let mut dev_mode = false;
    let mut game_id = "com.beatgames.beatsaber";
    let mut open_browser = false;

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check for specific arguments
    if args.contains(&"--help".to_string()) {
        let help_message = [
            format!("Usage: {} [OPTIONS]", env::current_exe().unwrap().file_name().unwrap().to_string_lossy()).as_str(),
            "",
            "Options:",
            "  --help              Show this help message",
            "  --port <PORT>       Specify a custom port for the server (default: 25037, or 0 if not persistent)",
            "  --persistent        Keep the server running after the browser is closed",
            "  --url <URL>         Specify a custom URL for the MBF app (default: https://mbf.bsquest.xyz/)",
            "  --open-browser      Open the browser automatically after starting the server (implied if not persistent)",
            "",
            "Development Options:",
            "  --dev               Enable development mode (adds 'dev=true' to the query string)",
            "  --game <ID>         Specify a custom game ID for the MBF app (default: com.beatgames.beatsaber)",
            "",
            "Behavior:",
            "  If --persistent is not specified:",
            "    - The server will shut down after 10 seconds of inactivity.",
            "    - The browser will open automatically (--open-browser is implied).",
            "    - The server will use a random port (--port 0 is implied).",
        ].join("\n");

        #[cfg(not(windows))]
        {
            println!("{}", help_message);
        }

        #[cfg(windows)]
        {
            use std::ptr::null_mut;
            use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONINFORMATION};
            use winapi::shared::ntdef::LPCWSTR;

            // Convert the Rust string to a wide string (UTF-16)
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

    open_browser = args.contains(&"--open-browser".to_string());
    run_persistent = args.contains(&"--persistent".to_string());
    dev_mode = args.contains(&"--dev".to_string());

    // Check for custom URL argument
    if args.contains(&"--url".to_string()) {
        // Parse and set the URL
        if let Some(index) = args.iter().position(|x| x == "--url") {
            if let Some(url_str) = args.get(index + 1) {
                app_url = url_str;
            }
        }
    }

    // Check for custom port argument
    if args.contains(&"--port".to_string()) {
        // Parse and set the port number
        if let Some(index) = args.iter().position(|x| x == "--port") {
            if let Some(port_str) = args.get(index + 1) {
                if let Ok(port_num) = port_str.parse::<u16>() {
                    port = port_num;
                }
            }
        }
    }

    // Check for custom game ID argument
    if args.contains(&"--game".to_string()) {
        // Parse and set the game ID
        if let Some(index) = args.iter().position(|x| x == "--game") {
            if let Some(game_id_str) = args.get(index + 1) {
                game_id = game_id_str;
            }
        }
    }

    // If not running persistently, always open the browser, and always use a random port
    if !run_persistent {
        open_browser = true;
        port = 0;
    }

    // Check if ADB server is running and start it if not.
    tokio::spawn(async { adb_connect_or_start().await.unwrap() });

    // Track the last request time
    let last_request_time = Arc::new(Mutex::new(Instant::now()));

    // Middleware-like function to update `last_request_time`
    let last_request_time_clone = Arc::clone(&last_request_time);
    let update_last_request_time = move |req: Request, next: axum::middleware::Next| {
        let last_request_time_clone = Arc::clone(&last_request_time_clone);
        async move {
            *last_request_time_clone.lock().unwrap() = Instant::now();
            next.run(req).await
        }
    };

    let mut allowed_origins = vec![
        "http://localhost:3000",
        "https://localhost:3000",
        "https://mbf.bsquest.xyz",
    ];

    let app_origin = extract_origin(app_url).unwrap();
    let app_origin = app_origin.as_str();

    if !allowed_origins.contains(&app_origin) {
        allowed_origins.push(app_origin);
    }

    // Log the allowed origins
    println!("Allowed Origins: {:?}", allowed_origins);

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
                        .allow_origin(allowed_origins.iter().map(|x| x.parse().unwrap()).collect::<Vec<_>>())
                        .allow_private_network(true),
                ),
        )
        .fallback(redirect_request)
        .layer(axum::middleware::from_fn(update_last_request_time)); // Apply middleware-like function globally

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let local_addr = listener.local_addr().unwrap();
    let assigned_ip = local_addr.ip().to_string();
    let assigned_port = local_addr.port();
    let assigned_url = format!("http://{}:{}", assigned_ip, assigned_port);
    let mut query_strings: Vec<(&str, String)> = vec![];

    if dev_mode {
        query_strings.push(("dev", "true".to_string()));
    }

    if game_id != "com.beatgames.beatsaber" {
        query_strings.push(("game", game_id.to_string()));
    }

    query_strings.push(("bridge", format!("{}:{}", assigned_ip, assigned_port)));

    let mut browser_url = app_url.to_string();

    if query_strings.len() > 0 {
        browser_url.push_str("?");
        for (key, value) in query_strings {
            browser_url.push_str(key);
            browser_url.push_str("=");
            browser_url.push_str(&url_encode(&value));
            browser_url.push_str("&");
        }
        browser_url.pop();
    }

    let browser_url = browser_url;
    PROXY_HOST.get_or_init(|| app_url.to_string());

    println!("Server is running: {}", assigned_url);

    if open_browser {
        start_browser(browser_url.clone());
    }

    // Create a shutdown signal
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        println!("Shutdown signal received. Cleaning up...");
    };

    tokio::spawn(async {
        tokio::select! {
            _ = axum::serve(listener, app) => {},
            _ = shutdown_signal => {
                println!("Server is shutting down...");
                exit(0);
            },
        }
    });

    // Background task to monitor inactivity
    if !run_persistent {
        let last_request_time_clone = Arc::clone(&last_request_time);
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let elapsed = last_request_time_clone.lock().unwrap().elapsed();
            if elapsed > Duration::from_secs(10) {
                println!("No requests received in the last 10 seconds. Shutting down...");
                exit(0);
            }
        }
    }

    let menu_open = MenuItem::new("Open", true, None);

    let auto_launch = AutoLaunchBuilder::new()
        .set_app_name("Tango")
        .set_app_path(env::current_exe().unwrap().to_str().unwrap())
        .set_args(&[ARG_AUTO_RUN])
        .set_use_launch_agent(true)
        .build()
        .unwrap();
    let menu_auto_run = CheckMenuItem::new(
        "Run at startup",
        true,
        auto_launch.is_enabled().unwrap(),
        None,
    );

    let menu_quit = MenuItem::new("Quit", true, None);

    let tray_menu = Menu::new();
    tray_menu
        .append_items(&[
            &menu_open,
            &menu_auto_run,
            &PredefinedMenuItem::separator(),
            &menu_quit,
        ])
        .unwrap();

    let menu_receiver = MenuEvent::receiver();
    let tray_receiver = TrayIconEvent::receiver();

    let mut tray_icon = None;

    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::new().build();

    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::EventLoopExtMacOS;

        // https://github.com/glfw/glfw/issues/1552
        event_loop.set_activation_policy(tao::platform::macos::ActivationPolicy::Accessory);
    }

    println!("Starting main loop");

    event_loop.run(move |event, _, control_flow| {
        *control_flow =
            tao::event_loop::ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(16));

        if let tao::event::Event::Reopen { .. } = event {
            start_browser(browser_url.clone());
            return;
        }

        if let tao::event::Event::NewEvents(tao::event::StartCause::Init) = event {
            let image = image::load_from_memory_with_format(
                include_bytes!("../tango.png"),
                image::ImageFormat::Png,
            )
            .unwrap()
            .into_rgba8();
            let (width, height) = image.dimensions();
            let rgba = image.into_raw();
            let icon = tray_icon::Icon::from_rgba(rgba, width, height).unwrap();

            tray_icon = Some(
                TrayIconBuilder::new()
                    .with_tooltip("Tango (rs)")
                    .with_icon(icon)
                    .with_menu(Box::new(tray_menu.clone()))
                    .build()
                    .unwrap(),
            );

            #[cfg(target_os = "macos")]
            unsafe {
                use core_foundation::runloop::{CFRunLoopGetMain, CFRunLoopWakeUp};

                let rl = CFRunLoopGetMain();
                CFRunLoopWakeUp(rl);
            }
        }

        if let Ok(event) = menu_receiver.try_recv() {
            if event.id == menu_open.id() {
                start_browser(browser_url.clone());
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
                tray_icon.take();
                *control_flow = tao::event_loop::ControlFlow::Exit;
                return;
            }
        }

        if let Ok(TrayIconEvent::Click {
            button: tray_icon::MouseButton::Left,
            button_state: tray_icon::MouseButtonState::Down,
            ..
        }) = tray_receiver.try_recv()
        {
            start_browser(browser_url.clone());
            return;
        }
    });
}
