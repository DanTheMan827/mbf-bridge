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

mod config;
mod adb;
mod utils;
mod browser;
mod server;
mod server_info;
mod console;

use crate::adb::adb_connect_or_start;
use crate::utils::extract_origin;
use crate::server_info::ServerInfo;
use browser::start_browser;
use clap::{arg, command, CommandFactory, Parser};
use config::{AUTO_START_ARG, DEFAULT_GAME_ID, DEFAULT_IP, DEFAULT_PORT, DEFAULT_PROXY, DEFAULT_URL};
use server::router_instance::get_router_instance;
use urlencoding::encode as url_encode;
use serde::Serialize;
use lazy_static::lazy_static;

#[cfg(not(target_os = "android"))]
use auto_launch::AutoLaunchBuilder;

use reqwest::Url;

#[cfg(not(target_os = "android"))]
use single_instance::SingleInstance;

use std::{
    process::exit, sync::{Arc, Mutex}, time::Duration
};

#[cfg(not(target_os = "android"))]
use std::{
    sync::OnceLock, time::Instant
};

#[cfg(not(target_os = "android"))]
use std::env;

#[cfg(not(target_os = "android"))]
use tao::event_loop::EventLoopBuilder;

#[cfg(not(target_os = "android"))]
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};

#[cfg(not(target_os = "android"))]
#[cfg(not(target_os = "macos"))]
use tray_icon::TrayIconEvent;

#[derive(Parser, Debug, Serialize, Clone)]
#[command(version, about, long_about = None, disable_help_flag = true)]
struct Args {
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Automatically exit the bridge after 10 seconds of inactivity
    #[arg[long, default_value_t = false]]
    auto_close: bool,

    /// Specify a custom URL for the MBF app
    #[arg[long, default_value_t = DEFAULT_URL.to_owned()]]
    url: String,

    /// Proxy requests through the internal server to avoid mixed content errors
    #[arg[long, default_value_t = DEFAULT_PROXY, hide = cfg!(target_os = "macos")]]
    proxy: bool,

    /// Allocate a console window to display logs
    #[arg[long, default_value_t = false, hide = cfg!(not(windows)) || cfg!(debug_assertions)]]
    console: bool,

    /// Start the server without automatically opening the browser
    #[arg(long = AUTO_START_ARG.strip_prefix("--"), hide = cfg!(target_os = "android"), default_value_t = cfg!(target_os = "android"))]
    no_browser: bool,

    /// The port that the adb server is running on
    #[arg[long, default_value_t = 5037]]
    adb_port: u16,

    /// Output the startup information as JSON
    #[arg[long, default_value_t = false, help_heading = "Development Options"]]
    output_json: bool,

    /// Enable MBF development mode
    #[arg[long = "dev", default_value_t = false, help_heading = "Development Options"]]
    dev_mode: bool,

    /// Specify a custom game ID for the MBF app
    #[arg[long, default_value_t = DEFAULT_GAME_ID.to_owned(), help_heading = "Development Options"]]
    game_id: String,

    /// Ignore the package ID check during qmod installation
    #[arg[long, default_value_t = false, help_heading = "Development Options"]]
    ignore_package_id: bool,

    /// Additional HTTP origins to allow for CORS
    #[arg[long = "origin", name = "ORIGIN", help_heading = "Development Options"]]
    additional_origins: Vec<String>,

    /// The IP address to bind the server to
    #[arg[long, default_value = DEFAULT_IP, help_heading = "Development Options"]]
    bind_ip: String,

    /// Print help
    #[arg[long, short]]
    help: bool,
}

/// Struct to hold startup information for JSON output.
#[derive(Serialize, Clone)]
struct StartupInfo {
    allowed_origins: Vec<String>,
    server_url: String,
    browser_url: String,
    args: Args,
}

/// A generic struct representing a message with a type key.
#[derive(Debug, Serialize, Clone)]
struct Message<T> {
    message_type: String,
    payload: T,
}

impl<T> Message<T> {
    /// Creates a new message with the given payload.
    /// The `message_type` is automatically set to the name of the type `T`.
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

impl ErrorMessage {
    /// Creates a new standard message with the given message.
    fn from_str(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }

    /// Creates a new standard message from a string.
    fn from_string(message: String) -> Self {
        Self { message }
    }
}

#[derive(Debug, Serialize, Clone)]
struct StandardMesage {
    message: String,
}

impl StandardMesage {
    /// Creates a new standard message with the given message.
    fn from_str(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }

    /// Creates a new standard message from a string.
    fn from_string(message: String) -> Self {
        Self { message }
    }
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
}

pub fn eprint_message(message: &str) {
    if (ARGS.output_json) {
        let json = serde_json::to_string(&Message::new(ErrorMessage::from_str(message))).unwrap();
        println!("{}", json);
    } else {
        eprintln!("{}", message);
    }
}

pub fn print_message(message: &str) {
    if (ARGS.output_json) {
        let json = serde_json::to_string(&Message::new(StandardMesage::from_str(message))).unwrap();
        println!("{}", json);
    } else {
        println!("{}", message);
    }
}

/// Entry point of the application.
#[tokio::main]
async fn main() {
    // ------------------------------
    // Configuration and Command-Line Parsing
    // ------------------------------
    #[cfg(not(target_os = "android"))]
    let launch_args: Vec<String> = env::args().into_iter()
        .skip(1)
        .filter(|item| **item != config::AUTO_START_ARG.to_owned())
        .collect();

    let mut port = ARGS.port;
    let run_persistent = !ARGS.auto_close;
    let app_url = ARGS.url.as_str();
    let dev_mode = ARGS.dev_mode;
    let ignore_package_id = ARGS.ignore_package_id;
    let game_id = ARGS.game_id.as_str();
    let mut open_browser = !ARGS.no_browser;
    let proxy_requests = ARGS.proxy;
    let _ = adb::ADB_PORT.set(ARGS.adb_port);

    // Allocate a console window if requested or needed.
    #[cfg(not(debug_assertions))]
    #[cfg(windows)]
    let allocated_console = (ARGS.console || ARGS.help) && console::allocate_console();

    // Display help message if requested.
    if ARGS.help {
        let mut cmd = Args::command();
        let help = cmd.render_help().to_string();


        #[cfg(not(debug_assertions))]
        #[cfg(windows)]
        {
            use std::io;
            if allocated_console {
                print_message("Press Enter to exit...");
                let _ = io::stdin().read_line(&mut String::new());
            }
        }

        print_message(&help);

        return;
    }

    // If running in auto-close mode, force browser open and use a random port.
    if !run_persistent {
        open_browser = true;
        port = 0;
    }

    // ------------------------------
    // App Title
    // ------------------------------
    #[cfg(not(target_os = "android"))]
    let app_title: &str = if launch_args.len() > 0 {
        Box::leak(format!("ModsBeforeFriday Bridge {:?}", launch_args).into_boxed_str())
    } else {
        "ModsBeforeFriday Bridge"
    };

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


    // Determine allowed origins for CORS.
    let app_origin = extract_origin(app_url).unwrap();
    let allowed_origins = {
        let mut allowed_origins = vec![
            "http://localhost:3000",
            "https://localhost:3000",
            "https://mbf.bsquest.xyz",
        ];

        if !allowed_origins.contains(&app_origin.as_str()) {
            allowed_origins.push(app_origin.as_str());
        }

        let additional_origins: &Vec<String> = ARGS.additional_origins.as_ref();
        if additional_origins.len() > 0 {
            for origin in additional_origins {
                if !allowed_origins.contains(&origin.as_str()) {
                    allowed_origins.push(Box::leak(origin.clone().into_boxed_str()));
                }
            }
        }

        allowed_origins
    };

    // ------------------------------
    // Single Instance Check
    // ------------------------------
    #[cfg(not(target_os = "android"))]
    let single_instance = SingleInstance::new(app_title).unwrap().is_single();

    #[cfg(target_os = "android")]
    let single_instance = true;

    // Bind the server listener.
    let server_info = ServerInfo::new(single_instance, ARGS.bind_ip.to_string(), Some(port)).await;

    // Assign the browser URL with query parameters.
    let browser_url = {
        let mut browser_url = app_url.to_string();

        // If proxying requests, set browser URL to the local server with the path from app_url preserved.
        if proxy_requests {
            // Parse the app URL with the Url crate and extract the path
            let mut app_url = Url::parse(app_url).unwrap();
            app_url.set_scheme("http").unwrap();
            app_url.set_host(Some(server_info.assigned_ip.as_str())).unwrap();
            app_url.set_port(Some(server_info.assigned_port)).unwrap();
            browser_url = app_url.to_string();
        }

        // Build query string parameters for the browser URL.
        let mut query_strings: Vec<(&str, String)> = Vec::new();
        if dev_mode {
            query_strings.push(("dev", "true".to_string()));
        }
        if game_id != config::DEFAULT_GAME_ID {
            query_strings.push(("game_id", url_encode(game_id).into_owned()));
        }
        if server_info.assigned_port != config::DEFAULT_PORT || server_info.assigned_ip != config::DEFAULT_IP {
            if proxy_requests {
                query_strings.push(("bridge", "".to_owned()));
            } else {
                query_strings.push(("bridge", format!("{}:{}", server_info.assigned_ip, server_info.assigned_port)));
            }
        }

        if ignore_package_id {
            query_strings.push(("ignore_package_id", "true".to_string()));
        }

        // Append query strings to the browser URL.
        if !query_strings.is_empty() {
            browser_url.push('?');
            for (key, value) in query_strings {
                browser_url.push_str(key);
                browser_url.push('=');
                browser_url.push_str(&url_encode(&value).to_owned());
                browser_url.push('&');
            }
            browser_url.pop(); // Remove trailing '&'
        }

        browser_url
    };

    // Setup the router instance.
    let (app, last_request_time) = get_router_instance(allowed_origins.clone(), app_url.to_string());

    // Log the startup information.
    if ARGS.output_json {
        let startup_info = StartupInfo {
            allowed_origins: allowed_origins.iter().map(|s| s.to_string()).collect(),
            server_url: server_info.assigned_url.clone(),
            browser_url: browser_url.clone(),
            args: ARGS.clone(),
        };
        let json = serde_json::to_string(&Message::<StartupInfo>::new(startup_info)).unwrap();
        println!("{}", json);
    } else {
        println!("Allowed Origins: {:?}", allowed_origins);
        println!("Server is running: {}", server_info.assigned_url);
        println!("Browser URL: {}", browser_url);
    }

    // Set the global proxy host.
    let browser_url = Arc::new(browser_url);

    if !single_instance && port > 0 {
        let _ = start_browser(&browser_url).await;

        return;
    }

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

            #[cfg(not(unix))]
            {
                loop {
                    tokio::time::sleep(Duration::from_millis(16)).await;
                }
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
            let listener = server_info.listener.unwrap();
            tokio::spawn(async move {
                tokio::select! {
                    _ = axum::serve(listener, app) => {
                        eprint_message("Server ended, this shouldn't happen.");
                        exit(1);
                    },
                    _ = shutdown_signal => print_message("Shutdown signal received."),
                    _ = unix_hup_signal => print_message("SIGHUP signal received."),
                    _ = idle_check => print_message("No requests received in the last 10 seconds."),
                    _ = event_loop_check => print_message("Event loop ended.")
                }
            })
        };

        {
            tokio::spawn(async move {
                let _ = server.await;

                print_message("Exiting...");
                exit(0);
            })
        }
    };

    // ------------------------------
    // System Tray and Event Loop
    // ------------------------------
    #[allow(unused_mut)]
    #[cfg(not(target_os = "android"))]
    let mut event_loop = EventLoopBuilder::new().build();

    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::EventLoopExtMacOS;

        // https://github.com/glfw/glfw/issues/1552
        event_loop.set_activation_policy(tao::platform::macos::ActivationPolicy::Accessory);
    }

    if cfg!(target_os = "android") || !run_persistent.as_ref() {
        #[cfg(target_os = "android")]
        {
            loop {
                tokio::time::sleep(Duration::from_millis(16)).await;
            }
        }

        #[cfg(not(target_os = "android"))]
        {
            event_loop.run(move |_, _, control_flow| {
                *control_flow =
                    tao::event_loop::ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(16));
            });
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        // Create the open menu item.
        let menu_open = MenuItem::new("Open", true, None);

        // Create the auto-launch configuration.
        let auto_launch = {
            // Clone the launch arguments and add the auto-close flag.
            let mut auto_launch_args = launch_args.clone();
            auto_launch_args.push(config::AUTO_START_ARG.to_string());

            // Create the auto-launch configuration.
            AutoLaunchBuilder::new()
                .set_app_name(app_title)
                .set_app_path(env::current_exe().unwrap().to_str().unwrap())
                .set_args(&auto_launch_args)
                .set_use_launch_agent(true)
                .build()
                .unwrap()
        };

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

        // Create the tray icon event receiver.
        #[cfg(windows)]
        let tray_receiver = TrayIconEvent::receiver();

        // Create the tray icon.
        let tray_icon: OnceLock<Option<TrayIcon>> = OnceLock::new();

        print_message("Starting event loop");
        event_loop.run(move |event, _, control_flow| {
            *control_flow =
                tao::event_loop::ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(16));

            if let tao::event::Event::Reopen { .. } = event {
                start_browser(&browser_url);
                return;
            }

            // Handle initialization events.
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
                            .with_tooltip(app_title)
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

            // Handle menu events.
            if let Ok(event) = menu_receiver.try_recv() {
                // Open the browser
                if event.id == menu_open.id() {
                    start_browser(&browser_url);
                    return;
                }

                // Toggle auto-run at startup
                if event.id == menu_auto_run.id() {
                    if auto_launch.is_enabled().unwrap() {
                        auto_launch.disable().unwrap();
                    } else {
                        auto_launch.enable().unwrap();
                    }
                    menu_auto_run.set_checked(auto_launch.is_enabled().unwrap());
                    return;
                }

                // Quit the application
                if event.id == menu_quit.id() {
                    let mut event_loop_running = event_loop_running.as_ref().lock().unwrap();
                    *event_loop_running = false;

                    return;
                }
            }

            // Handle tray icon double-click.
            #[cfg(windows)]
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

            return;
        });
    }
}
