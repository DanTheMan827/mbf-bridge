/// Default IP for the server.
pub const DEFAULT_IP: &str = "127.0.0.1";

/// Default port for the server.
pub const DEFAULT_PORT: u16 = 25037;

/// Default URL for the MBF app.
pub const DEFAULT_URL: &str = "https://dantheman827.github.io/ModsBeforeFriday/";

/// Default game ID for the MBF app.
pub const DEFAULT_GAME_ID: &str = "com.beatgames.beatsaber";

pub const DEFAULT_PROXY: bool = cfg!(target_os = "macos");

/// Argument to automatically start the server without a tray icon.
pub const AUTO_START_ARG: &str = "--no-browser";
