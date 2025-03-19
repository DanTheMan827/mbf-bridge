use crate::utils::locate_executable;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::process::Command;

/// Path to the Microsoft Edge executable.
static EDGE_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Path to the Google Chrome executable.
static CHROME_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Path to the Google Chrome executable (alternative name).
static GOOGLE_CHROME_PATH: OnceLock<Option<String>> = OnceLock::new();

/// Attempts to start a chromium-based browser in app mode with the specified URL.
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

/// Opens the default browser with the specified URL.
///
/// # Arguments
///
/// * `url` - The URL to open.
pub fn start_browser(url: &Arc<String>) -> tokio::task::JoinHandle<()> {
    let url = Arc::clone(&url);

    tokio::spawn(async move {
        if start_chromium_app(
            EDGE_PATH.get_or_init(|| locate_executable("msedge")),
            url.as_ref(),
        ) {
            return;
        }

        if start_chromium_app(
            CHROME_PATH.get_or_init(|| locate_executable("chrome")),
            url.as_ref(),
        ) {
            return;
        }

        if start_chromium_app(
            GOOGLE_CHROME_PATH.get_or_init(|| locate_executable("google-chrome")),
            url.as_ref(),
        ) {
            return;
        }

        open::that_detached(url.as_ref()).unwrap();
    })
}
