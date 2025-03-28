/// Allocates a new console for the current process on Windows systems.
///
/// This function is only available on Windows and uses the `winapi` crate to
/// interact with the Windows API. It performs the following steps:
/// 1. Allocates a new console using `AllocConsole`.
/// 2. Redirects the standard output (`stdout`) and standard error (`stderr`)
///    to the newly allocated console.
///
/// # Errors
/// If the console allocation fails or if the redirection of `stdout` fails,
/// error messages are printed to the existing standard error.
///
/// # Safety
/// This function uses unsafe code to call Windows API functions. Ensure that
/// the environment is properly set up for these operations.
///
/// # Example
/// ```no_run
/// #[cfg(windows)]
/// fn main() {
///     allocate_console();
///     println!("This will be printed to the allocated console.");
/// }
/// ```
#[cfg(windows)]
pub fn allocate_console() -> bool {
    use std::io::{self, Write};
    use winapi::um::consoleapi::AllocConsole;
    use winapi::um::fileapi::CreateFileW;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::winbase::{STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    use winapi::um::winnt::GENERIC_READ;
    use winapi::um::winnt::GENERIC_WRITE;
    use winapi::um::processenv::SetStdHandle;
    use std::ptr::null_mut;

    use crate::eprint_message;

    unsafe {
        // Allocate a new console
        if AllocConsole() == 0 {
            eprint_message("Failed to allocate console");
            return false;
        }

        // Redirect stdout to the console
        let stdout_handle = CreateFileW(
            "CONOUT$\0".encode_utf16().collect::<Vec<u16>>().as_ptr(),
            GENERIC_WRITE | GENERIC_READ,
            0,
            null_mut(),
            3, // OPEN_EXISTING
            0,
            null_mut(),
        );

        if stdout_handle != INVALID_HANDLE_VALUE {
            SetStdHandle(STD_OUTPUT_HANDLE, stdout_handle);
            SetStdHandle(STD_ERROR_HANDLE, stdout_handle);
            let _ = io::stdout().flush(); // Ensure stdout is flushed
        } else {
            eprint_message("Failed to redirect stdout");
        }
    }

    return true;
}
