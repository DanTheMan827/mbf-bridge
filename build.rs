fn main() {
    // Build the React/Vite frontend before the Tauri build step so that
    // `include_bytes!("../ui/dist/index.html")` resolves correctly.
    let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui");

    // On Windows the npm wrapper is `npm.cmd`; on Unix it is plain `npm`.
    let npm = if cfg!(target_os = "windows") {
        "npm.cmd"
    } else {
        "npm"
    };

    // Install Node dependencies if they are missing.
    if !ui_dir.join("node_modules").exists() {
        let status = std::process::Command::new(npm)
            .arg("install")
            .current_dir(&ui_dir)
            .status()
            .expect("Failed to run `npm install` in ui/");
        assert!(status.success(), "`npm install` exited with {status}");
    }

    // Select the build script based on the Cargo profile:
    //   release → `npm run build`        (terser, no source maps)
    //   debug   → `npm run build:debug`  (no minification, full source maps)
    //
    // Cargo sets the PROFILE env var automatically for build scripts.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let build_script = if profile == "release" { "build" } else { "build:debug" };

    // Re-run this script when the Cargo profile changes (e.g. switching between
    // `cargo build` and `cargo build --release`).
    println!("cargo:rerun-if-env-changed=PROFILE");

    // Build the frontend bundle.
    let status = std::process::Command::new(npm)
        .args(["run", build_script])
        .current_dir(&ui_dir)
        .status()
        .expect("Failed to run `npm run build` in ui/");
    assert!(status.success(), "`npm run build` exited with {status}");

    // Re-run this build script when frontend source files change.
    println!("cargo:rerun-if-changed=ui/src");
    println!("cargo:rerun-if-changed=ui/index.html");
    println!("cargo:rerun-if-changed=ui/package.json");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.app.json");

    tauri_build::build();
}
