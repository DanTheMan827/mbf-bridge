fn main() {
    // Build the React/Vite frontend before the Tauri build step so that
    // `include_bytes!("../ui/dist/index.html")` resolves correctly.
    let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui");

    // Install Node dependencies if they are missing.
    if !ui_dir.join("node_modules").exists() {
        let status = std::process::Command::new("npm")
            .arg("install")
            .current_dir(&ui_dir)
            .status()
            .expect("Failed to run `npm install` in ui/");
        assert!(status.success(), "`npm install` exited with {status}");
    }

    // Build the frontend bundle.
    let status = std::process::Command::new("npm")
        .args(["run", "build"])
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
