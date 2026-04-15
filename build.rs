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

    // Compress every file in ui/dist/ into ui/dist-gz/ with gzip level 9.
    // The compressed files are embedded in the binary via `include_dir!` to
    // reduce binary size.  serve_embedded() decompresses them on the Rust side
    // before returning responses (Tauri custom protocol handlers do not honour
    // Content-Encoding: gzip transparently).
    let dist_dir = ui_dir.join("dist");
    let dist_gz_dir = ui_dir.join("dist-gz");
    assert!(
        dist_dir.exists(),
        "ui/dist/ does not exist after npm build — check that `npm run {build_script}` succeeded"
    );
    compress_dir(&dist_dir, &dist_gz_dir);

    // Re-run this build script when frontend source files change.
    println!("cargo:rerun-if-changed=ui/src");
    println!("cargo:rerun-if-changed=ui/index.html");
    println!("cargo:rerun-if-changed=ui/package.json");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.app.json");

    tauri_build::build();
}

/// Recursively gzip-compress every file under `src` into a mirrored tree at
/// `dst`.  The destination directory is wiped clean before each run so stale
/// files from a previous build never linger.
fn compress_dir(src: &std::path::Path, dst: &std::path::Path) {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write as _;

    if dst.exists() {
        std::fs::remove_dir_all(dst).expect("failed to clear dist-gz/");
    }
    std::fs::create_dir_all(dst).expect("failed to create dist-gz/");

    for entry in std::fs::read_dir(src).expect("failed to read dist/") {
        let entry = entry
            .unwrap_or_else(|e| panic!("failed to read directory entry in {}: {e}", src.display()));
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            compress_dir(&src_path, &dst_path);
        } else {
            let data = std::fs::read(&src_path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", src_path.display()));
            let mut enc = GzEncoder::new(Vec::new(), Compression::best());
            enc.write_all(&data)
                .unwrap_or_else(|e| panic!("gzip write failed for {}: {e}", src_path.display()));
            let compressed = enc
                .finish()
                .unwrap_or_else(|e| panic!("gzip finish failed for {}: {e}", src_path.display()));
            std::fs::write(&dst_path, compressed)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", dst_path.display()));
        }
    }
}
