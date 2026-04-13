import { defineConfig, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
//
// Two build modes are supported, selected by the --mode flag:
//
//   vite build              (mode = "production", default)
//     - terser minifier, two compression passes
//     - all console.* and debugger statements stripped
//     - top-level name mangling across the whole bundle
//     - module-preload polyfill omitted (Tauri's WebView natively supports it)
//     - Rollup "recommended" treeshake preset (honours /*#__PURE__*/ annotations)
//     - no source maps
//
//   vite build --mode debug
//     - no minification (bundle stays readable)
//     - full source maps written alongside every output file
//
export default defineConfig(({ mode }): UserConfig => {
  const isDebug = mode === "debug";

  return {
    plugins: [react()],
    // Set base to "/" so all asset paths are absolute — required because the
    // embedded `mbf://` protocol serves files from the include_dir root.
    base: "/",
    build: {
      outDir: "dist",
      emptyOutDir: true,

      // Full source maps in debug; none in release.
      sourcemap: isDebug,

      // The module-preload polyfill (~1 KB) is unnecessary: Tauri's WebView
      // (Chromium on Windows/Linux, WKWebView on macOS) natively supports
      // <link rel="modulepreload">, so we can safely omit it.
      modulePreload: { polyfill: false },

      // Debug: skip minification so the bundle remains readable and debuggable.
      // Release: terser for maximum output reduction.
      minify: isDebug ? false : "terser",

      // Terser options are only relevant for release builds.
      ...(isDebug
        ? {}
        : {
            terserOptions: {
              compress: {
                // Two passes let terser find more opportunities after the
                // inlining and constant-folding done in the first pass.
                passes: 2,

                // Remove every console.* call and debugger statement so they
                // never reach production users.
                drop_console: true,
                drop_debugger: true,

                // Target ES2020: emit nullish-coalescing, optional chaining,
                // etc., matching our tsconfig target and Tauri's Chromium WebView.
                ecma: 2020,

                // Inform terser that all code is in ES-module scope, enabling
                // stricter analysis (implicit "use strict", no dynamic imports
                // at top-level, top-level bindings are not globals).
                module: true,

                // Safe rewrites for ES-module bundles running on modern engines.
                // Arrow functions and method shorthands are semantically
                // equivalent in strict-mode ES2020.
                unsafe_arrows: true,
                unsafe_methods: true,

                // Enable cross-statement analysis within each top-level scope;
                // combined with module:true this gives the best reduction.
                toplevel: true,
              },
              mangle: {
                // Mangle top-level binding names.  Everything inside the bundle
                // is scoped to the module, so there are no accidental globals.
                toplevel: true,
              },
              format: {
                // Strip all comments from the output, including licence headers
                // of bundled libraries.  Licences remain in node_modules and are
                // not distributed inside the compiled binary.
                comments: false,
              },
            },
          }),

      rollupOptions: {
        treeshake: {
          // Assume external packages have no side effects beyond their used
          // exports. This lets Rolldown (Vite 8's bundler) strip unused parts
          // of npm dependencies (e.g. React internals, xterm sub-modules).
          // Local module side effects are still preserved by default.
          moduleSideEffects: "no-external",
        },
      },
    },
  };
});
