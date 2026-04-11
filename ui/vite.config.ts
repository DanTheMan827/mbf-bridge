import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Inline all JS and CSS into a single self-contained index.html so that
    // Rust can embed it with `include_bytes!("../ui/dist/index.html")`.
    viteSingleFile(),
  ],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
