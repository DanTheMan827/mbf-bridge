import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Set base to "/" so all asset paths are absolute — required because the
  // embedded `mbf://` protocol serves files from the include_dir root.
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
