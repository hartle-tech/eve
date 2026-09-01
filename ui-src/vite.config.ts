import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built into ../ui, which is what Tauri embeds. Keeping the output in the
// repo means the .app can still be assembled from a checkout without anyone
// having run npm — the build step is only needed to *change* the frontend.
export default defineConfig({
  plugins: [react()],
  // Relative, so the bundle loads from Tauri's custom protocol and from a
  // plain file:// — the second is how the UI gets driven headlessly without
  // rebuilding the .app for every change.
  base: "./",
  build: {
    outDir: "../ui",
    emptyOutDir: true,
    // One file each. The bundle is small, and a single pair keeps the
    // headless harness able to inject its stub before the app script.
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app.js",
        assetFileNames: "[name][extname]",
      },
    },
  },
});
