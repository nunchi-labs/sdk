import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  publicDir: false,
  build: {
    emptyOutDir: false,
    outDir: "dist",
    lib: {
      entry: resolve(__dirname, "src/content.ts"),
      name: "nunchiWalletContent",
      formats: ["iife"],
      fileName: () => "content.js",
    },
  },
});
