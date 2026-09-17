import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  publicDir: false,
  build: {
    emptyOutDir: false,
    outDir: "dist",
    lib: {
      entry: resolve(__dirname, "src/inpage.ts"),
      name: "nunchiWalletInpage",
      formats: ["iife"],
      fileName: () => "inpage.js",
    },
  },
});
