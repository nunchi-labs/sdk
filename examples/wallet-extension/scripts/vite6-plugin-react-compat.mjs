// @vitejs/plugin-react 6 imports `vite/internal` at load time. Vite 8 exports
// that subpath (Rolldown's React refresh wrapper). Vite 6.4.5 does not, so
// vitest fails while loading vite.config.ts. The wallet stays on Vite 6.4.5.
// Point the missing subpath at a no-op wrapper so the plugin can load.
// Production JSX still goes through Vite 6's esbuild.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vitePkgPath = join(root, "node_modules/vite/package.json");

let raw;
try {
  raw = readFileSync(vitePkgPath, "utf8");
} catch (error) {
  if (error && error.code === "ENOENT") process.exit(0);
  throw error;
}

const pkg = JSON.parse(raw);
const version = String(pkg.version ?? "");
if (!version.startsWith("6.") || pkg.exports?.["./internal"]) {
  process.exit(0);
}

const shimRel = "./dist/node/internal-compat.js";
writeFileSync(
  join(root, "node_modules/vite/dist/node/internal-compat.js"),
  `export function reactRefreshWrapperPlugin() {
  return { name: "vite:react-refresh-wrapper-compat" };
}
`,
);

pkg.exports["./internal"] = shimRel;
writeFileSync(vitePkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
