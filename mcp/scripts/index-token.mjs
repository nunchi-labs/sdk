/**
 * Local INDEX_TOKEN shared by `wrangler dev` (.dev.vars) and `just mcp-index`.
 *
 *   node scripts/index-token.mjs
 */

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const devVarsPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.dev.vars");

function tokenFromDevVars(text) {
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("INDEX_TOKEN=")) {
      continue;
    }
    return unquote(trimmed.slice("INDEX_TOKEN=".length).trim());
  }
  return "";
}

function unquote(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

export function readIndexToken() {
  if (process.env.INDEX_TOKEN) {
    return process.env.INDEX_TOKEN;
  }
  if (!existsSync(devVarsPath)) {
    return "";
  }
  return tokenFromDevVars(readFileSync(devVarsPath, "utf8"));
}

function ensureIndexToken() {
  const existing = existsSync(devVarsPath) ? readFileSync(devVarsPath, "utf8") : "";
  if (/^INDEX_TOKEN=/m.test(existing)) {
    return;
  }
  const token = randomBytes(32).toString("hex");
  const prefix = existing.length === 0 || existing.endsWith("\n") ? existing : `${existing}\n`;
  writeFileSync(devVarsPath, `${prefix}INDEX_TOKEN=${token}\n`, { mode: 0o600 });
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedDirectly) {
  ensureIndexToken();
}
