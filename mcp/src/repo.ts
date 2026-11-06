/**
 * Discover Nunchi SDK files and git refs for the local search index.
 *
 * `HEAD` is the working tree of the checkout (tracked files as they are on disk).
 * Every git tag is an additional immutable ref.
 */

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Skip files larger than this. D1 rows and tool responses stay bounded. */
export const MAX_INDEX_BYTES = 512 * 1024;

const INDEXABLE_EXTENSIONS = new Set([
  "rs",
  "md",
  "toml",
  "json",
  "jsonc",
  "yml",
  "yaml",
  "js",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "html",
  "css",
  "sh",
  "sql",
]);

const SKIP_BASENAMES = new Set(["Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]);

/**
 * Source, docs, and example text. Images, lockfiles, and build output are omitted.
 */
export function isIndexablePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.startsWith("../") || normalized.includes("/../") || normalized.startsWith("/")) {
    return false;
  }
  const parts = normalized.split("/");
  if (parts.some((part) => part === "node_modules" || part === "target" || part === ".git")) {
    return false;
  }
  const base = parts[parts.length - 1];
  if (SKIP_BASENAMES.has(base)) {
    return false;
  }
  if (base === "Justfile" || base === "Dockerfile" || base.startsWith("LICENSE")) {
    return true;
  }
  const dot = base.lastIndexOf(".");
  if (dot <= 0) {
    return false;
  }
  return INDEXABLE_EXTENSIONS.has(base.slice(dot + 1).toLowerCase());
}

/**
 * Resolve the SDK checkout. `REPO_ROOT` is relative to the `mcp/` directory,
 * which is the Wrangler working directory.
 */
export function resolveRepoRoot(repoRoot: string): string {
  return path.resolve(process.cwd(), repoRoot);
}

/** `HEAD` plus every local tag, with `HEAD` first. */
export async function listRepoRefs(repoRoot: string): Promise<string[]> {
  const { stdout } = await execFileAsync("git", ["tag", "--list"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const tags = stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return ["HEAD", ...tags];
}

/** Tracked, indexable paths for one ref. `HEAD` uses the working tree. */
export async function listRepoFiles(repoRoot: string, ref: string): Promise<string[]> {
  const args = ref === "HEAD" ? ["ls-files", "-z"] : ["ls-tree", "-r", "--name-only", "-z", ref];
  const { stdout } = await execFileAsync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return stdout.split("\0").filter((file) => file.length > 0 && isIndexablePath(file));
}

/**
 * Read one file. `HEAD` reads the working tree so uncommitted edits are indexed.
 * Other refs use `git show`, which is the tree recorded by that tag.
 */
export async function readRepoFile(
  repoRoot: string,
  ref: string,
  filePath: string
): Promise<string | null> {
  if (!isIndexablePath(filePath)) {
    return null;
  }
  if (ref === "HEAD") {
    const root = path.resolve(repoRoot);
    const full = path.resolve(root, filePath);
    if (full !== root && !full.startsWith(root + path.sep)) {
      return null;
    }
    try {
      const bytes = await readFile(full);
      if (bytes.length > MAX_INDEX_BYTES || bytes.includes(0)) {
        return null;
      }
      return bytes.toString("utf8");
    } catch {
      return null;
    }
  }

  try {
    const { stdout } = await execFileAsync("git", ["show", `${ref}:${filePath}`], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: MAX_INDEX_BYTES + 1,
    });
    if (stdout.length > MAX_INDEX_BYTES || stdout.includes("\u0000")) {
      return null;
    }
    return stdout;
  } catch {
    return null;
  }
}
