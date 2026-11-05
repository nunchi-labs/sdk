#!/usr/bin/env node
/**
 * Index the Nunchi SDK checkout into a running MCP server.
 *
 * Reads HEAD (working tree) and every git tag, then posts file batches to
 * the Worker's /__index route, which stores them in D1.
 *
 *   just mcp-index
 *   MCP_URL=http://127.0.0.1:8787 node --experimental-strip-types scripts/index-repo.mjs
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { listRepoFiles, listRepoRefs, readRepoFile } from "../src/repo.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const baseUrl = process.env.MCP_URL || "http://127.0.0.1:8787";
const BATCH = 20;

async function post(body) {
  let response;
  try {
    response = await fetch(`${baseUrl}/__index`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not reach ${baseUrl}. Start the server with \`just mcp\` first. ${message}`
    );
  }
  if (!response.ok) {
    throw new Error(`index request failed (${response.status}): ${await response.text()}`);
  }
}

const refs = await listRepoRefs(repoRoot);
console.log(`Indexing ${repoRoot}`);
console.log(`Refs: ${refs.join(", ")}`);

for (const ref of refs) {
  const files = await listRepoFiles(repoRoot, ref);
  let stored = 0;
  let reset = true;
  if (files.length === 0) {
    await post({ op: "batch", version: ref, reset: true, files: [] });
  }
  for (let i = 0; i < files.length; i += BATCH) {
    const payload = [];
    for (const file of files.slice(i, i + BATCH)) {
      const content = await readRepoFile(repoRoot, ref, file);
      if (content !== null) {
        payload.push({ path: file, content });
      }
    }
    await post({ op: "batch", version: ref, reset, files: payload });
    reset = false;
    stored += payload.length;
  }
  console.log(`${ref}: ${stored} files`);
}

await post({ op: "prune", keep: refs });
console.log("Index complete. Tools default to HEAD.");
