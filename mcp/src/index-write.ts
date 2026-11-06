import type { Env } from "./env.d.ts";
import { isValidPath } from "./utils.ts";

const INDEX_BUILD_BATCH_SIZE = 20; // D1 has 100 bind param limit, 20 rows × 3 cols = 60

interface IndexFile {
  path: string;
  content: string;
}

type IndexRequest =
  | { op: "batch"; version: string; reset: boolean; files: IndexFile[] }
  | { op: "prune"; keep: string[] };

// Git tags may contain slashes (`release/1.0`). Reject traversal, empty
// segments, and characters git itself refuses in a ref name.
function isSafeRef(ref: string): boolean {
  if (ref.length === 0 || ref.length >= 200 || ref.includes("..")) {
    return false;
  }
  return /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(ref);
}

// Write one batch of this repository into D1. `just mcp-index` reads git in Node
// (the Worker isolate cannot spawn git) and posts batches here. The first batch
// for a ref sets `reset` so HEAD is replaced with the current working tree.
async function applyIndex(env: Env, body: IndexRequest): Promise<{ files: number }> {
  const session = env.SEARCH_DB.withSession("first-primary");

  if (body.op === "prune") {
    const indexed = await session
      .prepare("SELECT version FROM versions")
      .all<{ version: string }>();
    const keep = new Set(body.keep.filter(isSafeRef));
    for (const row of indexed.results) {
      if (!keep.has(row.version)) {
        await session.batch([
          session.prepare("DELETE FROM versions WHERE version = ?").bind(row.version),
          session.prepare("DELETE FROM files WHERE version = ?").bind(row.version),
        ]);
      }
    }
    return { files: 0 };
  }

  if (!isSafeRef(body.version)) {
    throw new Error(`invalid ref '${body.version}'`);
  }
  if (body.reset) {
    await session.prepare("DELETE FROM files WHERE version = ?").bind(body.version).run();
  }

  const files = body.files.filter(
    (file) =>
      isValidPath(file.path) &&
      typeof file.content === "string" &&
      file.content.length <= 512 * 1024
  );
  for (let i = 0; i < files.length; i += INDEX_BUILD_BATCH_SIZE) {
    const batch = files.slice(i, i + INDEX_BUILD_BATCH_SIZE);
    const placeholders = batch.map(() => "(?, ?, ?)").join(", ");
    const params = batch.flatMap((file) => [body.version, file.path, file.content]);
    await session
      .prepare(`INSERT OR REPLACE INTO files (version, path, content) VALUES ${placeholders}`)
      .bind(...params)
      .run();
  }

  await session
    .prepare("INSERT OR REPLACE INTO versions (version) VALUES (?)")
    .bind(body.version)
    .run();
  return { files: files.length };
}

function bearerToken(header: string | null): string | null {
  const prefix = "bearer ";
  if (header === null || header.length <= prefix.length) {
    return null;
  }
  if (header.slice(0, prefix.length).toLowerCase() !== prefix) {
    return null;
  }
  return header.slice(prefix.length);
}

// Compare secrets without returning on the first mismatched byte.
function safeEqual(left: string, right: string): boolean {
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    const a = i < left.length ? left.charCodeAt(i) : 0;
    const b = i < right.length ? right.charCodeAt(i) : 0;
    diff |= a ^ b;
  }
  return diff === 0;
}

function indexAuthorized(request: Request, env: Env): boolean {
  const expected = env.INDEX_TOKEN;
  if (typeof expected !== "string" || expected.length === 0) {
    return false;
  }
  const provided = bearerToken(request.headers.get("authorization"));
  if (provided === null || provided.length === 0) {
    return false;
  }
  return safeEqual(provided, expected);
}

// `/__index` is the only writer for the search corpus. A response means the
// request is finished. The Worker must not forward it to the MCP handler,
// whose permissive CORS would let a browser preflight and then replace indexed source.
export async function handleIndexWrite(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/__index") {
    return null;
  }
  if (request.method !== "POST") {
    return new Response(null, { status: 405 });
  }
  if (request.headers.has("origin") || !indexAuthorized(request, env)) {
    return new Response("unauthorized", { status: 401 });
  }
  try {
    const body = (await request.json()) as IndexRequest;
    if (body.op !== "batch" && body.op !== "prune") {
      return new Response("expected op batch or prune", { status: 400 });
    }
    const result = await applyIndex(env, body);
    return Response.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "index failed";
    return new Response(message, { status: 400 });
  }
}
