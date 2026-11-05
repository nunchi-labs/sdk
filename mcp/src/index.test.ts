import { describe, expect, it } from "vitest";
import type { Env } from "./env.d.ts";
import { handleIndexWrite } from "./index-write.ts";

function env(token: string | undefined, db: D1Database): Env {
  return {
    MCP: {} as DurableObjectNamespace,
    SEARCH_DB: db,
    INDEX_TOKEN: token,
  };
}

function untouchedDb(): D1Database {
  return {
    withSession() {
      throw new Error("search db should not be touched");
    },
  } as unknown as D1Database;
}

function recordingDb() {
  const queries: string[] = [];
  const statement = {
    bind() {
      return statement;
    },
    async run() {
      return { success: true };
    },
    async all() {
      return { results: [] as { version: string }[] };
    },
  };
  const db = {
    withSession() {
      return {
        prepare(sql: string) {
          queries.push(sql);
          return statement;
        },
        async batch() {
          queries.push("batch");
          return [];
        },
      };
    },
  } as unknown as D1Database;
  return { db, queries };
}

function indexRequest(
  url: string,
  method: string,
  headers: Record<string, string>,
  body?: string
): Request {
  return new Request(url, { method, headers, body });
}

async function indexResponse(
  url: string,
  method: string,
  headers: Record<string, string>,
  token: string | undefined,
  db: D1Database,
  body?: string
): Promise<Response> {
  const response = await handleIndexWrite(indexRequest(url, method, headers, body), env(token, db));
  if (response === null) {
    throw new Error("expected /__index to be handled");
  }
  return response;
}

describe("POST /__index", () => {
  it("does not answer CORS preflight", async () => {
    const response = await indexResponse(
      "http://127.0.0.1:8787/__index",
      "OPTIONS",
      {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type, authorization",
      },
      "secret",
      untouchedDb()
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("access-control-allow-methods")).toBeNull();
    expect(response.headers.get("access-control-allow-headers")).toBeNull();
  });

  it("leaves other paths to the MCP handler", async () => {
    const response = await handleIndexWrite(
      indexRequest("http://127.0.0.1:8787/", "OPTIONS", {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
      }),
      env("secret", untouchedDb())
    );

    expect(response).toBeNull();
  });

  it("rejects a cross-origin prune before writing", async () => {
    const response = await indexResponse(
      "https://nunchi-sdk-mcp.example/__index",
      "POST",
      {
        Origin: "https://evil.example",
        "content-type": "application/json",
        authorization: "Bearer secret",
      },
      "secret",
      untouchedDb(),
      JSON.stringify({ op: "prune", keep: [] })
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("rejects a public write with no token", async () => {
    const response = await indexResponse(
      "https://nunchi-sdk-mcp.example/__index",
      "POST",
      { "content-type": "application/json" },
      undefined,
      untouchedDb(),
      JSON.stringify({ op: "batch", version: "HEAD", reset: true, files: [] })
    );

    expect(response.status).toBe(401);
  });

  it("rejects the wrong token", async () => {
    const response = await indexResponse(
      "http://127.0.0.1:8787/__index",
      "POST",
      { "content-type": "application/json", authorization: "Bearer other" },
      "secret",
      untouchedDb(),
      JSON.stringify({ op: "prune", keep: [] })
    );

    expect(response.status).toBe(401);
  });

  it("writes a batch when the bearer token matches", async () => {
    const { db, queries } = recordingDb();
    const response = await indexResponse(
      "http://127.0.0.1:8787/__index",
      "POST",
      { "content-type": "application/json", authorization: "Bearer secret" },
      "secret",
      db,
      JSON.stringify({
        op: "batch",
        version: "HEAD",
        reset: true,
        files: [{ path: "coins/src/lib.rs", content: "fn main() {}" }],
      })
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ files: 1 });
    expect(queries.some((sql) => sql.startsWith("INSERT OR REPLACE INTO files"))).toBe(true);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("indexes a tag that contains a slash", async () => {
    const { db, queries } = recordingDb();
    const response = await indexResponse(
      "http://127.0.0.1:8787/__index",
      "POST",
      { "content-type": "application/json", authorization: "Bearer secret" },
      "secret",
      db,
      JSON.stringify({ op: "batch", version: "release/1.0", reset: true, files: [] })
    );

    expect(response.status).toBe(200);
    expect(queries.some((sql) => sql.startsWith("INSERT OR REPLACE INTO versions"))).toBe(true);
  });

  it("rejects a ref that escapes the repository", async () => {
    const response = await indexResponse(
      "http://127.0.0.1:8787/__index",
      "POST",
      { "content-type": "application/json", authorization: "Bearer secret" },
      "secret",
      untouchedDb(),
      JSON.stringify({ op: "batch", version: "release/../1.0", reset: true, files: [] })
    );

    expect(response.status).toBe(400);
  });
});
