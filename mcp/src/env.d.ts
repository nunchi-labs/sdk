/// <reference types="@cloudflare/workers-types" />

export interface Env {
  MCP: DurableObjectNamespace;
  SEARCH_DB: D1Database;
  // Bearer secret required by POST /__index. Unset rejects every index write.
  INDEX_TOKEN?: string;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
