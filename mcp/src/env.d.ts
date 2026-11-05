/// <reference types="@cloudflare/workers-types" />

export interface Env {
  MCP: DurableObjectNamespace;
  SEARCH_DB: D1Database;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
