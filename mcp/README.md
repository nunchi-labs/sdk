# Commonware MCP

This directory is Commonware's MCP server (`commonware-mcp`), vendored from [commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo/tree/5ac6c01c0901d0d48997820f898ceed286c10b73/mcp) at `5ac6c01c0901d0d48997820f898ceed286c10b73`. It is the SDK's MCP server. It replaces `nunchi-mcp`.

The package is a TypeScript Cloudflare Worker, so Cargo does not build it. From the repository root:

```bash
just mcp-build   # npm ci && npm run build (tsc --noEmit)
just mcp         # local D1 migration, then npm run dev
```

`just mcp` is the replacement for `cargo run -p nunchi-mcp`. The process listens on `http://127.0.0.1:8787` (Streamable HTTP). Cursor and Claude Code in this repo are already pointed at that URL. Start the server before opening a client.

Pass `version` `v2026.9.0` on tools that accept it. That tag matches this workspace's `commonware-*` pin. The server defaults to the latest indexed Commonware release.

Without `just`:

```bash
cd mcp
npm ci
npx wrangler d1 migrations apply commonware-mcp-search --local
npm run dev
```

`npm run ci` runs format, lint, typecheck, and unit tests. A Cloudflare account is required only for `npm run deploy`.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Tools

| Tool | Description |
|------|-------------|
| `get_file` | Retrieve a specific file by path (e.g., `commonware-cryptography/src/lib.rs`) |
| `search_code` | Search across source files for patterns or keywords |
| `list_versions` | List all available code versions |
| `list_crates` | List all crates with descriptions |
| `get_crate_readme` | Get README documentation for a specific crate |
| `get_overview` | Get the repository README/overview |
| `list_files` | List files in a crate or directory |

_Try these tools out on the [Commonware Library MCP Explorer](https://commonware.xyz/mcp)._

## Connecting

Start `just mcp` from the repository root, then point an MCP client at `http://127.0.0.1:8787`. The server is a version-pinned index of Commonware Library source and documentation, with ranked search that returns snippets and surrounding context.

### Claude Code

This repository's [`.mcp.json`](../.mcp.json) already points at the local server:

```json
{
  "mcpServers": {
    "commonware-library": {
      "type": "http",
      "url": "http://127.0.0.1:8787"
    }
  }
}
```

### Cursor

This repository's [`.cursor/mcp.json`](../.cursor/mcp.json) already points at the local server:

```json
{
  "mcpServers": {
    "commonware-library": {
      "url": "http://127.0.0.1:8787"
    }
  }
}
```

## Development

### Prerequisites

- Node.js 22
- `npm ci` in this directory (Wrangler is a dev dependency)

A Cloudflare account is required only for the deploy steps below.

### Setup

```bash
cd mcp
npm install
```

### Local Development

```bash
# Create local D1 database and run migrations
npx wrangler d1 migrations apply commonware-mcp-search --local

# Start dev server
npm run dev
```

In a separate terminal, trigger indexing to populate the search index:

```bash
curl "http://localhost:8787/__scheduled?cron=*"
```

The server will be available at `http://localhost:8787`. Use the MCP inspector to test:

```bash
npx @modelcontextprotocol/inspector@latest
```

In the inspector UI, select **Streamable HTTP** transport, enter `http://localhost:8787` as the URL, and choose **Direct** connection mode.

### Deploy

```bash
# Login to Cloudflare (first time only)
npx wrangler login

# Create D1 database (first time only)
npx wrangler d1 create commonware-mcp-search
# Update database_id in wrangler.jsonc with the returned ID

# Run migrations (first time and after schema changes)
npx wrangler d1 migrations apply commonware-mcp-search

# Deploy
npm run deploy

# Indexing runs automatically via cron (every 10 minutes)
```

## Architecture

The server uses Cloudflare's [Agents SDK](https://developers.cloudflare.com/agents/) with the `McpAgent` class:

- **Durable Objects**: Maintains persistent connections for MCP clients
- **Sitemap-based discovery**: Parses `commonware.xyz/sitemap.xml` to discover available versions
- **D1 + FTS5**: Full-text search index powered by SQLite FTS5

## Example Usage

Once connected, you can ask your AI assistant questions like:

- "How do I use BLS signatures in commonware-cryptography?"
- "Show me the simplex consensus implementation"
- "What's the difference between the broadcast and p2p crates?"
- "Find where threshold signatures are implemented"
- "Explain how the deterministic runtime works"

The assistant will use the MCP tools to fetch actual source code rather than relying on training data.