# Nunchi SDK MCP

MCP server for this repository. It indexes the Nunchi SDK checkout and its git tags, then exposes that corpus through the same tool surface the Worker was built with:

| Tool | Description |
|------|-------------|
| `get_file` | Read a file by repo-relative path (for example `coins/src/lib.rs`) |
| `search_code` | Full-text search over indexed source, docs, and examples |
| `list_versions` | List indexed refs. `HEAD` is the working tree. Other entries are git tags |
| `list_crates` | List workspace crates from the root `Cargo.toml` |
| `get_crate_readme` | Read a crate README (`nunchi-coins` or `coins`) |
| `get_overview` | Read the repository `README.md` |
| `list_files` | List files in a crate or directory |

The Worker architecture is unchanged: a Durable Object holds the MCP session, D1 stores file text and two FTS5 indexes, and the scheduled handler fills that database. What changed is the corpus. The handler reads this git checkout instead of a remote sitemap.

## Build and run

From the repository root, with Node.js 22:

```bash
just mcp-build
just mcp
```

`just mcp-build` installs dependencies and typechecks (`tsc --noEmit`). `just mcp` applies the local D1 migration and starts Wrangler on `http://127.0.0.1:8787`.

The same steps without `just`:

```bash
cd mcp
npm ci
npx wrangler d1 migrations apply nunchi-mcp-search --local
npm run dev
```

Cursor (`.cursor/mcp.json`) and Claude Code (`.mcp.json`) already point at that URL as `nunchi-sdk`. Start the server before connecting a client.

## Index this repository

In a second terminal, after the server is listening:

```bash
just mcp-index
```

That command reads this git checkout in Node and posts file batches to the Worker's `/__index` route. The Worker stores them in D1. The Worker isolate cannot spawn git, so the index command is the process that walks the repository.

`/__index` accepts those batches only with `Authorization: Bearer $INDEX_TOKEN`. `npm run dev` writes a local token to `.dev.vars` (gitignored), and `just mcp-index` reads it. A deployed Worker rejects writes until the same secret is set with `npx wrangler secret put INDEX_TOKEN`. Export that value before indexing a remote `MCP_URL`.

* tracked text files in the working tree are stored as `HEAD` (replaced on every run, so local edits show up)
* each git tag is stored under that tag name
* refs that are no longer present are dropped

Tools default to `HEAD`. Pass `version` to read a tag, for example `v2026.7.0-alpha.1`.

Indexed paths are Rust, Markdown, TOML, JSON, YAML, JavaScript, TypeScript, HTML, CSS, shell, and SQL, plus `Justfile`, `Dockerfile`, and `LICENSE*` files. Lockfiles, images, `target/`, and `node_modules/` are skipped.

`npm run ci` in `mcp/` runs format, lint, typecheck, and unit tests.

## Architecture

* **Durable Objects** keep MCP client sessions (`NunchiMCP`)
* **D1 + FTS5** stores one copy of each file per git ref, with trigram and word indexes
* **`just mcp-index`** walks this checkout and posts batches. The Worker writes those batches into D1

Deploying the Worker to Cloudflare does not bring the git checkout with it. Indexing runs against the repository on disk and must present `INDEX_TOKEN`.
