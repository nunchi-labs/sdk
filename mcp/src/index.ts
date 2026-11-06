/**
 * Nunchi SDK MCP
 *
 * A Model Context Protocol server that exposes this repository (crates, docs,
 * and examples) to AI assistants. Content comes from the local checkout (`HEAD`)
 * and from git tags. Search runs against the D1 full-text index.
 *
 * Tools:
 * - get_file: Retrieve a specific file by path
 * - search_code: Search across source code files
 * - list_versions: List indexed git refs (`HEAD` and tags)
 * - list_crates: List workspace crates from Cargo.toml
 * - get_crate_readme: Get the README for a specific crate
 * - get_overview: Get the repository README
 * - list_files: List files in a crate or directory
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";
import { handleIndexWrite } from "./index-write.ts";
import {
  buildFileTree,
  topLevelDirectories,
  buildSnippets,
  formatSnippet,
  formatWithLineNumbers,
  getLanguage,
  isValidPath,
  parseWorkspaceMembers,
  parseCrateInfo,
  selectTopSnippets,
  sortVersionsDesc,
  stripCratePrefix,
} from "./utils.ts";
import pkg from "../package.json";

// Types
interface CrateInfo {
  name: string;
  path: string;
  description: string;
}

// Constants
const MAX_SEARCH_RESULTS = 50;

export class NunchiMCP extends McpAgent<Env, {}, {}> {
  server!: McpServer;

  async init() {
    this.server = new McpServer({
      name: "nunchi-sdk",
      version: pkg.version,
    });

    // Tool: Get a specific file by path
    this.server.tool(
      "get_file",
      "Retrieve a file from the Nunchi SDK repository by its path. " +
        "Paths are relative to the repository root (e.g., 'coins/src/lib.rs'). " +
        "Optionally specify a git ref (`HEAD` for the current checkout, or a tag). Defaults to HEAD when it is indexed. " +
        "Optionally specify start_line and end_line to fetch a specific range (0-indexed, inclusive). " +
        "Line numbers in output match those returned by search_code.",
      {
        path: z
          .string()
          .describe("File path relative to the repository root, e.g., 'coins/src/lib.rs'"),
        version: z
          .string()
          .optional()
          .describe("Git ref. `HEAD` is the current checkout. Defaults to HEAD when indexed."),
        start_line: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("Start line number (0-indexed, inclusive). Defaults to beginning of file."),
        end_line: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("End line number (0-indexed, inclusive). Defaults to end of file."),
      },
      async ({ path, version, start_line, end_line }) => {
        // Basic path validation - no path traversal
        if (!isValidPath(path)) {
          return {
            content: [{ type: "text", text: `Error: Invalid path '${path}'` }],
            isError: true,
          };
        }

        const ver = version || (await this.getLatestVersion());
        const content = await this.fetchFile(ver, path);
        if (content === null) {
          return {
            content: [
              {
                type: "text",
                text: `Error: File not found at ${path} (version ${ver})`,
              },
            ],
            isError: true,
          };
        }

        // Format with line numbers (and optionally filter to range)
        const formatted = formatWithLineNumbers(content, start_line, end_line);

        // Build header with line range info if specified
        const totalLines = content.split("\n").length;
        const rangeInfo =
          start_line !== undefined || end_line !== undefined
            ? ` [lines ${start_line ?? 0}-${end_line ?? totalLines - 1}]`
            : "";

        return {
          content: [
            {
              type: "text",
              text: `# ${path} (${ver})${rangeInfo}\n\n\`\`\`${getLanguage(path)}\n${formatted}\n\`\`\``,
            },
          ],
        };
      }
    );

    // Tool: Search code files
    this.server.tool(
      "search_code",
      "Search source, docs, and examples in the Nunchi SDK repository. " +
        "Returns matching files with relevant snippets. Useful for finding function definitions, " +
        "usage patterns, or how a crate is implemented.",
      {
        query: z.string().describe("Search query"),
        mode: z
          .enum(["substring", "word"])
          .optional()
          .default("substring")
          .describe(
            "Search mode: 'substring' for literal substring match (min 3 chars), " +
              "'word' for word-based search with prefix matching"
          ),
        crate: z
          .string()
          .optional()
          .describe("Limit search to a crate name or directory (e.g., 'nunchi-coins' or 'coins')"),
        file_type: z
          .enum(["rs", "md", "toml", "ts", "js", "json", "yml", "all"])
          .optional()
          .default("rs")
          .describe("File type to search: 'rs', 'md', 'toml', 'ts', 'js', 'json', 'yml', or 'all'"),
        version: z
          .string()
          .optional()
          .describe("Git ref. `HEAD` is the current checkout. Defaults to HEAD when indexed."),
        max_results: z
          .number()
          .optional()
          .default(10)
          .describe(
            `Maximum number of results to return (default: 10, max: ${MAX_SEARCH_RESULTS})`
          ),
      },
      async ({ query, mode, crate, file_type, version, max_results }) => {
        // Substring mode requires at least 3 characters (trigram tokenizer)
        if (mode === "substring" && query.trim().length < 3) {
          return {
            content: [
              {
                type: "text",
                text: `Error: Substring search requires at least 3 characters`,
              },
            ],
            isError: true,
          };
        }

        // Clamp max_results to valid range (negative LIMIT in SQLite means no limit)
        const limit = Math.max(1, Math.min(max_results, MAX_SEARCH_RESULTS));

        const ver = version || (await this.getLatestVersion());

        // Check if version exists
        const isIndexed = await this.isVersionIndexed(ver);
        if (!isIndexed) {
          return {
            content: [
              {
                type: "text",
                text: `Error: Version '${ver}' not found`,
              },
            ],
            isError: true,
          };
        }

        // Search using D1 FTS5
        const results = await this.searchWithFTS(ver, query, mode, crate, file_type, limit);

        if (results.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No matches found for "${query}" in ${ver}${crate ? ` (crate: ${crate})` : ""}`,
              },
            ],
          };
        }

        const output = results
          .map(
            (r) =>
              `## ${r.file}\n\n\`\`\`${getLanguage(r.file)}\n${r.matches.join("\n---\n")}\n\`\`\``
          )
          .join("\n\n");

        return {
          content: [
            {
              type: "text",
              text: `# Search results for "${query}" (${ver})\n\nFound ${results.length} file(s):\n\n${output}\n\n---\nFiles are listed by path. Use \`list_crates\` to see crate name to path mappings. Use \`get_file\` with \`start_line\` and \`end_line\` to fetch specific line ranges instead of entire files.`,
            },
          ],
        };
      }
    );

    // Tool: List available versions
    this.server.tool(
      "list_versions",
      "List indexed git refs of the Nunchi SDK. `HEAD` is the current checkout. Other entries are git tags.",
      {},
      async () => {
        const versions = await this.getVersions();
        if (versions.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: "No versions indexed. Start the server with `just mcp`, then run `just mcp-index`.",
              },
            ],
            isError: true,
          };
        }
        return {
          content: [
            {
              type: "text",
              text:
                `# Available Versions\n\n` +
                versions.map((v, i) => `- ${v}${i === 0 ? " (latest)" : ""}`).join("\n"),
            },
          ],
        };
      }
    );

    // Tool: List crates (dynamically from Cargo.toml)
    this.server.tool(
      "list_crates",
      "List crates in the Nunchi SDK workspace with their paths and descriptions.",
      {
        version: z
          .string()
          .optional()
          .describe("Git ref. `HEAD` is the current checkout. Defaults to HEAD when indexed."),
      },
      async ({ version }) => {
        const ver = version || (await this.getLatestVersion());
        const crates = await this.getCrates(ver);

        if (crates.length === 0) {
          return {
            content: [{ type: "text", text: "Error: Could not fetch crate information" }],
            isError: true,
          };
        }

        const output = crates
          .map((c) => `- **${c.name}** (${c.path}): ${c.description}`)
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: `# Nunchi SDK crates (${ver})\n\n${output}\n\nUse \`get_crate_readme\` for a crate's README. Use the path in parentheses with \`list_files\` or \`get_file\` to browse that crate.`,
            },
          ],
        };
      }
    );

    // Tool: Get crate README
    this.server.tool(
      "get_crate_readme",
      "Get the README for a Nunchi SDK crate.",
      {
        crate: z
          .string()
          .describe(
            "Crate name or directory (e.g., 'nunchi-coins', 'coins', 'examples/coins/chain')"
          ),
        version: z
          .string()
          .optional()
          .describe("Git ref. `HEAD` is the current checkout. Defaults to HEAD when indexed."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());
        const cratePath = await this.resolveCratePath(ver, crate);
        const content = await this.fetchFile(ver, `${cratePath}/README.md`);
        if (content === null) {
          return {
            content: [
              {
                type: "text",
                text: `Error: README not found for crate '${crate}' (version ${ver}). Use \`list_crates\` to see available crates.`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [{ type: "text", text: content }],
        };
      }
    );

    // Tool: Get repository overview
    this.server.tool(
      "get_overview",
      "Get the Nunchi SDK repository README: what the SDK is, its modules, and how to build it.",
      {},
      async () => {
        const ver = await this.getLatestVersion();
        const content = await this.fetchFile(ver, "README.md");
        if (content === null) {
          return {
            content: [{ type: "text", text: "Error fetching repository overview" }],
            isError: true,
          };
        }

        return {
          content: [{ type: "text", text: content }],
        };
      }
    );

    // Tool: List files in a crate or directory
    this.server.tool(
      "list_files",
      "List all files in a crate or directory. Useful for discovering the structure " +
        "of a crate before fetching specific files.",
      {
        crate: z
          .string()
          .optional()
          .describe(
            "Crate name (e.g., 'nunchi-coins') or directory path (e.g., 'examples/coins/chain'). " +
              "If omitted, lists top-level directories."
          ),
        version: z
          .string()
          .optional()
          .describe("Git ref. `HEAD` is the current checkout. Defaults to HEAD when indexed."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());
        const allFiles = await this.getFileList(ver);

        let filtered: string[];
        let prefix: string;

        if (crate) {
          // Resolve crate name or path to actual directory
          const folderName = await this.resolveCratePath(ver, crate);
          prefix = `${folderName}/`;
          filtered = allFiles.filter((f) => f.startsWith(prefix));

          if (filtered.length === 0) {
            return {
              content: [
                {
                  type: "text",
                  text: `Error: No files found for '${crate}' (version ${ver})`,
                },
              ],
              isError: true,
            };
          }
        } else {
          // List top-level directories. Root files have no slash and are not directories.
          const sortedDirs = topLevelDirectories(allFiles);
          return {
            content: [
              {
                type: "text",
                text:
                  `# Top-level directories (${ver})\n\n` +
                  sortedDirs.map((d) => `- ${d}/`).join("\n"),
              },
            ],
          };
        }

        // Build tree structure
        const tree = buildFileTree(filtered, prefix);

        return {
          content: [
            {
              type: "text",
              text: `# Files in ${crate} (${ver})\n\n\`\`\`\n${tree}\n\`\`\``,
            },
          ],
        };
      }
    );
  }

  // Helper: Read a file from the D1 index. Accepts a `nunchi-` prefixed path as a fallback.
  private async fetchFile(version: string, filePath: string): Promise<string | null> {
    const candidates = [filePath];
    if (filePath.startsWith("nunchi-")) {
      candidates.push(stripCratePrefix(filePath));
    }
    for (const candidate of candidates) {
      const row = await this.env.SEARCH_DB.withSession()
        .prepare("SELECT content FROM files WHERE version = ? AND path = ?")
        .bind(version, candidate)
        .first<{ content: string }>();
      if (row) {
        return row.content;
      }
    }
    return null;
  }

  // Helper: Get indexed versions from D1 (sorted descending)
  private async getIndexedVersions(): Promise<string[]> {
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT version FROM versions")
      .all<{ version: string }>();

    const versions = result.results.map((r) => r.version);
    sortVersionsDesc(versions);
    return versions;
  }

  // Helper: Default ref. `HEAD` is the working checkout when it has been indexed.
  private async getLatestVersion(): Promise<string> {
    const versions = await this.getIndexedVersions();
    if (versions.length === 0) {
      throw new Error("No versions indexed. Run `just mcp-index` after starting the server.");
    }
    return versions[0];
  }

  // Helper: Get all versions
  private async getVersions(): Promise<string[]> {
    return this.getIndexedVersions();
  }

  // Helper: Get file list for a version (from D1)
  private async getFileList(version: string): Promise<string[]> {
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT path FROM files WHERE version = ?")
      .bind(version)
      .all<{ path: string }>();

    return result.results.map((r) => r.path);
  }

  // Helper: Get crates list (individual Cargo.toml files are cached via fetchFile)
  private async getCrates(version: string): Promise<CrateInfo[]> {
    // Fetch workspace Cargo.toml to get members
    const workspaceToml = await this.fetchFile(version, "Cargo.toml");
    if (workspaceToml === null) {
      return [];
    }

    const memberPaths = parseWorkspaceMembers(workspaceToml);
    if (memberPaths.length === 0) {
      return [];
    }

    // Fetch each crate's Cargo.toml to get description
    const cratePromises = memberPaths.map(async (path) => {
      const cargoToml = await this.fetchFile(version, `${path}/Cargo.toml`);
      if (cargoToml === null) {
        return null;
      }

      const { name, description } = parseCrateInfo(cargoToml, path);
      return { name, path, description };
    });

    const results = await Promise.all(cratePromises);
    const crates: CrateInfo[] = [];
    for (const result of results) {
      if (result) {
        crates.push(result);
      }
    }

    // Sort alphabetically by name
    crates.sort((a, b) => a.name.localeCompare(b.name));

    return crates;
  }

  // Helper: Check if a version has been indexed
  private async isVersionIndexed(version: string): Promise<boolean> {
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT 1 FROM versions WHERE version = ?")
      .bind(version)
      .first();
    return result !== null;
  }

  // Helper: Resolve crate name or path to actual directory path
  private async resolveCratePath(version: string, crate: string): Promise<string> {
    // Match the Cargo package name first (`nunchi-coins` -> `coins`).
    const crates = await this.getCrates(version);
    const byName = crates.find((c) => c.name === crate);
    if (byName) {
      return byName.path;
    }

    // Otherwise treat it as a directory, stripping a leading `nunchi-` if present.
    return stripCratePrefix(crate);
  }

  // Helper: Search using D1 FTS5
  private async searchWithFTS(
    version: string,
    query: string,
    mode: "substring" | "word",
    crate: string | undefined,
    fileType: string,
    limit: number
  ): Promise<Array<{ file: string; matches: string[] }>> {
    // Build FTS query based on mode
    const { ftsQuery, snippetMatcher } = this.buildFTSQuery(query, mode);
    if (ftsQuery === null) {
      return [];
    }

    // Select FTS table based on mode
    const ftsTable = mode === "substring" ? "files_fts_substring" : "files_fts_word";

    // Build the SQL query with filters
    let sql = `
      SELECT f.path, f.content
      FROM ${ftsTable}
      JOIN files f ON ${ftsTable}.rowid = f.id
      WHERE ${ftsTable} MATCH ?
        AND f.version = ?
    `;
    const params: (string | number)[] = [ftsQuery, version];

    // Add crate filter (escape LIKE wildcards)
    if (crate) {
      const folderName = await this.resolveCratePath(version, crate);
      const escaped = folderName.replace(/[%_\\]/g, "\\$&");
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`${escaped}/%`);
    }

    // Add file type filter (escape LIKE wildcards)
    if (fileType !== "all") {
      const escaped = fileType.replace(/[%_\\]/g, "\\$&");
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`%.${escaped}`);
    }

    // Order by relevance and limit
    sql += ` ORDER BY bm25(${ftsTable}) LIMIT ?`;
    params.push(limit);

    // Execute the SQL query
    const results = await this.env.SEARCH_DB.withSession()
      .prepare(sql)
      .bind(...params)
      .all<{ path: string; content: string }>();

    // Extract snippets with context
    const output: Array<{ file: string; matches: string[] }> = [];

    for (const row of results.results) {
      const lines = row.content.split("\n");

      // Score each line by number of matching terms
      const lineScores = lines.map((line) => snippetMatcher(line.toLowerCase()));

      // Build and select top non-overlapping snippets
      const snippets = buildSnippets(lineScores);
      const selected = selectTopSnippets(snippets, 5);

      // Format selected snippets
      const matches = selected.map(({ start, end }) => formatSnippet(lines, start, end));

      // Always include file if FTS5 matched it
      output.push({ file: row.path, matches });
    }

    return output;
  }

  // Helper: Build FTS5 query based on mode
  // Returns a snippetMatcher that scores lines (0 = no match, higher = more matches)
  private buildFTSQuery(
    query: string,
    mode: "substring" | "word"
  ): { ftsQuery: string | null; snippetMatcher: (line: string) => number } {
    const trimmed = query.trim();

    if (mode === "substring") {
      // Trigram requires at least 3 characters
      if (trimmed.length < 3) {
        return { ftsQuery: null, snippetMatcher: () => 0 };
      }
      // Escape double quotes for FTS5
      const escaped = trimmed.replace(/"/g, '""');
      const queryLower = trimmed.toLowerCase();
      return {
        ftsQuery: `"${escaped}"`,
        // Substring mode: count occurrences
        snippetMatcher: (line) => {
          let count = 0;
          let idx = 0;
          while ((idx = line.indexOf(queryLower, idx)) !== -1) {
            count++;
            idx += queryLower.length;
          }
          return count;
        },
      };
    } else {
      // Word mode: escape special chars and add prefix matching
      const escaped = trimmed.replace(/["()*:^-]/g, " ").trim();
      const words = escaped.split(/\s+/).filter((w) => w.length > 0);
      if (words.length === 0) {
        return { ftsQuery: null, snippetMatcher: () => 0 };
      }
      const ftsQuery = words.map((w) => `${w}*`).join(" ");
      const wordsLower = words.map((w) => w.toLowerCase());
      return {
        ftsQuery,
        // Word mode: count total occurrences of all query words
        snippetMatcher: (line) => {
          let count = 0;
          for (const word of wordsLower) {
            let idx = 0;
            while ((idx = line.indexOf(word, idx)) !== -1) {
              count++;
              idx += word.length;
            }
          }
          return count;
        },
      };
    }
  }
}

// Create MCP handler using McpAgent.serve() for proper session management
// CORS is handled automatically by the WorkerTransport with permissive defaults
const mcpHandler = McpAgent.serve("/", { binding: "MCP" });

// Worker fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // `/__index` never reaches the MCP handler. That handler's permissive CORS
    // would otherwise answer OPTIONS and let a browser replace the corpus.
    const indexResponse = await handleIndexWrite(request, env);
    if (indexResponse !== null) {
      return indexResponse;
    }

    // Route all other requests to the MCP agent (handles CORS including OPTIONS preflight)
    return mcpHandler.fetch(request, env, ctx);
  },

  // The cron binding stays so the Worker shape matches the original server.
  // Indexing reads this git checkout from `just mcp-index`, which can spawn git.
  async scheduled(_event: ScheduledEvent, _env: Env, _ctx: ExecutionContext): Promise<void> {
    console.log("Nunchi SDK index is built by `just mcp-index` against the local checkout.");
  },
};
