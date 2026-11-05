import { describe, expect, it } from "vitest";
import { isIndexablePath } from "./repo.ts";
import {
  sortVersionsDesc,
  getLanguage,
  stripCratePrefix,
  isValidPath,
  parseWorkspaceMembers,
  parseCrateInfo,
  buildFileTree,
  buildSnippets,
  hasMajorityOverlap,
  selectTopSnippets,
  formatSnippet,
  formatWithLineNumbers,
} from "./utils.ts";

describe("sortVersionsDesc", () => {
  it("should sort versions in descending order", () => {
    const versions = ["v0.0.62", "v0.0.64", "v0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.0.64", "v0.0.63", "v0.0.62"]);
  });

  it("should handle versions without v prefix", () => {
    const versions = ["0.0.62", "0.0.64", "0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["0.0.64", "0.0.63", "0.0.62"]);
  });

  it("should handle mixed v prefix versions", () => {
    const versions = ["v0.0.62", "0.0.64", "v0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["0.0.64", "v0.0.63", "v0.0.62"]);
  });

  it("should handle major version differences", () => {
    const versions = ["v1.0.0", "v0.0.64", "v2.0.0"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v2.0.0", "v1.0.0", "v0.0.64"]);
  });

  it("should handle minor version differences", () => {
    const versions = ["v0.1.0", "v0.2.0", "v0.0.64"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.2.0", "v0.1.0", "v0.0.64"]);
  });

  it("should handle empty array", () => {
    const versions: string[] = [];
    sortVersionsDesc(versions);
    expect(versions).toEqual([]);
  });

  it("should handle single version", () => {
    const versions = ["v0.0.64"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.0.64"]);
  });

  it("should sort Nunchi tags above older tags and keep HEAD first", () => {
    const versions = ["v2026.7.0-alpha.1", "HEAD", "v2026.9.0-alpha.1"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["HEAD", "v2026.9.0-alpha.1", "v2026.7.0-alpha.1"]);
  });
});

describe("getLanguage", () => {
  it("should return rust for .rs files", () => {
    expect(getLanguage("src/lib.rs")).toBe("rust");
    expect(getLanguage("cryptography/src/bls12381/mod.rs")).toBe("rust");
  });

  it("should return toml for .toml files", () => {
    expect(getLanguage("Cargo.toml")).toBe("toml");
    expect(getLanguage("cryptography/Cargo.toml")).toBe("toml");
  });

  it("should return markdown for .md files", () => {
    expect(getLanguage("README.md")).toBe("markdown");
    expect(getLanguage("docs/CONTRIBUTING.md")).toBe("markdown");
  });

  it("should return empty string for unknown extensions", () => {
    expect(getLanguage("file.txt")).toBe("");
    expect(getLanguage("file.json")).toBe("json");
    expect(getLanguage("file")).toBe("");
  });
});

describe("stripCratePrefix", () => {
  it("should strip nunchi- prefix from crate names", () => {
    expect(stripCratePrefix("nunchi-coins")).toBe("coins");
    expect(stripCratePrefix("nunchi-bridge")).toBe("bridge");
    expect(stripCratePrefix("nunchi-rpc")).toBe("rpc");
  });

  it("should strip prefix from paths", () => {
    expect(stripCratePrefix("nunchi-coins/src/lib.rs")).toBe("coins/src/lib.rs");
  });

  it("should not modify names without prefix", () => {
    expect(stripCratePrefix("coins")).toBe("coins");
    expect(stripCratePrefix("bridge")).toBe("bridge");
    expect(stripCratePrefix("examples/coins/chain")).toBe("examples/coins/chain");
  });

  it("should only strip prefix at start", () => {
    expect(stripCratePrefix("foo-nunchi-bar")).toBe("foo-nunchi-bar");
  });
});

describe("isIndexablePath", () => {
  it("should accept SDK source, docs, and examples", () => {
    expect(isIndexablePath("coins/src/lib.rs")).toBe(true);
    expect(isIndexablePath("README.md")).toBe(true);
    expect(isIndexablePath("Cargo.toml")).toBe(true);
    expect(isIndexablePath("examples/wallet-extension/src/popup.ts")).toBe(true);
    expect(isIndexablePath("AGENTS.md")).toBe(true);
    expect(isIndexablePath("Justfile")).toBe(true);
    expect(isIndexablePath("LICENSE-MIT")).toBe(true);
  });

  it("should reject lockfiles, images, dependencies, and traversal", () => {
    expect(isIndexablePath("Cargo.lock")).toBe(false);
    expect(isIndexablePath("mcp/package-lock.json")).toBe(false);
    expect(isIndexablePath("image.png")).toBe(false);
    expect(isIndexablePath("mcp/node_modules/zod/index.js")).toBe(false);
    expect(isIndexablePath("target/debug/foo.rs")).toBe(false);
    expect(isIndexablePath("../secrets.env")).toBe(false);
  });
});

describe("isValidPath", () => {
  it("should accept valid relative paths", () => {
    expect(isValidPath("cryptography/src/lib.rs")).toBe(true);
    expect(isValidPath("README.md")).toBe(true);
    expect(isValidPath("examples/chat/src/main.rs")).toBe(true);
  });

  it("should reject paths with path traversal", () => {
    expect(isValidPath("../etc/passwd")).toBe(false);
    expect(isValidPath("cryptography/../../../etc/passwd")).toBe(false);
    expect(isValidPath("..")).toBe(false);
  });

  it("should reject absolute paths", () => {
    expect(isValidPath("/etc/passwd")).toBe(false);
    expect(isValidPath("/home/user/file.rs")).toBe(false);
  });

  it("should accept paths with dots that are not traversal", () => {
    expect(isValidPath(".gitignore")).toBe(true);
    expect(isValidPath("src/.hidden/file.rs")).toBe(true);
    expect(isValidPath("file.test.rs")).toBe(true);
  });
});

describe("parseWorkspaceMembers", () => {
  it("should parse workspace members from Cargo.toml", () => {
    const cargoToml = `[workspace]
members = [
    "broadcast",
    "codec",
    "cryptography",
    "examples/chat",
]
resolver = "2"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual(["broadcast", "codec", "cryptography", "examples/chat"]);
  });

  it("should handle empty members array", () => {
    const cargoToml = `[workspace]
members = []
resolver = "2"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual([]);
  });

  it("should return empty array for invalid Cargo.toml", () => {
    const cargoToml = `[package]
name = "some-crate"
version = "0.1.0"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual([]);
  });

  it("should handle inline members array", () => {
    const cargoToml = `[workspace]
members = ["broadcast", "codec"]`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual(["broadcast", "codec"]);
  });
});

describe("parseCrateInfo", () => {
  it("should parse crate name and description", () => {
    const cargoToml = `[package]
name = "nunchi-coins"
edition.workspace = true
description = "Generate keys, sign arbitrary messages, and deterministically verify signatures."`;

    const info = parseCrateInfo(cargoToml, "coins");
    expect(info.name).toBe("nunchi-coins");
    expect(info.description).toBe(
      "Generate keys, sign arbitrary messages, and deterministically verify signatures."
    );
  });

  it("should preserve nunchi- prefix in name", () => {
    const cargoToml = `[package]
name = "nunchi-bridge"
description = "Disseminate data over a wide-area network."`;

    const info = parseCrateInfo(cargoToml, "bridge");
    expect(info.name).toBe("nunchi-bridge");
  });

  it("should use fallback path when name is missing", () => {
    const cargoToml = `[package]
edition = "2024"
description = "Some description"`;

    const info = parseCrateInfo(cargoToml, "fallback-path");
    expect(info.name).toBe("fallback-path");
  });

  it("should use default description when missing", () => {
    const cargoToml = `[package]
name = "nunchi-oracle"`;

    const info = parseCrateInfo(cargoToml, "test");
    expect(info.description).toBe("No description available");
  });

  it("should handle example crates without a nunchi prefix", () => {
    const cargoToml = `[package]
name = "chat"
description = "Send encrypted messages to a group of friends."`;

    const info = parseCrateInfo(cargoToml, "examples/chat");
    expect(info.name).toBe("chat");
    expect(info.description).toBe("Send encrypted messages to a group of friends.");
  });

  it("should only match name in [package] section, not dependencies", () => {
    const cargoToml = `[dependencies]
some-crate = { version = "1.0", package = "actual-name" }

[dependencies.renamed]
name = "wrong-name"
version = "1.0"

[package]
name = "correct-name"
description = "The correct description"

[dev-dependencies]
test-crate = { name = "also-wrong" }`;

    const info = parseCrateInfo(cargoToml, "fallback");
    expect(info.name).toBe("correct-name");
    expect(info.description).toBe("The correct description");
  });
});

describe("buildFileTree", () => {
  it("should build tree from files with prefix", () => {
    const files = [
      "cryptography/src/lib.rs",
      "cryptography/src/bls12381/mod.rs",
      "cryptography/src/bls12381/keys.rs",
      "cryptography/Cargo.toml",
      "cryptography/README.md",
    ];
    const result = buildFileTree(files, "cryptography/");

    expect(result).toBe(
      `Cargo.toml
README.md
src/
  lib.rs
src/bls12381/
  keys.rs
  mod.rs`
    );
  });

  it("should handle files only in root directory", () => {
    const files = ["crate/Cargo.toml", "crate/README.md", "crate/LICENSE"];
    const result = buildFileTree(files, "crate/");

    expect(result).toBe(`Cargo.toml
LICENSE
README.md`);
  });

  it("should handle deeply nested directories", () => {
    const files = ["pkg/src/a/b/c/deep.rs", "pkg/src/a/b/shallow.rs", "pkg/src/a/top.rs"];
    const result = buildFileTree(files, "pkg/");

    expect(result).toBe(
      `src/a/
  top.rs
src/a/b/
  shallow.rs
src/a/b/c/
  deep.rs`
    );
  });

  it("should sort directories and files alphabetically", () => {
    const files = [
      "pkg/src/zebra.rs",
      "pkg/src/alpha.rs",
      "pkg/tests/z_test.rs",
      "pkg/tests/a_test.rs",
    ];
    const result = buildFileTree(files, "pkg/");

    expect(result).toBe(
      `src/
  alpha.rs
  zebra.rs
tests/
  a_test.rs
  z_test.rs`
    );
  });

  it("should handle empty file list", () => {
    const result = buildFileTree([], "pkg/");
    expect(result).toBe("");
  });

  it("should handle single file", () => {
    const files = ["pkg/README.md"];
    const result = buildFileTree(files, "pkg/");
    expect(result).toBe("README.md");
  });
});

describe("buildSnippets", () => {
  it("should create rolling windows centered on matching lines", () => {
    const scores = [0, 0, 0, 5, 0, 0, 0]; // match on line 3 (0-indexed)

    const snippets = buildSnippets(scores, 5);

    // Window of 5 centered on line 3: lines 1-6 (exclusive)
    expect(snippets).toHaveLength(1);
    expect(snippets[0]).toEqual({ start: 1, end: 6, score: 5 });
  });

  it("should create multiple overlapping windows for adjacent matches", () => {
    const scores = [0, 2, 3, 0, 0]; // matches on lines 1 and 2

    const snippets = buildSnippets(scores, 3);

    // Window size 3: halfWindow = 1
    // Line 1: window 0-3, score = 0+2+3 = 5
    // Line 2: window 1-4, score = 2+3+0 = 5
    expect(snippets).toHaveLength(2);
    expect(snippets[0]).toEqual({ start: 0, end: 3, score: 5 });
    expect(snippets[1]).toEqual({ start: 1, end: 4, score: 5 });
  });

  it("should clamp windows to file boundaries", () => {
    const scores = [5, 0, 0]; // match on first line

    const snippets = buildSnippets(scores, 7);

    // Window of 7 centered on line 0, clamped to 0-3
    expect(snippets).toHaveLength(1);
    expect(snippets[0]).toEqual({ start: 0, end: 3, score: 5 });
  });

  it("should handle no matches", () => {
    const scores = [0, 0, 0];

    const snippets = buildSnippets(scores);

    expect(snippets).toHaveLength(0);
  });

  it("should accumulate scores from all lines in window", () => {
    const scores = [1, 2, 3, 2, 1]; // all lines have scores

    const snippets = buildSnippets(scores, 3);

    // Each line creates a window, scores accumulate
    expect(snippets).toHaveLength(5);
    // Line 0: window 0-2, score = 1+2 = 3 (clamped start)
    expect(snippets[0]).toEqual({ start: 0, end: 2, score: 3 });
    // Line 1: window 0-3, score = 1+2+3 = 6
    expect(snippets[1]).toEqual({ start: 0, end: 3, score: 6 });
    // Line 2: window 1-4, score = 2+3+2 = 7
    expect(snippets[2]).toEqual({ start: 1, end: 4, score: 7 });
  });

  it("should use default window size of 7", () => {
    const scores = Array(20).fill(0);
    scores[10] = 5; // match in middle

    const snippets = buildSnippets(scores);

    // Default window 7, halfWindow = 3
    // Line 10: window 7-14
    expect(snippets).toHaveLength(1);
    expect(snippets[0]).toEqual({ start: 7, end: 14, score: 5 });
  });
});

describe("hasMajorityOverlap", () => {
  it("should return false when no overlap", () => {
    expect(hasMajorityOverlap(0, 5, 10, 15)).toBe(false);
  });

  it("should return false when overlap is less than half of candidate", () => {
    // candidate: 0-10 (10 lines), selected: 8-12, overlap: 8-10 (2 lines)
    // 2 / 10 = 0.2, not > 0.5
    expect(hasMajorityOverlap(0, 10, 8, 12)).toBe(false);
  });

  it("should return true when overlap is more than half of candidate", () => {
    // candidate: 5-10 (5 lines), selected: 0-8, overlap: 5-8 (3 lines)
    // 3 / 5 = 0.6 > 0.5
    expect(hasMajorityOverlap(5, 10, 0, 8)).toBe(true);
  });

  it("should return true when candidate is fully contained in selected", () => {
    // candidate: 5-10 (5 lines), selected: 0-20, all 5 lines overlap
    // 5 / 5 = 1.0 > 0.5
    expect(hasMajorityOverlap(5, 10, 0, 20)).toBe(true);
  });

  it("should return false when selected is fully contained in large candidate", () => {
    // candidate: 0-20 (20 lines), selected: 5-10, overlap: 5 lines
    // 5 / 20 = 0.25 < 0.5
    expect(hasMajorityOverlap(0, 20, 5, 10)).toBe(false);
  });
});

describe("selectTopSnippets", () => {
  it("should select top snippets by score descending", () => {
    const snippets = [
      { start: 0, end: 3, score: 5 },
      { start: 10, end: 13, score: 10 },
      { start: 20, end: 23, score: 3 },
    ];

    const selected = selectTopSnippets(snippets, 3);

    expect(selected).toHaveLength(3);
    expect(selected[0]).toEqual({ start: 10, end: 13 }); // score 10
    expect(selected[1]).toEqual({ start: 0, end: 3 }); // score 5
    expect(selected[2]).toEqual({ start: 20, end: 23 }); // score 3
  });

  it("should preserve snippet boundaries without modification", () => {
    const snippets = [{ start: 5, end: 8, score: 10 }];

    const selected = selectTopSnippets(snippets, 1);

    expect(selected).toHaveLength(1);
    expect(selected[0]).toEqual({ start: 5, end: 8 });
  });

  it("should filter overlapping snippets", () => {
    const snippets = [
      { start: 0, end: 6, score: 10 }, // highest score - 6 lines
      { start: 2, end: 6, score: 8 }, // 4 lines, overlaps 4/4 = 100% with first
      { start: 20, end: 25, score: 5 }, // no overlap
    ];

    const selected = selectTopSnippets(snippets, 3);

    expect(selected).toHaveLength(2);
    // First snippet (score 10) and third snippet (score 5)
    // Second is skipped due to majority overlap with first (100% > 50%)
  });

  it("should respect maxSnippets limit", () => {
    const snippets = [
      { start: 0, end: 3, score: 10 },
      { start: 10, end: 13, score: 8 },
      { start: 20, end: 23, score: 6 },
      { start: 30, end: 33, score: 4 },
    ];

    const selected = selectTopSnippets(snippets, 2);

    expect(selected).toHaveLength(2);
  });

  it("should handle empty snippets array", () => {
    const selected = selectTopSnippets([], 5);
    expect(selected).toHaveLength(0);
  });

  it("should filter out snippets with score of 0", () => {
    const snippets = [
      { start: 0, end: 3, score: 10 },
      { start: 10, end: 13, score: 0 }, // should be filtered out
      { start: 20, end: 23, score: 5 },
    ];

    const selected = selectTopSnippets(snippets, 5);

    expect(selected).toHaveLength(2);
    expect(selected[0]).toEqual({ start: 0, end: 3 });
    expect(selected[1]).toEqual({ start: 20, end: 23 });
  });

  it("should return empty array when all snippets have score 0", () => {
    const snippets = [
      { start: 0, end: 3, score: 0 },
      { start: 10, end: 13, score: 0 },
    ];

    const selected = selectTopSnippets(snippets, 5);

    expect(selected).toHaveLength(0);
  });
});

describe("formatSnippet", () => {
  it("should format lines with 0-based line numbers", () => {
    const lines = ["line 0", "line 1", "line 2", "line 3", "line 4"];

    const result = formatSnippet(lines, 1, 4);

    expect(result).toBe("1: line 1\n2: line 2\n3: line 3");
  });

  it("should handle first lines of file", () => {
    const lines = ["first", "second", "third"];

    const result = formatSnippet(lines, 0, 2);

    expect(result).toBe("0: first\n1: second");
  });

  it("should handle single line", () => {
    const lines = ["only line"];

    const result = formatSnippet(lines, 0, 1);

    expect(result).toBe("0: only line");
  });
});

describe("formatWithLineNumbers", () => {
  const sampleContent = `fn main() {
    println!("Hello, world!");
}

fn helper() {
    // do something
}`;

  it("should format entire file with line numbers (0-indexed)", () => {
    const result = formatWithLineNumbers(sampleContent);
    // Note: empty line 3 produces "3: " with trailing space from the format string
    const expected = [
      "0: fn main() {",
      '1:     println!("Hello, world!");',
      "2: }",
      "3: ",
      "4: fn helper() {",
      "5:     // do something",
      "6: }",
    ].join("\n");
    expect(result).toBe(expected);
  });

  it("should format a range of lines (start_line only)", () => {
    const result = formatWithLineNumbers(sampleContent, 4);
    expect(result).toBe(`4: fn helper() {
5:     // do something
6: }`);
  });

  it("should format a range of lines (end_line only)", () => {
    const result = formatWithLineNumbers(sampleContent, undefined, 2);
    expect(result).toBe(`0: fn main() {
1:     println!("Hello, world!");
2: }`);
  });

  it("should format a range of lines (both start and end)", () => {
    const result = formatWithLineNumbers(sampleContent, 1, 3);
    // Note: line 3 is empty, produces "3: " with trailing space
    const expected = ['1:     println!("Hello, world!");', "2: }", "3: "].join("\n");
    expect(result).toBe(expected);
  });

  it("should clamp start_line to 0", () => {
    const result = formatWithLineNumbers(sampleContent, -5, 1);
    expect(result).toBe(`0: fn main() {
1:     println!("Hello, world!");`);
  });

  it("should clamp end_line to last line index", () => {
    const result = formatWithLineNumbers(sampleContent, 4, 100);
    expect(result).toBe(`4: fn helper() {
5:     // do something
6: }`);
  });

  it("should return empty string if start > end", () => {
    const result = formatWithLineNumbers(sampleContent, 5, 2);
    expect(result).toBe("");
  });

  it("should return empty string if start >= total lines", () => {
    const result = formatWithLineNumbers(sampleContent, 100);
    expect(result).toBe("");
  });

  it("should handle single line file", () => {
    const result = formatWithLineNumbers("single line");
    expect(result).toBe("0: single line");
  });

  it("should handle empty content", () => {
    const result = formatWithLineNumbers("");
    expect(result).toBe("0: ");
  });

  it("should use 0-indexed line numbers matching search_code", () => {
    const content = "line one\nline two\nline three";
    const result = formatWithLineNumbers(content, 1, 1);
    expect(result).toBe("1: line two");
  });
});
