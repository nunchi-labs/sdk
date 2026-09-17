import { describe, it, expect } from "vitest";
import { isAllowedPageOrigin, requirePageOrigin, senderOrigin } from "./origin";

describe("senderOrigin", () => {
  it("prefers origin when present", () => {
    expect(senderOrigin({ origin: "https://app.example", url: "https://other.example/x" })).toBe(
      "https://app.example"
    );
  });

  it("falls back to a valid url origin", () => {
    expect(senderOrigin({ url: "https://app.example/path" })).toBe("https://app.example");
  });

  it("returns empty string when origin and url are missing", () => {
    expect(senderOrigin({})).toBe("");
  });

  it("returns empty string for an invalid url", () => {
    expect(senderOrigin({ url: "not a url" })).toBe("");
  });
});

describe("isAllowedPageOrigin", () => {
  it("allows http and https origins", () => {
    expect(isAllowedPageOrigin("https://dapp.example")).toBe(true);
    expect(isAllowedPageOrigin("http://127.0.0.1:8545")).toBe(true);
  });

  it("rejects opaque, file, and extension origins", () => {
    expect(isAllowedPageOrigin("")).toBe(false);
    expect(isAllowedPageOrigin("null")).toBe(false);
    expect(isAllowedPageOrigin("file://")).toBe(false);
    expect(isAllowedPageOrigin("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef")).toBe(false);
    expect(() => requirePageOrigin("null")).toThrow("Missing sender origin");
  });
});
