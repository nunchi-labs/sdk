import { describe, it, expect } from "vitest";
import { senderOrigin } from "./origin";

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
