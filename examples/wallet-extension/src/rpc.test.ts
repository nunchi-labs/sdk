import { describe, it, expect } from "vitest";
import { parseRpcUrl, rpcOriginPattern } from "./rpc";

describe("parseRpcUrl", () => {
  it("accepts http and https", () => {
    expect(parseRpcUrl("http://localhost:8545").origin).toBe("http://localhost:8545");
    expect(parseRpcUrl("https://rpc.example:443").protocol).toBe("https:");
  });

  it("rejects non-http schemes", () => {
    expect(() => parseRpcUrl("file:///tmp/rpc")).toThrow("http or https");
    expect(() => parseRpcUrl("javascript:alert(1)")).toThrow();
  });

  it("rejects embedded credentials", () => {
    expect(() => parseRpcUrl("https://user:pass@rpc.example")).toThrow("credentials");
  });

  it("rejects malformed URLs", () => {
    expect(() => parseRpcUrl("not a url")).toThrow("RPC URL is invalid");
  });
});

describe("rpcOriginPattern", () => {
  it("builds a host permission pattern", () => {
    expect(rpcOriginPattern("https://rpc.example/path")).toBe("https://rpc.example/*");
  });
});
