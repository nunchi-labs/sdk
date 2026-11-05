import { describe, it, expect } from "vitest";
import { parseRpcResponse, parseRpcUrl, rpcOriginPattern } from "./rpc";

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

describe("parseRpcResponse", () => {
  it("preserves u64 nonces that do not fit in a JavaScript number", () => {
    const parsed = parseRpcResponse('{"jsonrpc":"2.0","id":1,"result":{"nonce":9007199254740993}}');
    expect((parsed.result as { nonce: string }).nonce).toBe("9007199254740993");
  });

  it("leaves small integers as numbers", () => {
    const parsed = parseRpcResponse('{"result":{"nonce":7,"amount":"42"}}');
    expect(parsed.result).toEqual({ nonce: 7, amount: "42" });
  });
});
