import { describe, it, expect } from "vitest";
import { randomRequestId } from "./ids";

describe("randomRequestId", () => {
  it("uses the prefix and 32 hex chars", () => {
    const id = randomRequestId("conn");
    expect(id).toMatch(/^conn-[0-9a-f]{32}$/);
  });

  it("produces unique ids", () => {
    const ids = new Set(Array.from({ length: 20 }, () => randomRequestId("tx")));
    expect(ids.size).toBe(20);
  });
});
