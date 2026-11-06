import { describe, expect, it } from "vitest";
import { formatUnitsExact, parseUnits } from "./tokens";

describe("formatUnitsExact", () => {
  it("keeps every base unit so Max can send the full balance", () => {
    expect(formatUnitsExact("1", 18)).toBe("0.000000000000000001");
    expect(parseUnits(formatUnitsExact("1", 18), 18)).toBe("1");
    expect(formatUnitsExact("1000000000000000001", 18)).toBe("1.000000000000000001");
    expect(parseUnits(formatUnitsExact("1000000000000000001", 18), 18)).toBe("1000000000000000001");
  });

  it("drops a trailing decimal when the balance is a whole token", () => {
    expect(formatUnitsExact("1000000", 6)).toBe("1");
    expect(formatUnitsExact("0", 6)).toBe("0");
    expect(formatUnitsExact("5", 0)).toBe("5");
  });
});
