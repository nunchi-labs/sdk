import { describe, it, expect } from "vitest";
import { isPrivilegedSender } from "./privilege";

const EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef";

describe("isPrivilegedSender", () => {
  it("allows the extension popup with no tab", () => {
    expect(isPrivilegedSender({ origin: EXTENSION_ORIGIN }, EXTENSION_ORIGIN)).toBe(true);
  });

  it("allows an extension page opened as a tab", () => {
    expect(
      isPrivilegedSender(
        { origin: EXTENSION_ORIGIN, tab: { url: `${EXTENSION_ORIGIN}/popup.html?approve=connection` } },
        EXTENSION_ORIGIN
      )
    ).toBe(true);
  });

  it("rejects a web page origin", () => {
    expect(
      isPrivilegedSender(
        { origin: "https://evil.example", tab: { url: "https://evil.example/" } },
        EXTENSION_ORIGIN
      )
    ).toBe(false);
  });

  it("rejects an extension origin paired with a web tab url", () => {
    expect(
      isPrivilegedSender(
        { origin: EXTENSION_ORIGIN, tab: { url: "https://evil.example/" } },
        EXTENSION_ORIGIN
      )
    ).toBe(false);
  });

  it("rejects a sender whose origin is not the extension", () => {
    expect(
      isPrivilegedSender({ origin: "https://evil.example" }, EXTENSION_ORIGIN)
    ).toBe(false);
  });
});
