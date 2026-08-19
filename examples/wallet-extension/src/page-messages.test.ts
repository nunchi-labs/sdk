import { describe, it, expect } from "vitest";
import { isAllowedPageMessage } from "./page-messages";

describe("isAllowedPageMessage", () => {
  it("allows dApp connection and tx messages", () => {
    expect(isAllowedPageMessage("REQUEST_CONNECTION")).toBe(true);
    expect(isAllowedPageMessage("REQUEST_TRANSACTION")).toBe(true);
    expect(isAllowedPageMessage("REQUEST_SIGN")).toBe(true);
    expect(isAllowedPageMessage("GET_CHAIN_ID")).toBe(true);
  });

  it("blocks privileged types", () => {
    expect(isAllowedPageMessage("SEND_TRANSACTION")).toBe(false);
    expect(isAllowedPageMessage("APPROVE_TRANSACTION")).toBe(false);
    expect(isAllowedPageMessage("CREATE_WALLET")).toBe(false);
    expect(isAllowedPageMessage("GET_STATE")).toBe(false);
  });
});
