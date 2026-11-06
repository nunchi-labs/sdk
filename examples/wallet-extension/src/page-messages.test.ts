import { describe, it, expect } from "vitest";
import {
  isAllowedPageMessage,
  isTrustedPageEvent,
  isTrustedPageRequest,
  isTrustedPageResponse,
  PAGE_EVENT_TARGET,
  PAGE_REQUEST_TARGET,
  PAGE_RESPONSE_TARGET,
} from "./page-messages";

describe("isAllowedPageMessage", () => {
  it("allows dApp connection and tx messages", () => {
    expect(isAllowedPageMessage("REQUEST_CONNECTION")).toBe(true);
    expect(isAllowedPageMessage("REQUEST_TRANSACTION")).toBe(true);
    expect(isAllowedPageMessage("REQUEST_SIGN")).toBe(true);
    expect(isAllowedPageMessage("GET_CHAIN_ID")).toBe(true);
    expect(isAllowedPageMessage("GET_ACCOUNTS")).toBe(true);
    expect(isAllowedPageMessage("DISCONNECT")).toBe(true);
  });

  it("blocks privileged types", () => {
    expect(isAllowedPageMessage("SEND_TRANSACTION")).toBe(false);
    expect(isAllowedPageMessage("APPROVE_TRANSACTION")).toBe(false);
    expect(isAllowedPageMessage("CREATE_WALLET")).toBe(false);
    expect(isAllowedPageMessage("GET_STATE")).toBe(false);
    expect(isAllowedPageMessage("GET_HOLDINGS")).toBe(false);
    expect(isAllowedPageMessage("SWAP")).toBe(false);
    expect(isAllowedPageMessage("SWITCH_ACCOUNT")).toBe(false);
  });
});

describe("isTrustedPageRequest", () => {
  const token = "tok-abc";

  it("requires target, token, and an allowed type", () => {
    expect(
      isTrustedPageRequest({ type: "REQUEST_CONNECTION", target: PAGE_REQUEST_TARGET, token }, token)
    ).toBe(true);
    expect(
      isTrustedPageRequest({ type: "REQUEST_CONNECTION", target: PAGE_REQUEST_TARGET, token: "other" }, token)
    ).toBe(false);
    expect(isTrustedPageRequest({ type: "REQUEST_CONNECTION", token }, token)).toBe(false);
    expect(
      isTrustedPageRequest({ type: "SEND_TRANSACTION", target: PAGE_REQUEST_TARGET, token }, token)
    ).toBe(false);
  });

  it("rejects an empty token", () => {
    expect(
      isTrustedPageRequest({ type: "REQUEST_CONNECTION", target: PAGE_REQUEST_TARGET, token: "" }, "")
    ).toBe(false);
  });
});

describe("isTrustedPageResponse", () => {
  it("requires the response target and token", () => {
    expect(isTrustedPageResponse({ target: PAGE_RESPONSE_TARGET, token: "tok" }, "tok")).toBe(true);
    expect(isTrustedPageResponse({ target: PAGE_RESPONSE_TARGET, token: "tok" }, "other")).toBe(false);
    expect(isTrustedPageResponse({ target: PAGE_REQUEST_TARGET, token: "tok" }, "tok")).toBe(false);
  });
});

describe("isTrustedPageEvent", () => {
  it("requires the event target, token, and event name", () => {
    expect(
      isTrustedPageEvent({ target: PAGE_EVENT_TARGET, token: "tok", event: "accountsChanged" }, "tok")
    ).toBe(true);
    expect(isTrustedPageEvent({ target: PAGE_EVENT_TARGET, token: "tok" }, "tok")).toBe(false);
    expect(
      isTrustedPageEvent({ target: PAGE_EVENT_TARGET, token: "other", event: "accountsChanged" }, "tok")
    ).toBe(false);
  });
});
