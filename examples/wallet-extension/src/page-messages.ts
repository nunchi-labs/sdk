export const ALLOWED_PAGE_MESSAGES = new Set([
  "REQUEST_CONNECTION",
  "REQUEST_TRANSACTION",
  "REQUEST_SIGN",
  "GET_CHAIN_ID",
]);

export const PAGE_REQUEST_TARGET = "nunchi-wallet-content";
export const PAGE_RESPONSE_TARGET = "nunchi-wallet-inpage";

export function isAllowedPageMessage(type: string): boolean {
  return ALLOWED_PAGE_MESSAGES.has(type);
}

export function isTrustedPageRequest(
  data: { type?: unknown; target?: unknown; token?: unknown },
  token: string
): boolean {
  return (
    !!token &&
    data.target === PAGE_REQUEST_TARGET &&
    data.token === token &&
    typeof data.type === "string" &&
    isAllowedPageMessage(data.type)
  );
}

export function isTrustedPageResponse(
  data: { target?: unknown; token?: unknown },
  token: string
): boolean {
  return !!token && data.target === PAGE_RESPONSE_TARGET && data.token === token;
}
