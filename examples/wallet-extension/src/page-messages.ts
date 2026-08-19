export const ALLOWED_PAGE_MESSAGES = new Set([
  "REQUEST_CONNECTION",
  "REQUEST_TRANSACTION",
  "REQUEST_SIGN",
  "GET_CHAIN_ID",
]);

export function isAllowedPageMessage(type: string): boolean {
  return ALLOWED_PAGE_MESSAGES.has(type);
}
