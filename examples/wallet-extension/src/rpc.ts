export function parseRpcUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("RPC URL is invalid");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("RPC URL must be http or https");
  }
  if (url.username || url.password) {
    throw new Error("RPC URL must not contain credentials");
  }
  if (!url.hostname) {
    throw new Error("RPC URL is invalid");
  }
  return url;
}

export function rpcOriginPattern(rpcUrl: string): string {
  return `${parseRpcUrl(rpcUrl).origin}/*`;
}

/**
 * Parse a JSON-RPC body without rounding integers past `Number.MAX_SAFE_INTEGER`.
 * Account and factory nonces are `u64`. `JSON.parse` turns those into IEEE-754
 * values, so a nonce above 2^53-1 would be signed incorrectly.
 */
export function parseRpcResponse(text: string): { error?: { message: string }; result?: unknown } {
  const quoted = text.replace(/(-?\d{16,})(?=\s*[,}\]])/g, '"$1"');
  return JSON.parse(quoted) as { error?: { message: string }; result?: unknown };
}
