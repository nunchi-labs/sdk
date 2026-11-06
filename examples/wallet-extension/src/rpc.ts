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
 *
 * Quoting is limited to bare JSON numbers. Digits that already sit inside a
 * string, such as a nonce cited by an error message, are left unchanged.
 */
export function parseRpcResponse(text: string): { error?: { message: string }; result?: unknown } {
  return JSON.parse(quoteLargeJsonIntegers(text)) as { error?: { message: string }; result?: unknown };
}

const LARGE_JSON_INT = /(-?\d{16,})(?=\s*[,}\]])/g;

function quoteLargeJsonIntegers(text: string): string {
  let quoted = "";
  let index = 0;
  while (index < text.length) {
    if (text[index] !== '"') {
      const nextString = text.indexOf('"', index);
      const end = nextString === -1 ? text.length : nextString;
      quoted += text.slice(index, end).replace(LARGE_JSON_INT, '"$1"');
      index = end;
      continue;
    }
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === '"') {
        index += 1;
        break;
      }
      index += 1;
    }
    quoted += text.slice(start, index);
  }
  return quoted;
}
