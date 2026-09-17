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
