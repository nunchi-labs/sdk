export function parseRpcUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("RPC URL must be http or https");
  }
  return url;
}

export function rpcOriginPattern(rpcUrl: string): string {
  return `${parseRpcUrl(rpcUrl).origin}/*`;
}
