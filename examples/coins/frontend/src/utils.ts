export function compactHex(value: string | undefined, head = 8, tail = 6): string {
  if (!value) return "";
  if (value.length <= head + tail) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export function httpBase(raw: string): string {
  return raw.trim().replace(/\/$/, "");
}

export function wsBase(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}`;
  }
  // A scheme is only present when it is followed by ://. `host:port` also
  // contains a colon and must not be treated as a URL scheme.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error("backend URL is not a valid http(s) or ws(s) URL");
  }
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  else if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error("backend URL must be http, https, ws, or wss");
  }
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export function nextReconnectDelay(previous: number): number {
  if (!Number.isFinite(previous) || previous < 1000) return 1000;
  return Math.min(previous * 2, 30_000);
}
