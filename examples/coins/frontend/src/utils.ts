export function compactHex(value: string | undefined, head = 8, tail = 6): string {
  if (!value) return "";
  if (value.length <= head + tail) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export function httpBase(raw: string): string {
  return raw.trim().replace(/\/$/, "");
}

export function wsBase(raw: string): string {
  const base = httpBase(raw);
  if (!base) {
    return `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}`;
  }
  if (base.startsWith("https://")) return `wss://${base.slice("https://".length)}`;
  if (base.startsWith("http://")) return `ws://${base.slice("http://".length)}`;
  return base;
}
