export function compactHex(value: Uint8Array | string | undefined, head = 8, tail = 6): string {
  if (!value) return "";
  const hex = typeof value === "string" ? value : bytesToHex(value);
  if (hex.length <= head + tail) return hex;
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array | null {
  const normalized = hex.trim().replace(/^0x/, "");
  if (!normalized || normalized.length % 2 !== 0 || /[^a-fA-F0-9]/.test(normalized)) {
    return null;
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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

export async function bytesFromResponse(response: Response): Promise<Uint8Array> {
  return new Uint8Array(await response.arrayBuffer());
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

export function numberField(value: unknown, key: string): number | null {
  const record = asRecord(value);
  const field = record?.[key];
  return typeof field === "number" && Number.isFinite(field) ? field : null;
}

export function bytesField(value: unknown, key: string): Uint8Array | null {
  const record = asRecord(value);
  const field = record?.[key];
  return field instanceof Uint8Array ? field : null;
}
