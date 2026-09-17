export function senderOrigin(sender: { origin?: string; url?: string }): string {
  if (sender.origin) {
    return sender.origin;
  }
  if (!sender.url) {
    return "";
  }
  try {
    return new URL(sender.url).origin;
  } catch {
    return "";
  }
}

export function isAllowedPageOrigin(origin: string): boolean {
  if (!origin || origin === "null") {
    return false;
  }
  try {
    const url = new URL(origin);
    return (url.protocol === "http:" || url.protocol === "https:") && url.origin === origin;
  } catch {
    return false;
  }
}

export function requirePageOrigin(origin: string): string {
  if (!isAllowedPageOrigin(origin)) {
    throw new Error("Missing sender origin");
  }
  return origin;
}
