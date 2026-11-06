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

/**
 * Origin to pass to `window.postMessage`. `*` would deliver the bridge token
 * and any signed transaction to whatever document occupies the window after a
 * navigation. Opaque frames use the literal origin `"null"`.
 */
export function pageTargetOrigin(origin: string): string {
  if (isAllowedPageOrigin(origin)) {
    return origin;
  }
  return "null";
}
