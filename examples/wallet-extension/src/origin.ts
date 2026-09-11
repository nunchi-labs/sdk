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
