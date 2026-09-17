export function isPrivilegedSender(
  sender: { origin?: string; tab?: { url?: string } },
  extensionOrigin: string
): boolean {
  if (sender.origin !== extensionOrigin) {
    return false;
  }
  if (sender.tab?.url !== undefined && !sender.tab.url.startsWith(`${extensionOrigin}/`)) {
    return false;
  }
  return true;
}
