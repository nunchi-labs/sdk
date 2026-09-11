/**
 * Balance privacy toggle.
 *
 * Persisted like the theme: it has to survive the tab remount that happens on
 * every switch, and someone who hid their balances does not expect them back
 * the next time the popup opens.
 */
const KEY = "nunchi.hideBalances";

export function loadHidden(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function saveHidden(hidden: boolean): void {
  try {
    localStorage.setItem(KEY, hidden ? "1" : "0");
  } catch {
    /* preference simply will not persist */
  }
}

/** Stand-in for any hidden figure, so callers never format a real number. */
export const MASK = "•••••";
