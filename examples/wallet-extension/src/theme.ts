/**
 * Theme selection.
 *
 * Stored in localStorage rather than wallet settings on purpose: the theme is
 * a local display preference, so it needs no round trip to the background and
 * adds nothing to the message contract. localStorage is also synchronous,
 * which lets the theme be applied before first paint — chrome.storage would
 * flash the default theme first.
 */
export type Theme = "system" | "dark" | "light";

export const THEMES: { id: Theme; label: string; hint: string }[] = [
  { id: "system", label: "System", hint: "Follow your OS setting" },
  { id: "dark", label: "Dark", hint: "Monotone, dark ground" },
  { id: "light", label: "Light", hint: "Monotone, light ground" },
];

const KEY = "nunchi.theme";

function isTheme(value: string | null): value is Theme {
  // A stored theme that no longer exists (a retired one) fails this check and
  // falls back to the default, so no one is stranded on a missing palette.
  return value === "system" || value === "dark" || value === "light";
}

export function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem(KEY);
    return isTheme(stored) ? stored : "dark";
  } catch {
    // Private mode or blocked storage: fall back rather than fail to render.
    return "dark";
  }
}

export function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* preference simply will not persist */
  }
}

function prefersDark(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Resolves "system" to a concrete theme and stamps it on the document. */
export function applyTheme(theme: Theme): void {
  const resolved = theme === "system" ? (prefersDark() ? "dark" : "light") : theme;
  document.documentElement.setAttribute("data-theme", resolved);
}

/** Keeps a "system" choice in step if the OS flips while the popup is open. */
export function watchSystemTheme(getTheme: () => Theme): () => void {
  if (typeof matchMedia !== "function") return () => {};
  const query = matchMedia("(prefers-color-scheme: dark)");
  const handler = () => {
    if (getTheme() === "system") applyTheme("system");
  };
  query.addEventListener("change", handler);
  return () => query.removeEventListener("change", handler);
}
