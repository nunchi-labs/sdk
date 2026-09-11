import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Lock,
  Copy,
  Send as SendIcon,
  Activity,
  ArrowLeft,
  Check,
  Home as HomeIcon,
  Settings as SettingsIcon,
  Shield,
  ChevronDown,
  ChevronRight,
  Plus,
  KeyRound,
  Pencil,
  Repeat,
  RefreshCw,
  Search,
  ArrowDown,
  CreditCard,
  ExternalLink,
} from "lucide-react";
import type { Settings, SubmittedTx } from "./types";
import { BrandMark } from "./BrandMark";
import { rpcOriginPattern } from "./rpc";
import { applyTheme, loadTheme, saveTheme, watchSystemTheme, THEMES, type Theme } from "./theme";
import { TokenLogo } from "./TokenLogo";
import { PortfolioChart } from "./PortfolioChart";
import { Dropdown } from "./Dropdown";
import { AssetDetail } from "./AssetDetail";
import { MASK, loadHidden, saveHidden } from "./privacy";
import {
  TOKENS,
  tokenByCoinId,
  tokenLabel,
  formatUnits,
  formatUsd,
  usdValue,
  parseUnits,
  groupTypedAmount,
} from "./tokens";
import { coinIdChange, coinIdPrice, getPrices, type PriceSnapshot } from "./prices";

/**
 * Compiled-in only for `npm run build:demo` or the Vite dev server. Vite
 * replaces both env reads with literals, so in a normal build this is `false`
 * and every branch below it — including the ./demo import — is dropped.
 */
const DEMO_ENABLED = import.meta.env.VITE_DEMO === "1" || import.meta.env.DEV;
import "./popup.css";

type View =
  | "loading"
  | "onboarding"
  | "backup"
  | "unlock"
  | "main"
  | "send"
  | "approveConnection"
  | "approveTransaction";

type Tab = "home" | "activity" | "swap" | "settings";

interface AccountSummary {
  id: string;
  label: string;
  address: string;
  curve: string;
  active: boolean;
}

interface WalletInfo {
  hasWallet: boolean;
  isUnlocked: boolean;
  address?: string;
  curve?: string;
  needsBackup?: boolean;
}

function compactAddress(address: string, head = 10, tail = 8): string {
  if (address.length <= head + tail) return address;
  return `${address.slice(0, head)}...${address.slice(-tail)}`;
}

/**
 * Identicons carry no hue in the monotone scheme, so they vary by lightness
 * instead — two addresses still look different at a glance. The label flips to
 * dark text on the lighter shades so it stays readable across the whole ramp.
 */
function identiconShade(address: string): { background: string; color: string } {
  let hash = 0;
  for (let i = 0; i < address.length; i++) {
    hash = address.charCodeAt(i) + ((hash << 5) - hash);
  }
  const lightness = 26 + (Math.abs(hash) % 38);
  return {
    // Hue and saturation come from the theme, so identicons stay greyscale in
    // the monotone themes and pick up the ground in the colourful one. Only
    // lightness is derived from the address.
    background: `hsl(var(--identicon-hue) var(--identicon-sat) ${lightness}%)`,
    color: lightness > 52 ? "#141414" : "#f5f5f5",
  };
}

/**
 * Renders base units for a coin. Coins in the registry get their real decimals;
 * anything else (a custom coin id from Settings) falls back to the grouped
 * integer, because guessing a decimal place on someone's balance is worse than
 * showing the raw figure.
 */
function formatCoin(baseUnits: string, coinId?: string): string {
  const token = coinId ? tokenByCoinId(coinId) : undefined;
  if (!token) return formatAmount(baseUnits);
  // Show up to eight places: capping at six silently dropped real value on
  // 8- and 18-decimal coins (0.00026086 BTC rendered as 0.00026).
  return formatUnits(baseUnits, token.decimals, Math.min(token.decimals, 8));
}

/**
 * Group the digits of an integer amount so an eleven-digit balance is legible.
 * Parsed as BigInt because these are base units and must not lose precision;
 * anything that is not a plain integer is shown exactly as it arrived.
 */
function formatAmount(value: string): string {
  if (!/^\d+$/.test(value)) return value;
  try {
    return BigInt(value).toLocaleString("en-US");
  } catch {
    return value;
  }
}

function hostname(origin: string): string {
  try {
    return new URL(origin).hostname;
  } catch {
    return origin;
  }
}

function faviconUrl(origin: string): string {
  return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(hostname(origin))}&sz=32`;
}

function groupActivityByDate(items: SubmittedTx[]): { label: string; items: SubmittedTx[] }[] {
  const groups = new Map<string, SubmittedTx[]>();
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  for (const item of items) {
    const date = new Date(item.timestamp);
    const day = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    let label: string;
    if (day.getTime() === today.getTime()) {
      label = "Today";
    } else if (day.getTime() === yesterday.getTime()) {
      label = "Yesterday";
    } else {
      label = date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
    }
    const bucket = groups.get(label) ?? [];
    bucket.push(item);
    groups.set(label, bucket);
  }

  return Array.from(groups.entries()).map(([label, groupItems]) => ({ label, items: groupItems }));
}

function Identicon({ address, size = 32 }: { address: string; size?: number }) {
  const shade = identiconShade(address);
  const initial = address.replace(/^nch1/, "").charAt(0).toUpperCase() || "N";
  return (
    <div className="identiconRing">
      <div
        className="identicon"
        style={{
          width: size,
          height: size,
          background: shade.background,
          color: shade.color,
          fontSize: size * 0.4,
        }}
        aria-hidden
      >
        {initial}
      </div>
    </div>
  );
}

export interface Holding {
  coinId: string;
  balance: string;
}

/**
 * Sums holdings into one fiat figure and one 24h move.
 *
 * Coins with no price contribute nothing rather than being guessed at, and the
 * move only aggregates coins that actually trade — a wallet of reference-priced
 * coins has no move to report.
 */
function portfolioTotals(holdings: Holding[], prices: PriceSnapshot | null) {
  let usd = 0;
  let previousUsd = 0;
  let anyChange = false;

  for (const holding of holdings) {
    const token = tokenByCoinId(holding.coinId);
    const price = coinIdPrice(prices, holding.coinId);
    if (!token || !price || !/^\d+$/.test(holding.balance)) continue;

    const value = usdValue(holding.balance, token.decimals, price);
    usd += value;
    const percent = coinIdChange(prices, holding.coinId);
    if (percent === undefined) {
      previousUsd += value;
    } else {
      anyChange = true;
      previousUsd += value / (1 + percent / 100);
    }
  }

  return { usd, delta: usd - previousUsd, anyChange };
}

/** The hero figure is the portfolio's fiat value, not a token count. */
function PortfolioValue({ usd, error }: { usd: number; error?: string }) {
  const text = error ? "\u2014" : formatUsd(usd);
  const size = text.length > 15 ? "xs" : text.length > 12 ? "sm" : text.length > 9 ? "md" : "lg";
  return <span className={`heroValue balanceValue ${size}`}>{text}</span>;
}

/**
 * 24h move across the portfolio. Rendered only when something in it trades:
 * a flat 0% for reference-priced coins would be a claim we cannot make.
 */
function ChangeBadge({
  usd,
  delta,
  show,
  onOpen,
}: {
  usd: number;
  delta: number;
  show: boolean;
  onOpen?: () => void;
}) {
  if (!show || usd === 0) return null;
  const before = usd - delta;
  const percent = before === 0 ? 0 : (delta / before) * 100;
  const up = delta >= 0;
  return (
    <button
      type="button"
      className={`changeBadge ${up ? "up" : "down"}`}
      onClick={onOpen}
      aria-label="View balance over time"
    >
      <span className="changeAmount">
        {up ? "+" : "-"}
        {formatUsd(Math.abs(delta))}
      </span>
      <span className="changePill">
        {up ? "+" : "-"}
        {Math.abs(percent).toFixed(2)}%
      </span>
      <ChevronRight size={14} className="changeChevron" />
    </button>
  );
}

/** The same 24h move as the hero badge, sized for a list row. */
function RowChange({
  baseUnits,
  coinId,
  prices,
}: {
  baseUnits: string | null;
  coinId?: string;
  prices: PriceSnapshot | null;
}) {
  const token = coinId ? tokenByCoinId(coinId) : undefined;
  const price = coinId ? coinIdPrice(prices, coinId) : undefined;
  const percent = coinId ? coinIdChange(prices, coinId) : undefined;
  if (!token || !price || percent === undefined || !baseUnits || !/^\d+$/.test(baseUnits)) {
    return null;
  }
  const now = usdValue(baseUnits, token.decimals, price);
  const delta = now - now / (1 + percent / 100);
  const up = delta >= 0;
  return (
    <span className={`rowChange ${up ? "up" : "down"}`}>
      {up ? "+" : "-"}
      {formatUsd(Math.abs(delta))}
    </span>
  );
}

function FiatLine({
  baseUnits,
  coinId,
  prices,
  className = "fiatLine",
}: {
  baseUnits: string | null;
  coinId?: string;
  prices: PriceSnapshot | null;
  className?: string;
}) {
  const token = coinId ? tokenByCoinId(coinId) : undefined;
  const price = coinId ? coinIdPrice(prices, coinId) : undefined;
  if (!token || !price || !baseUnits || !/^\d+$/.test(baseUnits)) return null;
  return (
    <span className={className}>
      {formatUsd(usdValue(baseUnits, token.decimals, price))}
      {prices?.stale && <span className="staleTag">rate unavailable</span>}
    </span>
  );
}

function Toast({ message }: { message: string }) {
  return <div className="toast">{message}</div>;
}

function BrandLogo({ large }: { large?: boolean }) {
  return (
    <BrandMark className={`brandLogo ${large ? "large" : ""}`} />
  );
}

/**
 * Dev-only escape hatch: swaps in the fake backend from ./demo so the rest of
 * the UI can be explored without a wallet. Renders nothing in a normal build.
 */
function DemoBypass({ onActivate }: { onActivate: () => void }) {
  if (!DEMO_ENABLED) return null;
  return (
    <button type="button" className="demoBypass" onClick={onActivate}>
      <span className="demoBypassTag">demo</span>
      Skip setup and explore the UI
    </button>
  );
}

function LoadingScreen({ message = "Loading wallet..." }: { message?: string }) {
  return (
    <div className="loadingScreen">
      <BrandLogo large />
      <div className="loadingSpinner" />
      <p className="subtitle">{message}</p>
    </div>
  );
}

/**
 * Placeholder explorer. Swap this for the real one per network — the detail
 * view labels the link as an example so nobody mistakes it for live data.
 */
const EXPLORER_TX_URL = "https://explorer.example.com/tx/";

/**
 * Fiat on-ramp. A real Stripe Crypto Onramp URL is a per-session link created
 * by your server (Stripe's API mints it), so it cannot be hardcoded — point
 * this at your own endpoint that creates the session and redirects. The UI
 * badges it as an example until it is replaced.
 */
const ONRAMP_URL = "https://onramp.example.com/topup";
const ONRAMP_PROVIDER = "Stripe";

const TABS = [
  { id: "home", label: "Home", Icon: HomeIcon },
  { id: "activity", label: "Activity", Icon: Activity },
  { id: "swap", label: "Swap", Icon: Repeat },
  { id: "settings", label: "Settings", Icon: SettingsIcon },
] as const;

function TabBar({ active, onChange }: { active: Tab; onChange: (tab: Tab) => void }) {
  const index = TABS.findIndex((entry) => entry.id === active);
  return (
    <nav
      className="tabBar"
      aria-label="Wallet navigation"
      style={{ "--tab-count": TABS.length } as React.CSSProperties}
    >
      {/* Slides between tabs rather than cutting, so the movement itself shows
          which tab you came from and which one you landed on. */}
      <span
        className="tabIndicator"
        style={{ transform: `translateX(${index * 100}%)` }}
        aria-hidden
      />
      {TABS.map(({ id, label, Icon }) => (
        <button
          key={id}
          type="button"
          className={`tabItem ${active === id ? "active" : ""}`}
          aria-current={active === id ? "page" : undefined}
          onClick={() => onChange(id)}
        >
          <Icon size={20} />
          <span>{label}</span>
        </button>
      ))}
    </nav>
  );
}

function Shell({
  tab,
  onTabChange,
  opening,
  onOpened,
  children,
}: {
  tab: Tab;
  onTabChange: (tab: Tab) => void;
  opening?: boolean;
  onOpened?: () => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`shell withTabs ${opening ? "opening" : ""}`}
      onAnimationEnd={(event) => {
        // Child animations bubble; only the shell's own run means we are done.
        if (event.target === event.currentTarget) onOpened?.();
      }}
    >
      <main className="shellMain">{children}</main>
      <TabBar active={tab} onChange={onTabChange} />
    </div>
  );
}

function App() {
  const [view, setView] = useState<View>("loading");
  const [tab, setTab] = useState<Tab>("home");
  const [walletInfo, setWalletInfo] = useState<WalletInfo | null>(null);
  const [requestId, setRequestId] = useState("");
  const [opening, setOpening] = useState(false);
  /** Asset the send was started from, so Send opens on it rather than the first holding. */
  const [sendCoin, setSendCoin] = useState<string | undefined>();
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const approve = params.get("approve");
    const id = params.get("id") || "";
    if (approve === "connection" || approve === "transaction") {
      setRequestId(id);
      setView(approve === "connection" ? "approveConnection" : "approveTransaction");
      return;
    }
    void loadState();
  }, []);

  async function activateDemo() {
    if (!DEMO_ENABLED) return;
    const { installDemoBackend } = await import("./demo");
    installDemoBackend();
    setView("loading");
    void loadState({ opening: true });
  }

  /** `opening` plays the wallet-open animation when this load lands on main. */
  async function loadState(options?: { opening?: boolean }) {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_STATE" });
      if (response.success) {
        setWalletInfo(response.data);
        if (!response.data.hasWallet) {
          setView("onboarding");
        } else if (response.data.needsBackup) {
          setView("backup");
        } else if (!response.data.isUnlocked) {
          setView("unlock");
        } else {
          if (options?.opening) setOpening(true);
          setView("main");
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (view === "loading") {
    return <LoadingScreen />;
  }

  if (view === "approveConnection") {
    return <ApproveConnection requestId={requestId} />;
  }

  if (view === "approveTransaction") {
    return <ApproveTransaction requestId={requestId} />;
  }

  if (view === "onboarding") {
    return (
      <>
        <Onboarding onComplete={() => loadState()} />
        <DemoBypass onActivate={() => void activateDemo()} />
      </>
    );
  }

  if (view === "backup") {
    return <BackupView onComplete={() => loadState()} />;
  }

  if (view === "unlock") {
    return (
      <>
        <Unlock onUnlock={() => loadState({ opening: true })} />
        <DemoBypass onActivate={() => void activateDemo()} />
      </>
    );
  }

  if (view === "send" && walletInfo?.address) {
    return (
      <Send
        address={walletInfo.address}
        initialCoin={sendCoin}
        onBack={() => {
          setSendCoin(undefined);
          setView("main");
        }}
      />
    );
  }

  if (view === "main" && walletInfo?.address) {
    return (
      <Shell tab={tab} onTabChange={setTab} opening={opening} onOpened={() => setOpening(false)}>
        <div key={tab} className="tabPanel">
          {tab === "home" && (
            <Home
              onAccountChange={() => void loadState()}
              address={walletInfo.address}
              onSend={(coinId) => {
                setSendCoin(coinId);
                setView("send");
              }}
              onSwap={() => setTab("swap")}
              onLock={() => setView("unlock")}
              onSetupAsset={() => setTab("settings")}
            />
          )}
          {tab === "activity" && <ActivityView onSend={() => setView("send")} />}
          {tab === "swap" && <SwapView />}
          {tab === "settings" && <SettingsView onReload={() => loadState()} />}
        </div>
        {error && <div className="error">{error}</div>}
      </Shell>
    );
  }

  return null;
}

function Onboarding({ onComplete }: { onComplete: () => void }) {
  const [mode, setMode] = useState<"choice" | "create" | "import">("choice");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [privateKeyInput, setPrivateKeyInput] = useState("");
  const [curve, setCurve] = useState<"Ed25519" | "Secp256r1">("Ed25519");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleCreate() {
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "CREATE_WALLET",
        payload: { curve, password },
      });

      if (response.success) {
        onComplete();
      } else {
        setError(response.error || "Failed to create wallet");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleImport() {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (!privateKeyInput.trim()) {
      setError("Private key is required");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "IMPORT_WALLET",
        payload: { private_key_hex: privateKeyInput.trim(), password },
      });

      if (response.success) {
        onComplete();
      } else {
        setError(response.error || "Failed to import wallet");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  if (mode === "choice") {
    return (
      <div className="container">
        <div className="onboardingHero">
          <BrandMark className="logoMark" />
          <h1>Welcome to Nunchi</h1>
          <p className="subtitle">A friendly wallet for Nunchi chains. Set up in under a minute.</p>
        </div>
        <div className="choiceCards">
          <button className="choiceCard" onClick={() => setMode("create")}>
            <span className="choiceCardTitle">Create a new wallet</span>
            <span className="choiceCardDesc">Generate a fresh key secured by your password</span>
          </button>
          <button className="choiceCard" onClick={() => setMode("import")}>
            <span className="choiceCardTitle">Import existing wallet</span>
            <span className="choiceCardDesc">Restore from a private key you already have</span>
          </button>
        </div>
      </div>
    );
  }

  if (mode === "create") {
    return (
      <div className="container">
        <div className="pageHeader">
          <button className="back" onClick={() => setMode("choice")}>
            <ArrowLeft size={20} />
          </button>
          <h2>Create Wallet</h2>
        </div>
        <div className="progressDots">
          <div className="progressDot active" />
          <div className="progressDot" />
          <div className="progressDot" />
        </div>
        <div className="pageContent">
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" />
          </label>
          <label>
            <span>Confirm Password</span>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
          </label>
          <button className="advancedToggle" onClick={() => setShowAdvanced(!showAdvanced)}>
            {showAdvanced ? "Hide advanced" : "Advanced options"}
          </button>
          {showAdvanced && (
            <div className="field">
              <span className="fieldLabel">Curve</span>
              <Dropdown
                ariaLabel="Curve"
                value={curve}
                onChange={(next) => setCurve(next as "Ed25519" | "Secp256r1")}
                options={[
                  { value: "Ed25519", label: "Ed25519" },
                  { value: "Secp256r1", label: "Secp256r1", hint: "P-256" },
                ]}
              />
            </div>
          )}
          {error && <div className="error">{error}</div>}
        </div>
        <div className="stickyFooter">
          <button className="primary large" onClick={handleCreate} disabled={loading}>
            {loading ? "Creating..." : "Create wallet"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="pageHeader">
        <button className="back" onClick={() => setMode("choice")}>
          <ArrowLeft size={20} />
        </button>
        <h2>Import Wallet</h2>
      </div>
      <div className="pageContent">
        <label>
          <span>Private Key (hex)</span>
          <textarea
            value={privateKeyInput}
            onChange={(e) => setPrivateKeyInput(e.target.value)}
            placeholder="01..."
            rows={3}
          />
        </label>
        <label>
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" />
        </label>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="stickyFooter">
        <button className="primary large" onClick={handleImport} disabled={loading}>
          {loading ? "Importing..." : "Import wallet"}
        </button>
      </div>
    </div>
  );
}

function BackupView({ onComplete }: { onComplete: () => void }) {
  const [privateKey, setPrivateKey] = useState("");
  const [saved, setSaved] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void loadBackup();
  }, []);

  async function loadBackup() {
    setLoading(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({ type: "REVEAL_BACKUP" });
      if (response.success) {
        setPrivateKey(response.data.private_key_hex);
      } else if (response.error?.includes("Password required")) {
        setError("Unlock expired. Enter your password to reveal the backup key.");
      } else {
        setError(response.error || "Failed to reveal backup");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function revealWithPassword() {
    setLoading(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({
        type: "REVEAL_BACKUP",
        payload: { password },
      });
      if (response.success) {
        setPrivateKey(response.data.private_key_hex);
      } else {
        setError(response.error || "Failed to reveal backup");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="pageHeader">
        <Shield size={20} />
        <h2>Save Your Key</h2>
      </div>
      <div className="progressDots">
        <div className="progressDot" />
        <div className="progressDot active" />
        <div className="progressDot" />
      </div>
      <div className="pageContent">
        <div className="warningBanner">
          Write this down offline. Nunchi Wallet cannot recover a lost private key.
        </div>
        {loading && !privateKey && <div className="loading">Loading...</div>}
        {privateKey ? (
          <label>
            <span>Private Key</span>
            <textarea readOnly value={privateKey} rows={4} />
          </label>
        ) : (
          !loading && (
            <label>
              <span>Password</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
          )
        )}
        {error && <div className="error">{error}</div>}
        {privateKey && (
          <label className="checkRow">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            <span>I saved this private key in a safe place</span>
          </label>
        )}
      </div>
      <div className="stickyFooter">
        {!privateKey ? (
          <button className="primary large" onClick={() => void revealWithPassword()} disabled={loading || !password}>
            {loading ? "Revealing..." : "Reveal key"}
          </button>
        ) : (
          <button
            className="primary large"
            disabled={!saved}
            onClick={async () => {
              const response = await chrome.runtime.sendMessage({ type: "CONFIRM_BACKUP" });
              if (response.success) {
                onComplete();
              } else {
                setError(response.error || "Failed to confirm backup");
              }
            }}
          >
            Continue
          </button>
        )}
      </div>
    </div>
  );
}

function Unlock({ onUnlock }: { onUnlock: () => void }) {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleUnlock() {
    setLoading(true);
    setError("");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "UNLOCK_WALLET",
        payload: { password },
      });

      if (response.success) {
        onUnlock();
      } else {
        setError(response.error || "Failed to unlock wallet");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="unlockHero">
        <div className="unlockIcon">
          <Lock size={28} />
        </div>
        <h2>Welcome back</h2>
        <p className="subtitle">Enter your password to unlock</p>
      </div>
      <div className="pageContent">
        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleUnlock()}
            autoFocus
          />
        </label>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="stickyFooter">
        <button className="primary large" onClick={handleUnlock} disabled={loading}>
          {loading ? "Unlocking..." : "Unlock"}
        </button>
      </div>
    </div>
  );
}

/** One row of the token list: logo, name and amount, then value and 24h move. */
function TokenRow({
  coinId,
  balance,
  prices,
  onOpen,
  hidden,
}: {
  coinId: string;
  balance: string | null;
  prices: PriceSnapshot | null;
  onOpen: () => void;
  hidden?: boolean;
}) {
  const token = tokenByCoinId(coinId);
  const amount = balance ?? "0";

  return (
    <button type="button" className="assetCard assetRow" onClick={onOpen}>
      <TokenLogo coinId={coinId} size={40} />
      <div className="assetMeta">
        <span className="assetName">{token?.name ?? tokenLabel(coinId)}</span>
        <span className="assetSub">
          {balance === null
            ? "..."
            : hidden
              ? `${MASK} ${tokenLabel(coinId)}`
              : `${formatCoin(amount, coinId)} ${tokenLabel(coinId)}`}
        </span>
      </div>
      <div className="assetValue">
        {hidden ? (
          <span className="assetFiat masked">{MASK}</span>
        ) : (
          <>
            <FiatLine baseUnits={balance} coinId={coinId} prices={prices} className="assetFiat" />
            <RowChange baseUnits={balance} coinId={coinId} prices={prices} />
          </>
        )}
      </div>
      <ChevronRight size={16} className="assetChevron" />
    </button>
  );
}

function Home({
  onAccountChange,
  address,
  onSend,
  onSwap,
  onLock,
  onSetupAsset,
}: {
  onAccountChange: () => void;
  address: string;
  onSend: (coinId?: string) => void;
  onSwap: () => void;
  onLock: () => void;
  onSetupAsset: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [accounts, setAccounts] = useState<AccountSummary[] | null>(null);
  const [showAccounts, setShowAccounts] = useState(false);
  /** Coin whose asset page is open, if any. */
  const [assetOpen, setAssetOpen] = useState<string | null>(null);
  const [activity, setActivity] = useState<SubmittedTx[]>([]);
  const [holdings, setHoldings] = useState<{ coinId: string; balance: string }[] | null>(null);
  const [showTopUp, setShowTopUp] = useState(false);
  const [showChart, setShowChart] = useState(false);
  const [hidden, setHidden] = useState(loadHidden);
  const [balance, setBalance] = useState<string | null>(null);
  const [balanceLoading, setBalanceLoading] = useState(true);
  const [balanceError, setBalanceError] = useState("");
  const [settings, setSettings] = useState<Settings | null>(null);
  const [prices, setPrices] = useState<PriceSnapshot | null>(null);

  useEffect(() => {
    void load();
    void loadAccounts();
    void loadHoldings();
    void getPrices().then(setPrices);
    void chrome.runtime
      .sendMessage({ type: "GET_ACTIVITY" })
      .then((r) => setActivity(r.success ? r.data : []))
      .catch(() => setActivity([]));
  }, [address]);

  /**
   * Probes the backend for account management. The real Wallet rejects
   * GET_ACCOUNTS, so `accounts` stays null and the switcher never appears;
   * only a backend that answers it gets the UI.
   */
  /**
   * Multi-token holdings. A backend that does not answer this keeps the
   * original single display-coin view, so nothing regresses on a real build.
   */
  async function loadHoldings() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_HOLDINGS" });
      setHoldings(response.success ? response.data : null);
    } catch {
      setHoldings(null);
    }
  }

  async function loadAccounts() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_ACCOUNTS" });
      setAccounts(response.success ? (response.data as AccountSummary[]) : null);
    } catch {
      setAccounts(null);
    }
  }

  async function load() {
    setBalanceLoading(true);
    const settingsResponse = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (!settingsResponse.success) {
      setBalanceLoading(false);
      return;
    }
    const next: Settings = settingsResponse.data;
    setSettings(next);
    if (!next.displayCoin) {
      setBalance(null);
      setBalanceError("");
      setBalanceLoading(false);
      return;
    }
    const balanceResponse = await chrome.runtime.sendMessage({
      type: "GET_BALANCE",
      payload: { address, coin: next.displayCoin },
    });
    if (balanceResponse.success) {
      setBalance(balanceResponse.data.balance);
      setBalanceError("");
    } else {
      setBalance(null);
      setBalanceError(balanceResponse.error || "Failed to load balance");
    }
    setBalanceLoading(false);
  }

  async function copyAddress() {
    await navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  async function handleLock() {
    await chrome.runtime.sendMessage({ type: "LOCK_WALLET" });
    onLock();
  }

  if (showTopUp) {
    return <TopUp address={address} onBack={() => setShowTopUp(false)} />;
  }


  if (showAccounts && accounts) {
    return (
      <AccountsView
        accounts={accounts}
        onBack={() => setShowAccounts(false)}
        onChanged={() => {
          setShowAccounts(false);
          void loadAccounts();
          onAccountChange();
        }}
      />
    );
  }

  const activeAccount = accounts?.find((account) => account.active);

  // Holdings when the backend supports them, otherwise the single display coin.
  const rows: Holding[] =
    holdings && holdings.length > 0
      ? holdings
      : settings?.displayCoin
        ? [{ coinId: settings.displayCoin, balance: balance ?? "0" }]
        : [];
  const totals = portfolioTotals(rows, prices);
  if (assetOpen) {
    return (
      <AssetDetail
        coinId={assetOpen}
        balance={rows.find((r) => r.coinId === assetOpen)?.balance ?? balance}
        prices={prices}
        settings={settings}
        activity={activity}
        hidden={hidden}
        onBack={() => setAssetOpen(null)}
        onSend={(coin) => onSend(coin)}
        onSwap={onSwap}
        onReceive={() => void copyAddress()}
        onBuy={() => setShowTopUp(true)}
      />
    );
  }

  if (showChart) {
    return (
      <PortfolioChart
        holdings={rows}
        currentPrice={(coinId) => coinIdPrice(prices, coinId)}
        currentTotal={totals.usd}
        onBack={() => setShowChart(false)}
      />
    );
  }

  return (
    <>
      <div className="accountBar">
        <Identicon address={address} size={36} />
        <div className="accountMeta">
          {activeAccount && (
            <button className="accountName" onClick={() => setShowAccounts(true)}>
              {activeAccount.label}
              <ChevronDown size={14} />
            </button>
          )}
          <button className="accountAddress" onClick={() => void copyAddress()}>
            {compactAddress(address, 8, 6)}
            <Copy size={13} />
          </button>
        </div>
        <button className="icon" onClick={() => void handleLock()} aria-label="Lock wallet">
          <Lock size={18} />
        </button>
      </div>
      {copied && <Toast message="Address copied" />}

      <div className="balanceHero">
        <button
          type="button"
          className="balanceToggle"
          onClick={() => {
            const next = !hidden;
            setHidden(next);
            saveHidden(next);
          }}
          aria-pressed={hidden}
          aria-label={hidden ? "Show balance" : "Hide balance"}
          title={hidden ? "Show balance" : "Hide balance"}
        >
          {balanceLoading && !holdings ? (
            <div className="skeleton" />
          ) : hidden ? (
            <span className="heroValue balanceValue lg masked">{MASK}</span>
          ) : (
            <PortfolioValue usd={totals.usd} error={balanceError} />
          )}
        </button>
        <div className="heroSub">
          <span className="heroTokenAmount">
            {hidden
              ? `${rows.length} ${rows.length === 1 ? "token" : "tokens"}`
              : rows.length === 1
                ? `${formatCoin(rows[0].balance, rows[0].coinId)} ${tokenLabel(rows[0].coinId)}`
                : `${rows.length} tokens`}
          </span>
          {settings && <span className="heroNetwork">{settings.network || "Nunchi"}</span>}
        </div>
        <ChangeBadge
          usd={totals.usd}
          delta={totals.delta}
          show={totals.anyChange && !hidden}
          onOpen={() => setShowChart(true)}
        />
        {balanceError && <div className="error" style={{ marginTop: 12 }}>{balanceError}</div>}
      </div>

      <div className="quickActions">
        <button className="actionTile" onClick={() => onSend()}>
          <SendIcon size={20} />
          <span>Send</span>
        </button>
        <button className="actionTile" onClick={onSwap}>
          <Repeat size={20} />
          <span>Swap</span>
        </button>
        <button className="actionTile" onClick={() => void copyAddress()}>
          <Copy size={20} />
          <span>Receive</span>
        </button>
        <button className="actionTile" onClick={() => setShowTopUp(true)}>
          <CreditCard size={20} />
          <span>Buy</span>
        </button>
      </div>

      <div className="assetSection">
        <div className="assetsHeading">Tokens</div>
        {holdings && holdings.length > 0 ? (
          holdings.map((holding) => (
            <TokenRow
              key={holding.coinId}
              coinId={holding.coinId}
              balance={holding.balance}
              prices={prices}
              hidden={hidden}
              onOpen={() => setAssetOpen(holding.coinId)}
            />
          ))
        ) : settings?.displayCoin ? (
          <TokenRow
            coinId={settings.displayCoin}
            balance={balanceLoading ? null : (balance ?? "0")}
            prices={prices}
            hidden={hidden}
            onOpen={() => setAssetOpen(settings.displayCoin)}
          />
        ) : (
          <div className="emptyCard">
            <p className="subtitle">Add a display coin to see your balance here</p>
            <button className="secondary" onClick={onSetupAsset}>
              Open Settings
            </button>
          </div>
        )}
      </div>
    </>
  );
}

function Send({
  address,
  initialCoin,
  onBack,
}: {
  address: string;
  /** Skips the asset step when the send was started from a specific token. */
  initialCoin?: string;
  onBack: () => void;
}) {
  /** asset -> form -> confirm, mirroring how the send actually gets built up. */
  const [step, setStep] = useState<"asset" | "form" | "confirm">(initialCoin ? "form" : "asset");
  /**
   * Whether the picker was ever shown. Arriving with an asset already chosen
   * skips it, and back should retrace the route taken rather than drop the
   * user on a screen they never saw.
   */
  const [usedPicker, setUsedPicker] = useState(!initialCoin);
  const [coin, setCoin] = useState(initialCoin ?? "");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [query, setQuery] = useState("");
  const [holdings, setHoldings] = useState<Holding[] | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [prices, setPrices] = useState<PriceSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const hidden = loadHidden();
  const token = coin ? tokenByCoinId(coin) : undefined;
  const balance = holdings?.find((h) => h.coinId === coin)?.balance ?? null;
  const price = coin ? coinIdPrice(prices, coin) : undefined;

  /**
   * The payload is always base units. Whole-token entry only works for coins in
   * the registry, because that is where decimals come from — a custom coin id
   * has no known scale, so its amount is passed through as typed.
   */
  const amountBase = token ? parseUnits(amount, token.decimals) : amount || null;
  const overBalance =
    balance !== null && amountBase !== null && /^\d+$/.test(amountBase)
      ? BigInt(amountBase) > BigInt(balance)
      : false;
  const fiat =
    token && price && amountBase && /^\d+$/.test(amountBase)
      ? usdValue(amountBase, token.decimals, price)
      : 0;

  useEffect(() => {
    void getPrices().then(setPrices);
    void (async () => {
      const [config, held] = await Promise.all([
        chrome.runtime.sendMessage({ type: "GET_SETTINGS" }),
        chrome.runtime.sendMessage({ type: "GET_HOLDINGS" }),
      ]);
      if (config.success) setSettings(config.data);
      const options: Holding[] | null = held.success ? held.data : null;
      setHoldings(options);

      // Without a holdings list there is nothing to pick from, so fall back to
      // the configured display coin and go straight to the form.
      if (!options?.length) {
        const fallback = config.success ? config.data.displayCoin : "";
        if (fallback) {
          setCoin((current) => current || fallback);
          setStep((current) => (current === "asset" ? "form" : current));
          setUsedPicker(false);
        }
      }
    })();
  }, []);

  const visible = (holdings ?? []).filter((holding) => {
    if (!query.trim()) return true;
    const entry = tokenByCoinId(holding.coinId);
    const haystack = `${entry?.name ?? ""} ${entry?.symbol ?? ""} ${holding.coinId}`.toLowerCase();
    return haystack.includes(query.trim().toLowerCase());
  });

  async function send() {
    setLoading(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({
        type: "SEND_TRANSACTION",
        payload: { coin, from: address, to: recipient, amount: amountBase },
      });
      if (response.success) {
        setSuccess(true);
        setTimeout(() => onBack(), 2400);
      } else {
        setError(response.error || "Transaction failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  // The dots and the tick occupy the same centre of the same stage, so the
  // handoff reads as one motion rather than two screens.
  if (loading || success) {
    return (
      <div className="container">
        <div className="sendStage" role="status" aria-live="polite">
          <span className="sendStageMarks">
            <SendingDots done={success} />
            {success && <SuccessMark />}
          </span>
          <span className={`sendStageLabel ${success ? "done" : ""}`}>
            {success ? "Transaction successfully sent" : "Sending"}
          </span>
          <span className="srOnly">
            {success ? "Transaction successfully sent" : "Sending transaction"}
          </span>
        </div>
      </div>
    );
  }

  // ---- 1. Which asset ------------------------------------------------------
  if (step === "asset") {
    return (
      <div className="container">
        <div className="pageHeader">
          <button className="back" onClick={onBack} aria-label="Back">
            <ArrowLeft size={20} />
          </button>
          <h2>Select asset</h2>
        </div>
        <div className="pageContent">
          <div className="searchField">
            <Search size={17} />
            <input
              type="text"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search..."
              aria-label="Search assets"
            />
          </div>

          {holdings === null ? (
            <div className="loading">Loading...</div>
          ) : visible.length === 0 ? (
            <p className="subtitle">No assets match “{query}”.</p>
          ) : (
            <div className="assetList">
              {visible.map((holding) => (
                <button
                  key={holding.coinId}
                  type="button"
                  className="assetOption"
                  onClick={() => {
                    setCoin(holding.coinId);
                    setAmount("");
                    setError("");
                    setStep("form");
                  }}
                >
                  <TokenLogo coinId={holding.coinId} size={40} />
                  <div className="assetOptionMeta">
                    <span className="assetOptionName">
                      {tokenByCoinId(holding.coinId)?.name ?? tokenLabel(holding.coinId)}
                    </span>
                    <span className="assetOptionAmount">
                      {hidden ? MASK : formatCoin(holding.balance, holding.coinId)}{" "}
                      {tokenLabel(holding.coinId)}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  // ---- 2. Recipient and amount --------------------------------------------
  if (step === "form") {
    const ready = Boolean(recipient.trim()) && Boolean(amountBase) && amountBase !== "0" && !overBalance;
    return (
      <div className="container">
        <div className="pageHeader">
          <button
            className="back"
            onClick={() => (usedPicker && holdings?.length ? setStep("asset") : onBack())}
            aria-label="Back"
          >
            <ArrowLeft size={20} />
          </button>
          <h2>Send {tokenLabel(coin)}</h2>
        </div>
        <div className="pageContent withFooter">
          <div className="sendHero">
            <TokenLogo coinId={coin} size={72} />
          </div>

          <input
            className="sendField"
            type="text"
            value={recipient}
            onChange={(event) => setRecipient(event.target.value)}
            placeholder={`Recipient's ${tokenByCoinId(coin)?.name ?? "Nunchi"} address`}
            aria-label="Recipient address"
          />

          <div className="amountField">
            <input
              className="amountFieldInput"
              type="text"
              inputMode="decimal"
              value={token ? groupTypedAmount(amount) : amount}
              onChange={(event) => {
                setError("");
                if (!token) {
                  setAmount(event.target.value.replace(/[^\d]/g, ""));
                  return;
                }
                const raw = event.target.value.replace(/,/g, "").replace(/[^\d.]/g, "");
                const [whole, ...rest] = raw.split(".");
                const fraction = rest.join("").slice(0, token.decimals);
                setAmount(rest.length ? `${whole}.${fraction}` : whole);
              }}
              placeholder="Amount"
              aria-label={`Amount in ${tokenLabel(coin)}`}
            />
            <span className="amountFieldUnit">{tokenLabel(coin)}</span>
            {balance !== null && (
              <button
                type="button"
                className="maxButton"
                disabled={balance === "0"}
                onClick={() =>
                  setAmount(token ? formatCoin(balance, coin).replace(/,/g, "") : balance)
                }
              >
                Max
              </button>
            )}
          </div>

          <div className="sendMeta">
            <span>{price ? `~${formatUsd(fiat)}` : ""}</span>
            {balance !== null && (
              <span>
                Available {hidden ? MASK : formatCoin(balance, coin)} {tokenLabel(coin)}
              </span>
            )}
          </div>

          {overBalance && (
            <div className="error">
              {hidden
                ? `That is more ${tokenLabel(coin)} than you have`
                : `You only have ${formatCoin(balance ?? "0", coin)} ${tokenLabel(coin)}`}
            </div>
          )}
          {error && <div className="error">{error}</div>}
        </div>
        <div className="stickyFooter row">
          <button className="secondary large" onClick={onBack}>
            Cancel
          </button>
          <button className="primary large" onClick={() => setStep("confirm")} disabled={!ready}>
            Next
          </button>
        </div>
      </div>
    );
  }

  // ---- 3. Confirm ----------------------------------------------------------
  return (
    <div className="container">
      <div className="pageHeader">
        <button className="back" onClick={() => setStep("form")} aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <h2>Confirm send</h2>
      </div>
      <div className="pageContent withFooter">
        <div className="confirmHero">
          <SendIcon size={26} />
          <span className="confirmAmount">
            {amount} {tokenLabel(coin)}
          </span>
          {price ? <span className="confirmFiat">~{formatUsd(fiat)}</span> : null}
        </div>

        <div className="detailCard">
          <div className="detailRow">
            <span>To</span>
            <div className="mono">{compactAddress(recipient, 8, 6)}</div>
          </div>
          <div className="detailRow">
            <span>Network</span>
            <div className="mono">{settings?.network || settings?.chainId || "—"}</div>
          </div>
          <div className="detailRow">
            <span>Asset</span>
            <div className="mono">{tokenByCoinId(coin)?.name ?? compactAddress(coin, 8, 6)}</div>
          </div>
        </div>

        {error && <div className="error">{error}</div>}
      </div>
      <div className="stickyFooter row">
        <button className="secondary large" onClick={onBack} disabled={loading}>
          Cancel
        </button>
        <button className="primary large" onClick={() => void send()} disabled={loading}>
          {loading ? "Sending..." : "Send"}
        </button>
      </div>
    </div>
  );
}

function AccountsView({
  accounts,
  onBack,
  onChanged,
}: {
  accounts: AccountSummary[];
  onBack: () => void;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"list" | "add" | "import">("list");
  const [renaming, setRenaming] = useState<AccountSummary | null>(null);
  const [label, setLabel] = useState("");
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function reset() {
    setLabel("");
    setPrivateKeyHex("");
    setPassword("");
    setError("");
  }

  async function rename() {
    if (!renaming) return;
    setBusy(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({
        type: "RENAME_ACCOUNT",
        payload: { id: renaming.id, label },
      });
      if (!response.success) {
        setError(response.error || "Could not rename the account");
        return;
      }
      setRenaming(null);
      reset();
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  async function switchTo(id: string) {
    setError("");
    const response = await chrome.runtime.sendMessage({ type: "SWITCH_ACCOUNT", payload: { id } });
    if (!response.success) {
      setError(response.error || "Could not switch account");
      return;
    }
    onChanged();
  }

  async function submit() {
    setBusy(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({
        type: mode === "add" ? "ADD_ACCOUNT" : "IMPORT_ACCOUNT",
        payload: { label, password, privateKeyHex },
      });
      if (!response.success) {
        setError(response.error || "Could not add the account");
        return;
      }
      reset();
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  if (renaming) {
    return (
      <>
        <div className="pageHeader">
          <button
            className="back"
            onClick={() => {
              setRenaming(null);
              reset();
            }}
            aria-label="Back to accounts"
          >
            <ArrowLeft size={20} />
          </button>
          <h2>Rename account</h2>
        </div>
        <div className="pageContent">
          <p className="subtitle">
            Names are stored locally so you can tell accounts apart. They are never sent anywhere.
          </p>
          <label>
            <span>Name</span>
            <input
              type="text"
              value={label}
              autoFocus
              maxLength={40}
              onChange={(event) => setLabel(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void rename();
              }}
              placeholder={renaming.label}
            />
          </label>
          <div className="accountRenameAddress mono">{compactAddress(renaming.address, 12, 10)}</div>
          {error && <div className="error">{error}</div>}
          <button
            className="primary large"
            style={{ marginTop: "auto" }}
            onClick={() => void rename()}
            disabled={busy || !label.trim()}
          >
            {busy ? "Saving..." : "Save name"}
          </button>
        </div>
      </>
    );
  }

  if (mode !== "list") {
    const importing = mode === "import";
    return (
      <>
        <div className="pageHeader">
          <button
            className="back"
            onClick={() => {
              reset();
              setMode("list");
            }}
            aria-label="Back to accounts"
          >
            <ArrowLeft size={20} />
          </button>
          <h2>{importing ? "Import account" : "Add account"}</h2>
        </div>
        <div className="pageContent withFooter">
          <p className="subtitle">
            {importing
              ? "Restore an existing key into this wallet. It is encrypted with your password before it is stored."
              : "Generate a fresh key alongside your existing accounts, secured by the same password."}
          </p>
          <label>
            <span>Name</span>
            <input
              type="text"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder={`Account ${accounts.length + 1}`}
            />
          </label>
          {importing && (
            <label>
              <span>Private key (hex)</span>
              <textarea
                rows={3}
                value={privateKeyHex}
                onChange={(event) => setPrivateKeyHex(event.target.value.trim())}
                placeholder="64 hex characters"
              />
            </label>
          )}
          <label>
            <span>Password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Your wallet password"
            />
          </label>
          {error && <div className="error">{error}</div>}
          <button className="primary large" onClick={() => void submit()} disabled={busy || !password}>
            {busy ? "Working..." : importing ? "Import account" : "Create account"}
          </button>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="pageHeader">
        <button className="back" onClick={onBack} aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <h2>Accounts</h2>
      </div>
      <div className="pageContent">
        <div className="accountList">
          {accounts.map((account) => (
            <div
              key={account.id}
              className={`accountRow ${account.active ? "active" : ""}`}
              aria-current={account.active ? "true" : undefined}
            >
              <button
                type="button"
                className="accountRowSelect"
                onClick={() => void switchTo(account.id)}
              >
                <Identicon address={account.address} size={36} />
                <div className="accountRowMeta">
                  <span className="accountRowLabel">{account.label}</span>
                  <span className="accountRowAddress">{compactAddress(account.address, 10, 8)}</span>
                </div>
                {account.active && <Check size={18} />}
              </button>
              <button
                type="button"
                className="icon accountRename"
                aria-label={`Rename ${account.label}`}
                onClick={() => {
                  setRenaming(account);
                  setLabel(account.label);
                  setError("");
                }}
              >
                <Pencil size={15} />
              </button>
            </div>
          ))}
        </div>
        {error && <div className="error">{error}</div>}
        <div className="accountActions">
          <button className="secondary" onClick={() => setMode("add")}>
            <Plus size={16} />
            Add account
          </button>
          <button className="secondary" onClick={() => setMode("import")}>
            <KeyRound size={16} />
            Import
          </button>
        </div>
      </div>
    </>
  );
}

/** Swaps show both assets; a transfer shows the single send glyph. */
function ActivityIcon({ tx }: { tx: SubmittedTx }) {
  if (tx.kind === "swap" && tx.toCoin) {
    return (
      <div className="activityPair">
        <TokenLogo coinId={tx.coin} size={26} />
        <TokenLogo coinId={tx.toCoin} size={26} />
      </div>
    );
  }
  return (
    <div className="activityMark">
      <TokenLogo coinId={tx.coin} size={36} />
      <span className="activityBadge">
        <SendIcon size={9} />
      </span>
    </div>
  );
}

/** A swap moved value both ways, so it reports both legs rather than one. */
function ActivityAmounts({ tx }: { tx: SubmittedTx }) {
  if (tx.kind === "swap" && tx.toCoin) {
    return (
      <div className="activityAmounts">
        <span className="activityAmount out">
          -{formatCoin(tx.amount, tx.coin)} {tokenLabel(tx.coin)}
        </span>
        <span className="activityAmount in">
          +{formatCoin(tx.toAmount ?? "0", tx.toCoin)} {tokenLabel(tx.toCoin)}
        </span>
      </div>
    );
  }
  return (
    <div className="activityAmount">
      -{formatCoin(tx.amount, tx.coin)} {tokenLabel(tx.coin)}
    </div>
  );
}

function TxDetail({ tx, onBack }: { tx: SubmittedTx; onBack: () => void }) {
  const [copied, setCopied] = useState("");

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    setTimeout(() => setCopied(""), 1500);
  }

  const rows: { label: string; value: string; copyable?: boolean }[] = [
    ...(tx.kind === "swap"
      ? [
          { label: "Sold", value: `${formatCoin(tx.amount, tx.coin)} ${tokenLabel(tx.coin)}` },
          {
            label: "Received",
            value: `${formatCoin(tx.toAmount ?? "0", tx.toCoin)} ${tokenLabel(tx.toCoin ?? "")}`,
          },
        ]
      : [{ label: "To", value: tx.to, copyable: true }]),
    { label: "Coin", value: tx.coin, copyable: true },
    { label: "Transaction hash", value: tx.hash, copyable: true },
    { label: "Time", value: new Date(tx.timestamp).toLocaleString() },
  ];

  return (
    <>
      <div className="pageHeader">
        <button className="back" onClick={onBack} aria-label="Back to activity">
          <ArrowLeft size={20} />
        </button>
        <h2>Transaction</h2>
      </div>
      <div className="pageContent">
        <div className="txHero">
          <ActivityIcon tx={tx} />
          <span className="txHeroLabel">{tx.kind === "swap" ? "Swapped" : "Sent"}</span>
          <span className="txHeroAmount">
            -{formatCoin(tx.amount, tx.coin)} {tokenLabel(tx.coin)}
          </span>
          {tx.kind === "swap" && tx.toCoin && (
            <span className="txHeroAmount in">
              +{formatCoin(tx.toAmount ?? "0", tx.toCoin)} {tokenLabel(tx.toCoin)}
            </span>
          )}
        </div>

        <div className="txRows">
          {rows.map((row) => (
            <div key={row.label} className="txRow">
              <span className="txRowLabel">{row.label}</span>
              {row.copyable ? (
                <button
                  type="button"
                  className="txRowValue copyable"
                  onClick={() => copy(row.label, row.value)}
                  title={row.value}
                >
                  <span className="txRowText">{row.value}</span>
                  {copied === row.label ? <Check size={14} /> : <Copy size={14} />}
                </button>
              ) : (
                <span className="txRowValue">{row.value}</span>
              )}
            </div>
          ))}
        </div>

        <a
          className="explorerLink"
          href={`${EXPLORER_TX_URL}${tx.hash}`}
          target="_blank"
          rel="noreferrer noopener"
        >
          View on explorer
          <span className="explorerNote">example link</span>
        </a>
      </div>
    </>
  );
}

/**
 * Swap. No Nunchi endpoint backs this yet, so the view probes GET_SWAP_QUOTE
 * and shows an unavailable state when the backend rejects it, rather than
 * presenting a form that cannot submit.
 */
/** Keeps small rates meaningful: 1 Hexy into BTC would round to 0.000000. */
function formatRate(rate: number): string {
  if (!Number.isFinite(rate) || rate === 0) return "0.00";
  if (rate >= 1) {
    return rate.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 4 });
  }
  const decimals = Math.min(12, Math.max(2, Math.ceil(-Math.log10(rate)) + 4));
  return rate.toFixed(decimals).replace(/0+$/, "");
}

/**
 * Confirmation for a completed swap: a circle pops in and the tick draws
 * itself. Sits over the form rather than in the layout so nothing shifts under
 * it, and it is pointer-transparent so it never intercepts a tap.
 *
 * The label is for screen readers — the mark carries the meaning visually.
 */
/** Circle pops in, tick draws itself. Shared by the swap and send flows. */
function SuccessMark({ size = 92 }: { size?: number }) {
  return (
    <span className="successMarkWrap" style={{ width: size, height: size }}>
      <span className="successRing" aria-hidden />
      <svg className="successMark" viewBox="0 0 52 52" aria-hidden>
        <circle cx="26" cy="26" r="24" />
        <path d="M14.5 27 L22 34.5 L37.5 18" />
      </svg>
    </span>
  );
}

/** Three dots breathing in sequence while a transaction settles. */
function SendingDots({ done }: { done?: boolean }) {
  return (
    <span className={`sendingDots ${done ? "out" : ""}`} aria-hidden>
      <span />
      <span />
      <span />
    </span>
  );
}

function SwapComplete() {
  return (
    <div className="swapComplete" role="status" aria-live="polite">
      <SuccessMark />
      <span className="srOnly">Swap complete</span>
    </div>
  );
}

function TokenSelect({ value, onChange }: { value: string; onChange: (coinId: string) => void }) {
  return (
    <Dropdown
      className="tokenDropdown"
      ariaLabel="Coin"
      value={value}
      onChange={onChange}
      options={TOKENS.map((token) => ({
        value: token.coinId,
        label: token.symbol,
        hint: token.name,
        icon: <TokenLogo coinId={token.coinId} size={22} />,
      }))}
    />
  );
}

/** Hands off to an external on-ramp; the wallet never touches payment details. */
function TopUp({ address, onBack }: { address: string; onBack: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <>
      <div className="pageHeader">
        <button className="back" onClick={onBack} aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <h2>Add funds</h2>
      </div>
      <div className="pageContent">
        <p className="subtitle">
          Buying is handled by an external provider. You will leave the wallet to complete the
          purchase, and the funds arrive at the address below.
        </p>

        <div className="topUpAddress">
          <span className="txRowLabel">Your address</span>
          <button
            type="button"
            className="txRowValue copyable"
            onClick={async () => {
              await navigator.clipboard.writeText(address);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            <span className="txRowText">{address}</span>
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        </div>

        <a className="providerCard" href={ONRAMP_URL} target="_blank" rel="noreferrer noopener">
          <div className="providerIcon">
            <CreditCard size={18} />
          </div>
          <div className="providerMeta">
            <span className="providerName">
              {ONRAMP_PROVIDER}
              <span className="explorerNote">example link</span>
            </span>
            <span className="providerDesc">Card and bank transfer</span>
          </div>
          <ExternalLink size={16} />
        </a>

        <p className="subtitle topUpNote">
          Nunchi never sees your card details. Always check the address above matches the one the
          provider is sending to.
        </p>
      </div>
    </>
  );
}

function SwapView() {
  const [supported, setSupported] = useState<boolean | null>(null);
  const [amount, setAmount] = useState("");
  const [quote, setQuote] = useState<{
    out: string;
    rate: string;
    feeBps: number;
    stale?: boolean;
  } | null>(null);
  const [prices, setPrices] = useState<PriceSnapshot | null>(null);
  const [holdings, setHoldings] = useState<Record<string, string> | null>(null);
  const [error, setError] = useState("");
  /**
   * "working" clears the form while the swap settles, "done" holds the
   * confirmation on the empty canvas. Keeping it one value rather than two
   * booleans means the two states cannot both be true.
   */
  const [phase, setPhase] = useState<"form" | "working" | "done">("form");
  const [refreshing, setRefreshing] = useState(false);
  /** Bumped to force a re-quote when nothing else in the deps changed. */
  const [quoteNonce, setQuoteNonce] = useState(0);
  // Honours the same toggle as Home: hiding balances there and then finding
  // them printed here in full would defeat the point of the switch.
  const hidden = loadHidden();

  const [from, setFrom] = useState(TOKENS[0].coinId);
  const [to, setTo] = useState(TOKENS[1].coinId);

  const fromToken = tokenByCoinId(from);
  /** The typed amount converted to the base units every message expects. */
  const amountBase = fromToken ? parseUnits(amount, fromToken.decimals) : null;

  // Two different unknowns, and they must not be conflated: no holdings map at
  // all means the backend cannot tell us (show nothing), while a map without
  // this coin means the balance is genuinely zero (show "0", keep the guard).
  const fromBalance = holdings ? (holdings[from] ?? "0") : null;
  const toBalance = holdings ? (holdings[to] ?? "0") : null;
  const overBalance =
    fromBalance !== null && amountBase !== null && BigInt(amountBase) > BigInt(fromBalance);

  function flip() {
    setFrom(to);
    setTo(from);
  }

  async function loadHoldings() {
    const response = await chrome.runtime.sendMessage({ type: "GET_HOLDINGS" });
    setHoldings(
      response.success
        ? Object.fromEntries(
            (response.data as { coinId: string; balance: string }[]).map((h) => [
              h.coinId,
              h.balance,
            ]),
          )
        : null,
    );
  }

  /** Explicit rate refresh: skips the price cache and re-quotes on the way back. */
  async function refreshRates() {
    setRefreshing(true);
    setError("");
    try {
      // A cached-DNS fetch can return inside 50ms, which shows as a flicker and
      // reads as "nothing happened". Hold the spinner long enough to register.
      const [snapshot] = await Promise.all([
        getPrices(true),
        new Promise((resolve) => setTimeout(resolve, 450)),
      ]);
      setPrices(snapshot);
      setQuoteNonce((n) => n + 1);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void getPrices().then(setPrices);
    void loadHoldings();
    void (async () => {
      const probe = await chrome.runtime.sendMessage({
        type: "GET_SWAP_QUOTE",
        payload: { from: TOKENS[0].coinId, to: TOKENS[1].coinId, amount: "1000000" },
      });
      // A routing error still proves the endpoint exists; only a missing
      // handler means swapping is unsupported here.
      setSupported(probe.success || !/unknown message type/i.test(probe.error || ""));
    })();
  }, []);

  useEffect(() => {
    if (!amountBase || amountBase === "0") {
      setQuote(null);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      const response = await chrome.runtime.sendMessage({
        type: "GET_SWAP_QUOTE",
        payload: { from, to, amount: amountBase },
      });
      if (cancelled) return;
      setQuote(response.success ? response.data : null);
      setError(response.success ? "" : response.error || "");
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [amountBase, from, to, quoteNonce]);

  async function submit() {
    setPhase("working");
    setError("");
    try {
      // The demo settles in ~120ms, which would make the form blink out and
      // straight back. Hold the cleared state long enough to read as a step.
      const [response] = await Promise.all([
        chrome.runtime.sendMessage({ type: "SWAP", payload: { from, to, amount: amountBase } }),
        new Promise((resolve) => setTimeout(resolve, 550)),
      ]);
      if (!response.success) {
        setError(response.error || "Swap failed");
        setPhase("form");
        return;
      }
      setAmount("");
      setQuote(null);
      // Balances moved: refresh them here rather than waiting for a remount.
      // Other tabs remount when selected, so they pick this up on their own.
      await loadHoldings();
      setPhase("done");
      setTimeout(() => setPhase("form"), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase("form");
    }
  }

  if (supported === false) {
    return (
      <>
        <div className="pageHeader">
          <h1>Swap</h1>
        </div>
        <div className="pageContent">
          <div className="empty">
            <div className="emptyIcon">
              <Repeat size={22} />
            </div>
            <p>Swapping is not available on this network</p>
            <p className="subtitle">No swap route is exposed by the connected node.</p>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="pageHeader">
        <h1>Swap</h1>
        <button
          type="button"
          className="icon refreshRates"
          onClick={() => void refreshRates()}
          disabled={refreshing}
          aria-label="Refresh rates"
          title="Refresh rates"
        >
          <RefreshCw size={17} className={refreshing ? "spinning" : ""} />
        </button>
      </div>
      <div className="pageContent">
        <div className={`swapForm ${phase === "form" ? "" : "clearing"}`} aria-hidden={phase !== "form"}>
          <div className="swapLeg">
            <div className="swapLegTop">
              <span className="swapLegLabel">From</span>
              <TokenSelect value={from} onChange={setFrom} />
            </div>
            <input
              className="amountInput"
              type="text"
              inputMode="decimal"
              value={groupTypedAmount(amount)}
              onChange={(event) => {
                // Digits plus at most one decimal point, capped at the coin's precision.
                const raw = event.target.value.replace(/,/g, "").replace(/[^\d.]/g, "");
                const [whole, ...rest] = raw.split(".");
                const fraction = rest.join("").slice(0, fromToken?.decimals ?? 8);
                setAmount(rest.length ? `${whole}.${fraction}` : whole);
              }}
              placeholder="0"
              aria-label={`Amount in ${tokenLabel(from)}`}
            />
            <FiatLine baseUnits={amountBase} coinId={from} prices={prices} className="swapFiat" />
            {fromBalance !== null && (
              <div className="swapBalance">
                <span>
                  Balance {hidden ? MASK : formatCoin(fromBalance, from)} {tokenLabel(from)}
                </span>
                <button
                  type="button"
                  className="maxButton"
                  disabled={fromBalance === "0"}
                  onClick={() => setAmount(formatCoin(fromBalance, from).replace(/,/g, ""))}
                >
                  Max
                </button>
              </div>
            )}
        </div>

        <button type="button" className="swapArrow" onClick={flip} aria-label="Swap direction">
          <ArrowDown size={16} />
        </button>

        <div className="swapLeg receiving">
          <div className="swapLegTop">
            <span className="swapLegLabel">To</span>
            <TokenSelect value={to} onChange={setTo} />
          </div>
          <span className="swapOut">{quote ? formatCoin(quote.out, to) : "0.00"}</span>
          <span className="swapEstimate">estimated</span>
          <FiatLine baseUnits={quote?.out ?? null} coinId={to} prices={prices} className="swapFiat" />
          {toBalance !== null && (
            <div className="swapBalance">
              <span>
                Balance {hidden ? MASK : formatCoin(toBalance, to)} {tokenLabel(to)}
              </span>
            </div>
          )}
        </div>

        {quote && (
          <div className="swapMeta">
            <span>Rate</span>
            <span className="mono">
              1 {tokenLabel(from)} = {formatRate(Number(quote.rate))} {tokenLabel(to)}
            </span>
          </div>
        )}
        {quote && (
          <div className="swapMeta">
            <span>Fee</span>
            <span className="mono">{(quote.feeBps / 100).toFixed(2)}%</span>
          </div>
        )}

        {quote?.stale && (
          <div className="warningBanner">
            Live prices are unavailable right now, so this quote uses fallback rates.
          </div>
        )}
        </div>

        {phase === "working" && (
          <div className="swapWorking" role="status" aria-live="polite">
            <div className="loadingSpinner" />
            <span className="srOnly">Swapping</span>
          </div>
        )}
        {phase === "done" && <SwapComplete />}

        {overBalance && (
          <div className="error">
            {hidden
              ? `That is more ${tokenLabel(from)} than you have`
              : `You only have ${formatCoin(fromBalance ?? "0", from)} ${tokenLabel(from)}`}
          </div>
        )}
        {error && !overBalance && <div className="error">{error}</div>}

        <button
          className="primary large"
          style={{ marginTop: "auto" }}
          onClick={() => void submit()}
          disabled={phase !== "form" || !quote || overBalance}
        >
          {phase === "working" ? "Swapping..." : "Swap"}
        </button>
      </div>
    </>
  );
}

function ActivityView({ onSend }: { onSend?: () => void }) {
  const [activity, setActivity] = useState<SubmittedTx[]>([]);
  const [selected, setSelected] = useState<SubmittedTx | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void loadActivity();
  }, []);

  async function loadActivity() {
    const response = await chrome.runtime.sendMessage({ type: "GET_ACTIVITY" });
    if (response.success) {
      setActivity(response.data);
    }
    setLoading(false);
  }

  const groups = groupActivityByDate(activity);

  if (selected) {
    return <TxDetail tx={selected} onBack={() => setSelected(null)} />;
  }

  return (
    <>
      <div className="pageHeader">
        <h1>Activity</h1>
      </div>
      <div className="pageContent">
        {loading ? (
          <div className="loading">Loading...</div>
        ) : activity.length === 0 ? (
          <div className="empty">
            <div className="emptyIcon">
              <Activity size={22} />
            </div>
            <p>No transactions yet</p>
            {onSend && (
              <button className="primary" onClick={onSend} style={{ marginTop: 8 }}>
                Send your first transfer
              </button>
            )}
          </div>
        ) : (
          groups.map((group) => (
            <div key={group.label} className="activityGroup">
              <div className="activityGroupLabel">{group.label}</div>
              <div className="activityList">
                {group.items.map((tx) => (
                  <button
                    key={tx.hash}
                    type="button"
                    className="activityItem"
                    onClick={() => setSelected(tx)}
                  >
                    <ActivityIcon tx={tx} />
                    <div className="activityDetails">
                      <div className="activityTitle">
                        {tx.kind === "swap" ? "Swap" : "Sent"}
                      </div>
                      <div className="activitySub" title={tx.kind === "swap" ? undefined : tx.to}>
                        {tx.kind === "swap" && tx.toCoin
                          ? `${tokenLabel(tx.coin)} \u2192 ${tokenLabel(tx.toCoin)}`
                          : `To ${compactAddress(tx.to, 6, 4)}`}
                      </div>
                    </div>
                    <ActivityAmounts tx={tx} />
                  </button>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </>
  );
}

function ThemePicker() {
  const [theme, setTheme] = useState<Theme>(loadTheme);

  // A "system" choice has to keep up if the OS flips while the popup is open.
  useEffect(() => watchSystemTheme(() => theme), [theme]);

  const current = THEMES.find((entry) => entry.id === theme);

  function choose(next: Theme) {
    setTheme(next);
    saveTheme(next);
    applyTheme(next);
  }

  return (
    <div className="themeField field">
      <span className="fieldLabel">Theme</span>
      <Dropdown
        className="themeDropdown"
        ariaLabel="Theme"
        value={theme}
        onChange={(next) => choose(next as Theme)}
        options={THEMES.map((entry) => ({
          value: entry.id,
          label: entry.label,
          icon: <span className={`themeSwatch swatch-${entry.id}`} aria-hidden />,
        }))}
      />
      {current && <span className="themeHint">{current.hint}</span>}
    </div>
  );
}

function SettingsView({ onReload }: { onReload: () => void }) {
  const [settings, setSettings] = useState<Settings>({
    rpcUrl: "",
    network: "",
    chainId: "",
    displayCoin: "",
  });
  const [sites, setSites] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exportPassword, setExportPassword] = useState("");
  const [exportedKey, setExportedKey] = useState("");
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");

  useEffect(() => {
    void load();
  }, []);

  async function load() {
    const [settingsResponse, sitesResponse] = await Promise.all([
      chrome.runtime.sendMessage({ type: "GET_SETTINGS" }),
      chrome.runtime.sendMessage({ type: "GET_CONNECTED_SITES" }),
    ]);
    if (settingsResponse.success) {
      setSettings(settingsResponse.data);
    }
    if (sitesResponse.success) {
      setSites(sitesResponse.data);
    }
    setLoading(false);
  }

  async function saveSettings() {
    setError("");
    try {
      const origin = rpcOriginPattern(settings.rpcUrl);
      if (chrome.permissions?.request) {
        await chrome.permissions.request({ origins: [origin] });
      }
      const response = await chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", payload: settings });
      if (!response.success) {
        setError(response.error || "Failed to save settings");
        return;
      }
      onReload();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function disconnect(origin: string) {
    await chrome.runtime.sendMessage({ type: "DISCONNECT_SITE", payload: { origin } });
    setSites((current) => current.filter((site) => site !== origin));
  }

  async function exportKey() {
    setError("");
    const response = await chrome.runtime.sendMessage({
      type: "EXPORT_PRIVATE_KEY",
      payload: { password: exportPassword },
    });
    if (response.success) {
      setExportedKey(response.data.private_key_hex);
    } else {
      setError(response.error || "Export failed");
    }
  }

  async function deleteWallet() {
    if (deleteConfirm !== "DELETE") {
      setError("Type DELETE to confirm");
      return;
    }
    setError("");
    const response = await chrome.runtime.sendMessage({
      type: "DELETE_WALLET",
      payload: { password: deletePassword },
    });
    if (response.success) {
      onReload();
    } else {
      setError(response.error || "Delete failed");
    }
  }

  if (loading) {
    return (
      <div className="pageContent">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <>
      <div className="pageHeader">
        <h1>Settings</h1>
      </div>
      <div className="pageContent">
        <div className="settingsSection">
          <div className="sectionTitle">Appearance</div>
          <ThemePicker />

          <div className="sectionTitle">Network</div>
          <label>
            <span>Network name</span>
            <input type="text" value={settings.network} onChange={(e) => setSettings({ ...settings, network: e.target.value })} />
          </label>
          <label>
            <span>Chain ID</span>
            <input type="text" value={settings.chainId} onChange={(e) => setSettings({ ...settings, chainId: e.target.value })} />
          </label>
          <label>
            <span>RPC URL</span>
            <input type="text" value={settings.rpcUrl} onChange={(e) => setSettings({ ...settings, rpcUrl: e.target.value })} />
          </label>
          <label>
            <span>Display coin (hex)</span>
            <input
              type="text"
              value={settings.displayCoin}
              onChange={(e) => setSettings({ ...settings, displayCoin: e.target.value })}
              placeholder="32-byte coin id"
            />
          </label>
          <button className="primary large" onClick={() => void saveSettings()}>
            Save network settings
          </button>
        </div>

        <div className="settingsSection">
          <div className="sectionTitle">Connected sites</div>
          {sites.length === 0 ? (
            <div className="empty" style={{ padding: "16px 0" }}>
              <p className="subtitle">No connected sites</p>
            </div>
          ) : (
            sites.map((site) => (
              <div className="siteRow" key={site}>
                <div className="mono">{hostname(site)}</div>
                <button className="danger" onClick={() => void disconnect(site)}>
                  Disconnect
                </button>
              </div>
            ))
          )}
        </div>

        <div className="settingsSection">
          <div className="sectionTitle">Security</div>
          <label>
            <span>Password</span>
            <input type="password" value={exportPassword} onChange={(e) => setExportPassword(e.target.value)} />
          </label>
          {exportedKey && (
            <label>
              <span>Private Key</span>
              <textarea readOnly value={exportedKey} rows={3} />
            </label>
          )}
          <button className="secondary large" onClick={() => void exportKey()} disabled={!exportPassword}>
            Export private key
          </button>
        </div>

        <div className="settingsSection">
          <div className="sectionTitle">Danger zone</div>
          <div className="dangerZone">
            <p className="subtitle">Deleting your wallet removes all local data. Make sure you have your private key backed up.</p>
            <label>
              <span>Password</span>
              <input type="password" value={deletePassword} onChange={(e) => setDeletePassword(e.target.value)} />
            </label>
            <label>
              <span>Type DELETE to confirm</span>
              <input type="text" value={deleteConfirm} onChange={(e) => setDeleteConfirm(e.target.value)} />
            </label>
            <button className="danger large" onClick={() => void deleteWallet()} disabled={!deletePassword}>
              Delete wallet
            </button>
          </div>
        </div>

        {error && <div className="error">{error}</div>}
      </div>
    </>
  );
}

interface PendingConnectionView {
  kind: "connection";
  origin: string;
  address?: string;
}

interface PendingTransactionView {
  kind: "transaction";
  origin: string;
  nonce: number;
  coin: string;
  from: string;
  to: string;
  amount: string;
  submit?: boolean;
}

function ApproveConnection({ requestId }: { requestId: string }) {
  const [pending, setPending] = useState<PendingConnectionView | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    void loadRequest();
  }, [requestId]);

  async function loadRequest() {
    const response = await chrome.runtime.sendMessage({
      type: "GET_PENDING_REQUEST",
      payload: { requestId },
    });
    if (!response.success || response.data?.kind !== "connection") {
      setError(response.error || "Request not found or expired");
      return;
    }
    setPending(response.data);
  }

  async function decide(type: "APPROVE_CONNECTION" | "REJECT_CONNECTION") {
    setLoading(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({ type, payload: { requestId } });
      if (!response.success) {
        setError(response.error || "Request failed");
        setLoading(false);
        return;
      }
      window.close();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  if (error && !pending) {
    return (
      <div className="container approval">
        <div className="approvalHeader">
          <h2 className="approvalTitle">Connection Request</h2>
        </div>
        <div className="approvalBody">
          <div className="error">{error}</div>
        </div>
        <div className="approvalFooter">
          <button className="secondary large" onClick={() => window.close()} style={{ gridColumn: "1 / -1" }}>
            Close
          </button>
        </div>
      </div>
    );
  }

  if (!pending) {
    return (
      <div className="container">
        <div className="loading">Loading request...</div>
      </div>
    );
  }

  return (
    <div className="container approval">
      <div className="approvalHeader">
        <img className="siteFavicon" src={faviconUrl(pending.origin)} alt="" />
        <div>
          <div className="approvalTitle">Connect to site</div>
          <div className="approvalOrigin">{hostname(pending.origin)}</div>
        </div>
      </div>
      <div className="approvalBody">
        <p className="subtitle">This site will be able to view your public address.</p>
        <div className="detailCard">
          {pending.address && (
            <div className="detailRow">
              <span>Account</span>
              <div className="mono">{compactAddress(pending.address, 14, 10)}</div>
            </div>
          )}
          <div className="detailRow">
            <span>Origin</span>
            <div className="mono">{pending.origin}</div>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="approvalFooter">
        <button className="danger" onClick={() => decide("REJECT_CONNECTION")} disabled={loading}>
          Reject
        </button>
        <button className="primary" onClick={() => decide("APPROVE_CONNECTION")} disabled={loading}>
          {loading ? "Working..." : "Connect"}
        </button>
      </div>
    </div>
  );
}

function ApproveTransaction({ requestId }: { requestId: string }) {
  const [pending, setPending] = useState<PendingTransactionView | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    void loadRequest();
  }, [requestId]);

  async function loadRequest() {
    const response = await chrome.runtime.sendMessage({
      type: "GET_PENDING_REQUEST",
      payload: { requestId },
    });
    if (!response.success || response.data?.kind !== "transaction") {
      setError(response.error || "Request not found or expired");
      return;
    }
    setPending(response.data);
  }

  async function decide(type: "APPROVE_TRANSACTION" | "REJECT_TRANSACTION") {
    setLoading(true);
    setError("");
    try {
      const response = await chrome.runtime.sendMessage({ type, payload: { requestId } });
      if (!response.success) {
        setError(response.error || "Request failed");
        setLoading(false);
        return;
      }
      window.close();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  if (error && !pending) {
    return (
      <div className="container approval">
        <div className="approvalHeader">
          <h2 className="approvalTitle">Transaction Request</h2>
        </div>
        <div className="approvalBody">
          <div className="error">{error}</div>
        </div>
        <div className="approvalFooter">
          <button className="secondary large" onClick={() => window.close()} style={{ gridColumn: "1 / -1" }}>
            Close
          </button>
        </div>
      </div>
    );
  }

  if (!pending) {
    return (
      <div className="container">
        <div className="loading">Loading request...</div>
      </div>
    );
  }

  const submit = pending.submit !== false;

  return (
    <div className="container approval">
      <div className="approvalHeader">
        <img className="siteFavicon" src={faviconUrl(pending.origin)} alt="" />
        <div>
          <div className="approvalTitle">{submit ? "Send transaction" : "Sign transaction"}</div>
          <div className="approvalOrigin">{hostname(pending.origin)}</div>
        </div>
      </div>
      <div className="approvalBody">
        <div className="approvalAmount">
          <div className="approvalAmountLabel">You are sending</div>
          <div className="approvalAmountValue">{pending.amount}</div>
        </div>
        <p className="subtitle">
          {submit
            ? "Review this transfer before signing and submitting."
            : "Review before signing. This will not be submitted."}
        </p>
        <div className="detailCard">
          <div className="detailRow">
            <span>From</span>
            <div className="mono">{compactAddress(pending.from, 14, 10)}</div>
          </div>
          <div className="detailRow">
            <span>To</span>
            <div className="mono">{compactAddress(pending.to, 14, 10)}</div>
          </div>
          <div className="detailRow">
            <span>Coin</span>
            <div className="mono">{compactAddress(pending.coin, 10, 10)}</div>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="approvalFooter">
        <button className="danger" onClick={() => decide("REJECT_TRANSACTION")} disabled={loading}>
          Reject
        </button>
        <button className="primary" onClick={() => decide("APPROVE_TRANSACTION")} disabled={loading}>
          {loading ? "Working..." : submit ? "Confirm" : "Sign"}
        </button>
      </div>
    </div>
  );
}

applyTheme(loadTheme());
createRoot(document.getElementById("root")!).render(<App />);
