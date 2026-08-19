import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Lock, Copy, Send as SendIcon, Activity, Settings as SettingsIcon, ArrowLeft, Check } from "lucide-react";
import type { Settings, SubmittedTx } from "./types";
import "./popup.css";

type View = "loading" | "onboarding" | "unlock" | "home" | "send" | "activity" | "settings" | "approveConnection" | "approveTransaction";

interface WalletInfo {
  hasWallet: boolean;
  isUnlocked: boolean;
  address?: string;
  curve?: string;
}

function App() {
  const [view, setView] = useState<View>("loading");
  const [walletInfo, setWalletInfo] = useState<WalletInfo | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    loadState();
    const params = new URLSearchParams(window.location.search);
    const approve = params.get("approve");
    if (approve) {
      handleApprovalFlow(approve, params.get("id") || "");
    }
  }, []);

  async function loadState() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_STATE" });
      if (response.success) {
        setWalletInfo(response.data);
        if (!response.data.hasWallet) {
          setView("onboarding");
        } else if (!response.data.isUnlocked) {
          setView("unlock");
        } else {
          setView("home");
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleApprovalFlow(type: string, _requestId: string) {
    setView(type === "connection" ? "approveConnection" : "approveTransaction");
  }

  if (view === "loading") {
    return (
      <div className="container">
        <div className="loading">Loading wallet...</div>
      </div>
    );
  }

  if (view === "onboarding") {
    return <Onboarding onComplete={() => loadState()} />;
  }

  if (view === "unlock") {
    return <Unlock onUnlock={() => setView("home")} />;
  }

  return (
    <div className="container">
      {view === "home" && walletInfo && (
        <Home
          address={walletInfo.address!}
          onSend={() => setView("send")}
          onActivity={() => setView("activity")}
          onSettings={() => setView("settings")}
          onLock={() => setView("unlock")}
        />
      )}
      {view === "send" && walletInfo && <Send address={walletInfo.address!} onBack={() => setView("home")} />}
      {view === "activity" && <ActivityView onBack={() => setView("home")} />}
      {view === "settings" && <SettingsView onBack={() => setView("home")} />}
      {error && <div className="error">{error}</div>}
    </div>
  );
}

function Onboarding({ onComplete }: { onComplete: () => void }) {
  const [mode, setMode] = useState<"choice" | "create" | "import">("choice");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [privateKeyInput, setPrivateKeyInput] = useState("");
  const [curve, setCurve] = useState<"Ed25519" | "Secp256r1">("Ed25519");
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

      if (response.success && response.data) {
        setPrivateKeyInput(response.data.private_key_hex);
        setTimeout(() => onComplete(), 3000);
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
        <div className="header">
          <h1>Nunchi Wallet</h1>
          <p className="subtitle">Browser wallet for Nunchi chains</p>
        </div>
        <div className="content">
          <button className="primary large" onClick={() => setMode("create")}>
            Create New Wallet
          </button>
          <button className="secondary large" onClick={() => setMode("import")}>
            Import Wallet
          </button>
        </div>
      </div>
    );
  }

  if (mode === "create") {
    return (
      <div className="container">
        <div className="header">
          <button className="back" onClick={() => setMode("choice")}>
            <ArrowLeft size={20} />
          </button>
          <h2>Create Wallet</h2>
        </div>
        <div className="content">
          <label>
            <span>Curve</span>
            <select value={curve} onChange={(e) => setCurve(e.target.value as "Ed25519" | "Secp256r1")}>
              <option value="Ed25519">Ed25519</option>
              <option value="Secp256r1">Secp256r1 (P-256)</option>
            </select>
          </label>
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <label>
            <span>Confirm Password</span>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
          </label>
          {privateKeyInput && (
            <label>
              <span>Private Key (SAVE THIS!)</span>
              <textarea
                readOnly
                value={privateKeyInput}
                rows={3}
                style={{ fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}
              />
              <p style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>
                Save this private key securely. You'll need it to recover your wallet.
              </p>
            </label>
          )}
          {error && <div className="error">{error}</div>}
          <button className="primary large" onClick={handleCreate} disabled={loading}>
            {loading ? "Creating..." : "Create"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="header">
        <button className="back" onClick={() => setMode("choice")}>
          <ArrowLeft size={20} />
        </button>
        <h2>Import Wallet</h2>
      </div>
      <div className="content">
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
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="error">{error}</div>}
        <button className="primary large" onClick={handleImport} disabled={loading}>
          {loading ? "Importing..." : "Import"}
        </button>
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
      <div className="header">
        <Lock size={32} />
        <h2>Unlock Wallet</h2>
      </div>
      <div className="content">
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
        <button className="primary large" onClick={handleUnlock} disabled={loading}>
          {loading ? "Unlocking..." : "Unlock"}
        </button>
      </div>
    </div>
  );
}

function Home({
  address,
  onSend,
  onActivity,
  onSettings,
  onLock,
}: {
  address: string;
  onSend: () => void;
  onActivity: () => void;
  onSettings: () => void;
  onLock: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [balance] = useState<string | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    const response = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (response.success) {
      setSettings(response.data);
    }
  }

  async function copyAddress() {
    await navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleLock() {
    await chrome.runtime.sendMessage({ type: "LOCK_WALLET" });
    onLock();
  }

  return (
    <>
      <div className="header">
        <h1>Nunchi Wallet</h1>
        <div className="headerActions">
          <button className="icon" onClick={handleLock}>
            <Lock size={18} />
          </button>
          <button className="icon" onClick={onSettings}>
            <SettingsIcon size={18} />
          </button>
        </div>
      </div>
      <div className="content">
        <div className="addressCard">
          <div className="addressText">{compactAddress(address)}</div>
          <button className="icon" onClick={copyAddress}>
            {copied ? <Check size={16} /> : <Copy size={16} />}
          </button>
        </div>
        {settings && (
          <div className="networkBadge">
            {settings.network} ({settings.rpcUrl})
          </div>
        )}
        <div className="balanceSection">
          <div className="balanceLabel">Balance</div>
          <div className="balanceValue">{balance || "0"}</div>
        </div>
        <div className="actions">
          <button className="primary" onClick={onSend}>
            <SendIcon size={16} />
            Send
          </button>
          <button className="secondary" onClick={onActivity}>
            <Activity size={16} />
            Activity
          </button>
        </div>
      </div>
    </>
  );
}

function Send({ address, onBack }: { address: string; onBack: () => void }) {
  const [recipient, setRecipient] = useState("");
  const [coin, setCoin] = useState("");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  async function handleSend() {
    if (!recipient || !coin || !amount) {
      setError("All fields are required");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "REQUEST_TRANSACTION",
        payload: { coin, from: address, to: recipient, amount },
      });

      if (response.success) {
        setSuccess(true);
        setTimeout(() => onBack(), 2000);
      } else {
        setError(response.error || "Transaction failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <div className="container">
        <div className="header">
          <h2>Transaction Sent</h2>
        </div>
        <div className="content">
          <div className="success">
            <Check size={48} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="header">
        <button className="back" onClick={onBack}>
          <ArrowLeft size={20} />
        </button>
        <h2>Send</h2>
      </div>
      <div className="content">
        <label>
          <span>Recipient</span>
          <input
            type="text"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            placeholder="nch1..."
          />
        </label>
        <label>
          <span>Coin (hex)</span>
          <input type="text" value={coin} onChange={(e) => setCoin(e.target.value)} placeholder="a1b2c3..." />
        </label>
        <label>
          <span>Amount</span>
          <input type="text" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="1000" />
        </label>
        {error && <div className="error">{error}</div>}
        <button className="primary large" onClick={handleSend} disabled={loading}>
          {loading ? "Sending..." : "Send"}
        </button>
      </div>
    </>
  );
}

function ActivityView({ onBack }: { onBack: () => void }) {
  const [activity, setActivity] = useState<SubmittedTx[]>([]);

  useEffect(() => {
    loadActivity();
  }, []);

  async function loadActivity() {
    const response = await chrome.runtime.sendMessage({ type: "GET_ACTIVITY" });
    if (response.success) {
      setActivity(response.data);
    }
  }

  return (
    <>
      <div className="header">
        <button className="back" onClick={onBack}>
          <ArrowLeft size={20} />
        </button>
        <h2>Activity</h2>
      </div>
      <div className="content">
        {activity.length === 0 ? (
          <div className="empty">No transactions yet</div>
        ) : (
          <div className="activityList">
            {activity.map((tx) => (
              <div key={tx.hash} className="activityItem">
                <div className="activityIcon">
                  <SendIcon size={16} />
                </div>
                <div className="activityDetails">
                  <div className="activityTo">{compactAddress(tx.to)}</div>
                  <div className="activityTime">{new Date(tx.timestamp).toLocaleString()}</div>
                </div>
                <div className="activityAmount">{tx.amount}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function SettingsView({ onBack }: { onBack: () => void }) {
  const [settings, setSettings] = useState<Settings>({ rpcUrl: "", network: "" });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    const response = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (response.success) {
      setSettings(response.data);
      setLoading(false);
    }
  }

  async function saveSettings() {
    await chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", payload: settings });
    onBack();
  }

  if (loading) return <div className="container">Loading...</div>;

  return (
    <>
      <div className="header">
        <button className="back" onClick={onBack}>
          <ArrowLeft size={20} />
        </button>
        <h2>Settings</h2>
      </div>
      <div className="content">
        <label>
          <span>Network</span>
          <input type="text" value={settings.network} onChange={(e) => setSettings({ ...settings, network: e.target.value })} />
        </label>
        <label>
          <span>RPC URL</span>
          <input type="text" value={settings.rpcUrl} onChange={(e) => setSettings({ ...settings, rpcUrl: e.target.value })} />
        </label>
        <button className="primary large" onClick={saveSettings}>
          Save
        </button>
      </div>
    </>
  );
}

function compactAddress(address: string, head = 10, tail = 8): string {
  if (address.length <= head + tail) return address;
  return `${address.slice(0, head)}...${address.slice(-tail)}`;
}

createRoot(document.getElementById("root")!).render(<App />);
