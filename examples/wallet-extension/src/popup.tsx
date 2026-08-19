import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Lock, Copy, Send as SendIcon, Activity, Settings as SettingsIcon, ArrowLeft, Check } from "lucide-react";
import type { Settings, SubmittedTx } from "./types";
import { rpcOriginPattern } from "./rpc";
import "./popup.css";

type View =
  | "loading"
  | "onboarding"
  | "backup"
  | "unlock"
  | "home"
  | "send"
  | "activity"
  | "settings"
  | "approveConnection"
  | "approveTransaction";

interface WalletInfo {
  hasWallet: boolean;
  isUnlocked: boolean;
  address?: string;
  curve?: string;
  needsBackup?: boolean;
}

function App() {
  const [view, setView] = useState<View>("loading");
  const [walletInfo, setWalletInfo] = useState<WalletInfo | null>(null);
  const [requestId, setRequestId] = useState("");
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

  async function loadState() {
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
          setView("home");
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (view === "loading") {
    return (
      <div className="container">
        <div className="loading">Loading wallet...</div>
      </div>
    );
  }

  if (view === "approveConnection") {
    return <ApproveConnection requestId={requestId} />;
  }

  if (view === "approveTransaction") {
    return <ApproveTransaction requestId={requestId} />;
  }

  if (view === "onboarding") {
    return <Onboarding onComplete={() => loadState()} />;
  }

  if (view === "backup") {
    return <BackupView onComplete={() => loadState()} />;
  }

  if (view === "unlock") {
    return <Unlock onUnlock={() => loadState()} />;
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
      {view === "settings" && <SettingsView onBack={() => loadState()} />}
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
      <div className="header">
        <h2>Save Your Key</h2>
      </div>
      <div className="content">
        <p className="subtitle">This is the only time the wallet shows your private key. Store it offline.</p>
        {privateKey ? (
          <label>
            <span>Private Key</span>
            <textarea readOnly value={privateKey} rows={4} />
          </label>
        ) : (
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
        )}
        {error && <div className="error">{error}</div>}
        {!privateKey && (
          <button className="primary large" onClick={() => void revealWithPassword()} disabled={loading || !password}>
            {loading ? "Revealing..." : "Reveal key"}
          </button>
        )}
        {privateKey && (
          <>
            <label className="checkRow">
              <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
              <span>I saved this private key in a safe place</span>
            </label>
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
          </>
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
  const [balance, setBalance] = useState<string | null>(null);
  const [balanceError, setBalanceError] = useState("");
  const [settings, setSettings] = useState<Settings | null>(null);

  useEffect(() => {
    void load();
  }, [address]);

  async function load() {
    const settingsResponse = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (!settingsResponse.success) {
      return;
    }
    const next: Settings = settingsResponse.data;
    setSettings(next);
    if (!next.displayCoin) {
      setBalance(null);
      setBalanceError("");
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
            {settings.network} / {settings.chainId} ({settings.rpcUrl})
          </div>
        )}
        <div className="balanceSection">
          <div className="balanceLabel">Balance</div>
          {settings?.displayCoin ? (
            <>
              <div className="balanceValue">{balance ?? (balanceError ? "-" : "...")}</div>
              <div className="subtitle">{compactAddress(settings.displayCoin, 8, 8)}</div>
            </>
          ) : (
            <div className="subtitle">Set a display coin in Settings to load a balance</div>
          )}
          {balanceError && <div className="error">{balanceError}</div>}
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

  useEffect(() => {
    void chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).then((response) => {
      if (response.success && response.data.displayCoin) {
        setCoin(response.data.displayCoin);
      }
    });
  }, []);

  async function handleSend() {
    if (!recipient || !coin || !amount) {
      setError("All fields are required");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await chrome.runtime.sendMessage({
        type: "SEND_TRANSACTION",
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
    void loadActivity();
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
      onBack();
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
      onBack();
    } else {
      setError(response.error || "Delete failed");
    }
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
          Save
        </button>

        <h2>Connected Sites</h2>
        {sites.length === 0 ? (
          <div className="empty">No connected sites</div>
        ) : (
          sites.map((site) => (
            <div className="detailRow" key={site}>
              <div className="mono">{site}</div>
              <button className="danger" onClick={() => void disconnect(site)}>
                Disconnect
              </button>
            </div>
          ))
        )}

        <h2>Export Key</h2>
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
          Export
        </button>

        <h2>Delete Wallet</h2>
        <label>
          <span>Password</span>
          <input type="password" value={deletePassword} onChange={(e) => setDeletePassword(e.target.value)} />
        </label>
        <label>
          <span>Type DELETE</span>
          <input type="text" value={deleteConfirm} onChange={(e) => setDeleteConfirm(e.target.value)} />
        </label>
        <button className="danger large" onClick={() => void deleteWallet()} disabled={!deletePassword}>
          Delete wallet
        </button>
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
      <div className="container">
        <div className="header">
          <h2>Connection Request</h2>
        </div>
        <div className="content">
          <div className="error">{error}</div>
          <button className="secondary large" onClick={() => window.close()}>
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
    <div className="container">
      <div className="header">
        <h2>Connection Request</h2>
      </div>
      <div className="content">
        <p className="subtitle">This site wants to see your account address.</p>
        <div className="detailCard">
          <div className="detailRow">
            <span>Site</span>
            <div className="mono">{pending.origin}</div>
          </div>
          {pending.address && (
            <div className="detailRow">
              <span>Account</span>
              <div className="mono">{compactAddress(pending.address)}</div>
            </div>
          )}
        </div>
        {error && <div className="error">{error}</div>}
        <div className="actions">
          <button className="danger" onClick={() => decide("REJECT_CONNECTION")} disabled={loading}>
            Reject
          </button>
          <button className="primary" onClick={() => decide("APPROVE_CONNECTION")} disabled={loading}>
            {loading ? "Working..." : "Connect"}
          </button>
        </div>
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
      <div className="container">
        <div className="header">
          <h2>Transaction Request</h2>
        </div>
        <div className="content">
          <div className="error">{error}</div>
          <button className="secondary large" onClick={() => window.close()}>
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
    <div className="container">
      <div className="header">
        <h2>{submit ? "Send Transaction" : "Sign Transaction"}</h2>
      </div>
      <div className="content">
        <p className="subtitle">
          {submit ? "Review this transfer before signing and submitting." : "Review this transfer before signing. It will not be submitted."}
        </p>
        <div className="detailCard">
          <div className="detailRow">
            <span>Site</span>
            <div className="mono">{pending.origin}</div>
          </div>
          <div className="detailRow">
            <span>From</span>
            <div className="mono">{compactAddress(pending.from)}</div>
          </div>
          <div className="detailRow">
            <span>To</span>
            <div className="mono">{compactAddress(pending.to)}</div>
          </div>
          <div className="detailRow">
            <span>Amount</span>
            <div className="mono">{pending.amount}</div>
          </div>
          <div className="detailRow">
            <span>Coin</span>
            <div className="mono">{compactAddress(pending.coin, 8, 8)}</div>
          </div>
        </div>
        {error && <div className="error">{error}</div>}
        <div className="actions">
          <button className="danger" onClick={() => decide("REJECT_TRANSACTION")} disabled={loading}>
            Reject
          </button>
          <button className="primary" onClick={() => decide("APPROVE_TRANSACTION")} disabled={loading}>
            {loading ? "Working..." : submit ? "Confirm" : "Sign"}
          </button>
        </div>
      </div>
    </div>
  );
}

function compactAddress(address: string, head = 10, tail = 8): string {
  if (address.length <= head + tail) return address;
  return `${address.slice(0, head)}...${address.slice(-tail)}`;
}

createRoot(document.getElementById("root")!).render(<App />);
