import type {
  Message,
  Response,
  WalletState,
  UnlockedWallet,
  Settings,
  ConnectionRequest,
  TransactionRequest,
  SubmittedTx,
} from "./types";
import { encryptPrivateKey, decryptPrivateKey } from "./crypto";
import { randomRequestId } from "./ids";
import { senderOrigin } from "./origin";
import { isPrivilegedSender as originIsPrivileged } from "./privilege";
import { parseRpcUrl } from "./rpc";

const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

type PendingConnection = ConnectionRequest & {
  windowId?: number;
  resolve: (response: Response) => void;
};

type PendingTransaction = TransactionRequest & {
  windowId?: number;
  resolve: (response: Response) => void;
};

type StoredConnection = { id: string; origin: string; timestamp: number; windowId?: number };
type StoredTransaction = Omit<TransactionRequest, "id"> & { id: string; windowId?: number };

async function initWasm() {
  const wasm = await import("./wasm/nunchi_wallet_crypto");
  await wasm.default();
  wasm.init_panic_hook();
  return wasm;
}

let unlockedWallet: UnlockedWallet | null = null;
const connectedSites: Set<string> = new Set();
const pendingConnections: Map<string, PendingConnection> = new Map();
const pendingTransactions: Map<string, PendingTransaction> = new Map();
let hydrated = false;

const DEFAULT_SETTINGS: Settings = {
  rpcUrl: "http://localhost:8545",
  network: "local",
  chainId: "nunchi-local",
  displayCoin: "",
};

async function hydrate(): Promise<void> {
  if (hydrated) {
    return;
  }
  hydrated = true;
  const stored = await chrome.storage.local.get(["connectedSites", "pendingConnections", "pendingTransactions"]);
  if (Array.isArray(stored.connectedSites)) {
    connectedSites.clear();
    for (const site of stored.connectedSites) {
      if (typeof site === "string" && site) {
        connectedSites.add(site);
      }
    }
  }
  if (Array.isArray(stored.pendingConnections)) {
    for (const item of stored.pendingConnections as StoredConnection[]) {
      if (!item?.id || !item.origin) {
        continue;
      }
      pendingConnections.set(item.id, {
        origin: item.origin,
        timestamp: item.timestamp,
        windowId: item.windowId,
        resolve: () => undefined,
      });
    }
  }
  if (Array.isArray(stored.pendingTransactions)) {
    for (const item of stored.pendingTransactions as StoredTransaction[]) {
      if (!item?.id) {
        continue;
      }
      pendingTransactions.set(item.id, {
        ...item,
        submit: item.submit !== false,
        resolve: () => undefined,
      });
    }
  }
}

async function persistConnectedSites(): Promise<void> {
  await chrome.storage.local.set({ connectedSites: Array.from(connectedSites) });
}

async function persistPending(): Promise<void> {
  const connections: StoredConnection[] = [];
  for (const [id, request] of pendingConnections) {
    connections.push({ id, origin: request.origin, timestamp: request.timestamp, windowId: request.windowId });
  }
  const transactions: StoredTransaction[] = [];
  for (const request of pendingTransactions.values()) {
    transactions.push({
      id: request.id,
      origin: request.origin,
      nonce: request.nonce,
      coin: request.coin,
      from: request.from,
      to: request.to,
      amount: request.amount,
      timestamp: request.timestamp,
      submit: request.submit,
      windowId: request.windowId,
    });
  }
  await chrome.storage.local.set({ pendingConnections: connections, pendingTransactions: transactions });
}

async function getWalletState(): Promise<WalletState | null> {
  const result = await chrome.storage.local.get("wallet");
  return result.wallet || null;
}

async function setWalletState(wallet: WalletState): Promise<void> {
  await chrome.storage.local.set({ wallet });
}

async function getSettings(): Promise<Settings> {
  const result = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(result.settings || {}) };
}

async function getActivity(): Promise<SubmittedTx[]> {
  const result = await chrome.storage.local.get("activity");
  return result.activity || [];
}

async function addActivity(tx: SubmittedTx): Promise<void> {
  const activity = await getActivity();
  activity.unshift(tx);
  await chrome.storage.local.set({ activity: activity.slice(0, 50) });
}

const failedUnlockAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_UNLOCK_ATTEMPTS = 5;
const LOCKOUT_DURATION = 5 * 60 * 1000;

function isPrivilegedSender(sender: chrome.runtime.MessageSender): boolean {
  return originIsPrivileged(sender, `chrome-extension://${chrome.runtime.id}`);
}

function getSenderOrigin(sender: chrome.runtime.MessageSender): string {
  return senderOrigin(sender);
}

function requireOrigin(origin: string): string {
  if (!origin) {
    throw new Error("Missing sender origin");
  }
  return origin;
}

function settlePending<T extends { resolve: (response: Response) => void }>(
  map: Map<string, T>,
  requestId: string,
  response: Response
): boolean {
  const entry = map.get(requestId);
  if (!entry) {
    return false;
  }
  map.delete(requestId);
  entry.resolve(response);
  void persistPending();
  return true;
}

function rejectWindowRequests(windowId: number): void {
  for (const [requestId, request] of pendingConnections) {
    if (request.windowId === windowId) {
      settlePending(pendingConnections, requestId, { success: false, error: "User rejected" });
    }
  }
  for (const [requestId, request] of pendingTransactions) {
    if (request.windowId === windowId) {
      settlePending(pendingTransactions, requestId, { success: false, error: "User rejected" });
    }
  }
}

chrome.windows.onRemoved.addListener((windowId) => {
  rejectWindowRequests(windowId);
});

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((error) => sendResponse({ success: false, error: error.message }));
  return true;
});

async function handleMessage(message: Message, sender: chrome.runtime.MessageSender): Promise<Response> {
  await hydrate();
  const { type, payload } = message;
  const isPrivileged = isPrivilegedSender(sender);
  const origin = getSenderOrigin(sender);

  const PRIVILEGED_TYPES = new Set([
    "CREATE_WALLET",
    "IMPORT_WALLET",
    "REVEAL_BACKUP",
    "CONFIRM_BACKUP",
    "EXPORT_PRIVATE_KEY",
    "DELETE_WALLET",
    "UNLOCK_WALLET",
    "LOCK_WALLET",
    "APPROVE_CONNECTION",
    "APPROVE_TRANSACTION",
    "REJECT_CONNECTION",
    "REJECT_TRANSACTION",
    "SEND_TRANSACTION",
    "UPDATE_SETTINGS",
    "GET_STATE",
    "GET_SETTINGS",
    "GET_CONNECTED_SITES",
    "DISCONNECT_SITE",
    "GET_NONCE",
    "GET_BALANCE",
    "GET_ACTIVITY",
    "GET_PENDING_REQUEST",
  ]);

  if (PRIVILEGED_TYPES.has(type) && !isPrivileged) {
    console.warn(`[Nunchi Wallet] Blocked privileged message ${type} from ${origin}`);
    throw new Error("Unauthorized: privileged operation");
  }

  switch (type) {
    case "CREATE_WALLET": {
      const existingWallet = await getWalletState();
      if (existingWallet) {
        throw new Error("Wallet already exists. Delete it in Settings before creating a new one.");
      }

      const { curve, password } = payload as {
        curve: "Ed25519" | "Secp256r1";
        password: string;
      };

      const wasm = await initWasm();
      const keyPair =
        curve === "Ed25519" ? wasm.generate_ed25519_keypair() : wasm.generate_secp256r1_keypair();

      const verifyKeyPair = wasm.import_private_key(keyPair.private_key_hex);
      if (verifyKeyPair.address !== keyPair.address) {
        throw new Error("Address mismatch: key derivation failed");
      }

      const { encrypted, salt } = await encryptPrivateKey(keyPair.private_key_hex, password);
      const wallet: WalletState = {
        encrypted,
        salt,
        address: keyPair.address,
        curve: keyPair.curve,
        needsBackup: true,
      };
      await setWalletState(wallet);

      unlockedWallet = {
        privateKeyHex: keyPair.private_key_hex,
        publicKeyHex: keyPair.public_key_hex,
        address: keyPair.address,
        curve: keyPair.curve,
      };

      return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: true } };
    }

    case "IMPORT_WALLET": {
      const existingWallet = await getWalletState();
      if (existingWallet) {
        throw new Error("Wallet already exists. Delete it in Settings before importing another.");
      }

      const { private_key_hex, password } = payload as {
        private_key_hex: string;
        password: string;
      };

      const wasm = await initWasm();
      const keyPair = wasm.import_private_key(private_key_hex);
      const { encrypted, salt } = await encryptPrivateKey(private_key_hex, password);
      const wallet: WalletState = {
        encrypted,
        salt,
        address: keyPair.address,
        curve: keyPair.curve,
        needsBackup: false,
      };
      await setWalletState(wallet);

      unlockedWallet = {
        privateKeyHex: private_key_hex,
        publicKeyHex: keyPair.public_key_hex,
        address: keyPair.address,
        curve: keyPair.curve,
      };

      return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: false } };
    }

    case "REVEAL_BACKUP": {
      const wallet = await getWalletState();
      if (!wallet?.needsBackup) {
        throw new Error("No pending backup");
      }

      const { password } = (payload || {}) as { password?: string };
      let privateKeyHex = unlockedWallet?.privateKeyHex;
      if (!privateKeyHex) {
        if (!password) {
          throw new Error("Password required to reveal backup");
        }
        privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
      }

      return { success: true, data: { private_key_hex: privateKeyHex } };
    }

    case "CONFIRM_BACKUP": {
      const wallet = await getWalletState();
      if (!wallet) {
        throw new Error("No wallet found");
      }
      await setWalletState({ ...wallet, needsBackup: false });
      return { success: true };
    }

    case "EXPORT_PRIVATE_KEY": {
      const { password } = payload as { password: string };
      const wallet = await getWalletState();
      if (!wallet) {
        throw new Error("No wallet found");
      }
      const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
      return { success: true, data: { private_key_hex: privateKeyHex } };
    }

    case "DELETE_WALLET": {
      const { password } = payload as { password: string };
      const wallet = await getWalletState();
      if (!wallet) {
        throw new Error("No wallet found");
      }
      await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
      unlockedWallet = null;
      connectedSites.clear();
      pendingConnections.clear();
      pendingTransactions.clear();
      await chrome.storage.local.remove(["wallet", "activity", "connectedSites", "pendingConnections", "pendingTransactions"]);
      await persistPending();
      return { success: true };
    }

    case "UNLOCK_WALLET": {
      const { password } = payload as { password: string };
      const wallet = await getWalletState();
      if (!wallet) {
        throw new Error("No wallet found");
      }

      const now = Date.now();
      const attempts = failedUnlockAttempts.get(origin) || { count: 0, lastAttempt: 0 };

      if (attempts.count >= MAX_UNLOCK_ATTEMPTS) {
        const timeSinceLastAttempt = now - attempts.lastAttempt;
        if (timeSinceLastAttempt < LOCKOUT_DURATION) {
          const remainingMs = LOCKOUT_DURATION - timeSinceLastAttempt;
          throw new Error(`Too many failed attempts. Try again in ${Math.ceil(remainingMs / 1000)}s`);
        }
        failedUnlockAttempts.delete(origin);
      }

      try {
        const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
        const wasm = await initWasm();
        const keyPair = wasm.import_private_key(privateKeyHex);

        if (keyPair.address !== wallet.address) {
          throw new Error("Address mismatch: stored address does not match derived address");
        }

        unlockedWallet = {
          privateKeyHex,
          publicKeyHex: keyPair.public_key_hex,
          address: keyPair.address,
          curve: wallet.curve,
        };

        failedUnlockAttempts.delete(origin);
        return { success: true, data: { address: wallet.address, needsBackup: !!wallet.needsBackup } };
      } catch (error) {
        attempts.count++;
        attempts.lastAttempt = now;
        failedUnlockAttempts.set(origin, attempts);
        throw error;
      }
    }

    case "LOCK_WALLET": {
      unlockedWallet = null;
      return { success: true };
    }

    case "GET_STATE": {
      const wallet = await getWalletState();
      return {
        success: true,
        data: {
          hasWallet: !!wallet,
          isUnlocked: !!unlockedWallet,
          address: wallet?.address,
          curve: wallet?.curve,
          needsBackup: !!wallet?.needsBackup,
        },
      };
    }

    case "GET_PENDING_REQUEST": {
      const { requestId } = payload as { requestId: string };
      const connection = pendingConnections.get(requestId);
      if (connection) {
        return {
          success: true,
          data: {
            kind: "connection",
            origin: connection.origin,
            timestamp: connection.timestamp,
            address: unlockedWallet?.address,
          },
        };
      }

      const transaction = pendingTransactions.get(requestId);
      if (transaction) {
        return {
          success: true,
          data: {
            kind: "transaction",
            origin: transaction.origin,
            nonce: transaction.nonce,
            coin: transaction.coin,
            from: transaction.from,
            to: transaction.to,
            amount: transaction.amount,
            timestamp: transaction.timestamp,
            submit: transaction.submit,
          },
        };
      }

      throw new Error("Request not found or expired");
    }

    case "REQUEST_CONNECTION": {
      requireOrigin(origin);
      if (connectedSites.has(origin)) {
        if (!unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        return { success: true, data: { address: unlockedWallet.address } };
      }

      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      const requestId = randomRequestId("conn");
      return waitForApproval(
        requestId,
        pendingConnections,
        { origin, timestamp: Date.now(), resolve: () => undefined },
        `popup.html?approve=connection&id=${encodeURIComponent(requestId)}`
      );
    }

    case "APPROVE_CONNECTION": {
      const { requestId } = payload as { requestId: string };
      const request = pendingConnections.get(requestId);
      if (!request) {
        throw new Error("Connection request not found or expired");
      }
      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      connectedSites.add(request.origin);
      await persistConnectedSites();
      const address = unlockedWallet.address;
      settlePending(pendingConnections, requestId, { success: true, data: { address } });
      return { success: true, data: { address } };
    }

    case "REJECT_CONNECTION": {
      const { requestId } = payload as { requestId: string };
      if (!settlePending(pendingConnections, requestId, { success: false, error: "User rejected" })) {
        throw new Error("Connection request not found or expired");
      }
      return { success: true };
    }

    case "REQUEST_TRANSACTION":
    case "REQUEST_SIGN": {
      requireOrigin(origin);
      if (!isPrivileged && !connectedSites.has(origin)) {
        throw new Error("Site not connected. Call nunchi_requestAccounts first.");
      }

      const { coin, to, amount } = payload as {
        coin: string;
        to: string;
        amount: string;
      };

      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      const settings = await getSettings();
      const nonce = await fetchNonce(settings.rpcUrl, unlockedWallet.address);
      const requestId = randomRequestId("tx");
      return waitForApproval(
        requestId,
        pendingTransactions,
        {
          id: requestId,
          origin,
          nonce,
          coin,
          from: unlockedWallet.address,
          to,
          amount,
          timestamp: Date.now(),
          submit: type === "REQUEST_TRANSACTION",
          resolve: () => undefined,
        },
        `popup.html?approve=transaction&id=${encodeURIComponent(requestId)}`
      );
    }

    case "APPROVE_TRANSACTION": {
      const { requestId } = payload as { requestId: string };
      const request = pendingTransactions.get(requestId);
      if (!request) {
        throw new Error("Transaction request not found or expired");
      }
      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }
      if (request.from !== unlockedWallet.address) {
        settlePending(pendingTransactions, requestId, {
          success: false,
          error: "Transaction from address must match unlocked wallet",
        });
        throw new Error("Transaction from address must match unlocked wallet");
      }

      try {
        const result = request.submit
          ? await signAndSubmit(unlockedWallet, request.nonce, request.coin, request.from, request.to, request.amount)
          : await signOnly(unlockedWallet, request.nonce, request.coin, request.from, request.to, request.amount);
        settlePending(pendingTransactions, requestId, { success: true, data: result });
        return { success: true, data: result };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        settlePending(pendingTransactions, requestId, { success: false, error: message });
        throw error;
      }
    }

    case "REJECT_TRANSACTION": {
      const { requestId } = payload as { requestId: string };
      if (!settlePending(pendingTransactions, requestId, { success: false, error: "User rejected" })) {
        throw new Error("Transaction request not found or expired");
      }
      return { success: true };
    }

    case "SEND_TRANSACTION": {
      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      const { from, to, amount, coin } = payload as {
        from: string;
        to: string;
        amount: string;
        coin: string;
      };

      if (from !== unlockedWallet.address) {
        throw new Error("from address must match unlocked wallet");
      }

      const settings = await getSettings();
      const nonce = await fetchNonce(settings.rpcUrl, unlockedWallet.address);
      const result = await signAndSubmit(unlockedWallet, nonce, coin, from, to, amount);
      return { success: true, data: result };
    }

    case "GET_CONNECTED_SITES": {
      return { success: true, data: Array.from(connectedSites) };
    }

    case "DISCONNECT_SITE": {
      const { origin: siteOrigin } = payload as { origin: string };
      connectedSites.delete(siteOrigin);
      await persistConnectedSites();
      return { success: true };
    }

    case "GET_SETTINGS": {
      const settings = await getSettings();
      return { success: true, data: settings };
    }

    case "UPDATE_SETTINGS": {
      const incoming = payload as Partial<Settings>;
      const current = await getSettings();
      const settings: Settings = {
        ...current,
        ...incoming,
      };
      parseRpcUrl(settings.rpcUrl);
      if (!settings.chainId) {
        settings.chainId = settings.network || DEFAULT_SETTINGS.chainId;
      }
      await chrome.storage.local.set({ settings });
      return { success: true, data: settings };
    }

    case "GET_CHAIN_ID": {
      const settings = await getSettings();
      return { success: true, data: { chainId: settings.chainId || settings.network || DEFAULT_SETTINGS.chainId } };
    }

    case "GET_NONCE": {
      const { address } = payload as { address: string };
      const settings = await getSettings();
      const nonce = await fetchNonce(settings.rpcUrl, address);
      return { success: true, data: { nonce } };
    }

    case "GET_BALANCE": {
      const { address, coin } = payload as { address: string; coin: string };
      const settings = await getSettings();
      const balance = await fetchBalance(settings.rpcUrl, address, coin);
      return { success: true, data: { balance } };
    }

    case "GET_ACTIVITY": {
      const activity = await getActivity();
      return { success: true, data: activity };
    }

    default:
      throw new Error(`Unknown message type: ${type}`);
  }
}

async function waitForApproval<T extends { windowId?: number; resolve: (response: Response) => void }>(
  requestId: string,
  map: Map<string, T>,
  request: T,
  popupPath: string
): Promise<Response> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (response: Response) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(response);
    };

    request.resolve = finish;
    map.set(requestId, request);
    void persistPending();

    const timer = setTimeout(() => {
      settlePending(map, requestId, { success: false, error: "Request timed out" });
    }, APPROVAL_TIMEOUT_MS);

    const originalResolve = request.resolve;
    request.resolve = (response) => {
      clearTimeout(timer);
      originalResolve(response);
    };

    chrome.windows
      .create({
        url: chrome.runtime.getURL(popupPath),
        type: "popup",
        width: 400,
        height: 600,
      })
      .then((win) => {
        const entry = map.get(requestId);
        if (!entry) {
          return;
        }
        if (win?.id === undefined) {
          settlePending(map, requestId, { success: false, error: "Failed to open approval window" });
          return;
        }
        entry.windowId = win.id;
        void persistPending();
      })
      .catch(() => {
        settlePending(map, requestId, { success: false, error: "Failed to open approval window" });
      });
  });
}

async function signOnly(
  wallet: UnlockedWallet,
  nonce: number,
  coin: string,
  from: string,
  to: string,
  amount: string
): Promise<{ digest: string; transaction: string }> {
  const wasm = await initWasm();
  const signed = wasm.sign_transfer(wallet.privateKeyHex, BigInt(nonce), coin, from, to, amount);
  return { digest: signed.digest_hex, transaction: signed.transaction_hex };
}

async function signAndSubmit(
  wallet: UnlockedWallet,
  nonce: number,
  coin: string,
  from: string,
  to: string,
  amount: string
): Promise<{ hash: string; digest: string; transaction: string }> {
  const signed = await signOnly(wallet, nonce, coin, from, to, amount);
  const settings = await getSettings();
  const hash = await submitTransaction(settings.rpcUrl, signed.transaction);
  await addActivity({
    hash,
    timestamp: Date.now(),
    coin,
    to,
    amount,
  });
  return { hash, digest: signed.digest, transaction: signed.transaction };
}

async function fetchNonce(rpcUrl: string, address: string): Promise<number> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "coins.nonce",
      params: { account: address },
    }),
  });

  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message);
  }
  return data.result.nonce;
}

async function fetchBalance(rpcUrl: string, address: string, coin: string): Promise<string> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "coins.balance",
      params: { account: address, coin },
    }),
  });

  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message);
  }
  return data.result.amount;
}

async function submitTransaction(rpcUrl: string, transactionHex: string): Promise<string> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "coins.submit_transaction",
      params: { transaction: transactionHex },
    }),
  });

  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message);
  }
  return data.result.hash;
}
