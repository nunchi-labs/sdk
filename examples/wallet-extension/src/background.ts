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

let unlockedWallet: UnlockedWallet | null = null;
const connectedSites: Set<string> = new Set();
const pendingConnections: Map<string, ConnectionRequest> = new Map();
const pendingTransactions: Map<string, TransactionRequest> = new Map();

const DEFAULT_SETTINGS: Settings = {
  rpcUrl: "http://localhost:8545",
  network: "local",
};

async function getWalletState(): Promise<WalletState | null> {
  const result = await chrome.storage.local.get("wallet");
  return result.wallet || null;
}

async function getSettings(): Promise<Settings> {
  const result = await chrome.storage.local.get("settings");
  return result.settings || DEFAULT_SETTINGS;
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

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  handleMessage(message, sender.tab?.url)
    .then((response) => sendResponse(response))
    .catch((error) => sendResponse({ success: false, error: error.message }));
  return true;
});

async function handleMessage(message: Message, senderUrl?: string): Promise<Response> {
  const { type, payload } = message;

  switch (type) {
    case "CREATE_WALLET": {
      const { privateKeyHex, publicKeyHex, address, curve, password } = payload as {
        privateKeyHex: string;
        publicKeyHex: string;
        address: string;
        curve: string;
        password: string;
      };

      const { encrypted, salt } = await encryptPrivateKey(privateKeyHex, password);

      const wallet: WalletState = { encrypted, salt, address, curve };
      await chrome.storage.local.set({ wallet });

      unlockedWallet = { privateKeyHex, publicKeyHex, address, curve };

      return { success: true, data: { address, curve } };
    }

    case "IMPORT_WALLET": {
      const { privateKeyHex, publicKeyHex, address, curve, password } = payload as {
        privateKeyHex: string;
        publicKeyHex: string;
        address: string;
        curve: string;
        password: string;
      };

      const { encrypted, salt } = await encryptPrivateKey(privateKeyHex, password);

      const wallet: WalletState = { encrypted, salt, address, curve };
      await chrome.storage.local.set({ wallet });

      unlockedWallet = { privateKeyHex, publicKeyHex, address, curve };

      return { success: true, data: { address, curve } };
    }

    case "UNLOCK_WALLET": {
      const { password } = payload as { password: string };
      const wallet = await getWalletState();
      if (!wallet) {
        throw new Error("No wallet found");
      }

      const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);

      const wasm = await import("./wasm/nunchi_wallet_crypto");
      const keyPair = wasm.import_private_key(privateKeyHex);

      unlockedWallet = {
        privateKeyHex,
        publicKeyHex: keyPair.public_key_hex,
        address: wallet.address,
        curve: wallet.curve,
      };

      return { success: true, data: { address: wallet.address } };
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
        },
      };
    }

    case "REQUEST_CONNECTION": {
      const origin = new URL(senderUrl || "").origin;
      if (connectedSites.has(origin)) {
        return { success: true, data: { address: unlockedWallet?.address } };
      }

      const requestId = `conn-${Date.now()}-${Math.random()}`;
      pendingConnections.set(requestId, { origin, timestamp: Date.now() });

      chrome.windows.create({
        url: chrome.runtime.getURL(`popup.html?approve=connection&id=${requestId}`),
        type: "popup",
        width: 400,
        height: 600,
      });

      return { success: true, data: { pending: true, requestId } };
    }

    case "APPROVE_CONNECTION": {
      const { requestId } = payload as { requestId: string };
      const request = pendingConnections.get(requestId);
      if (!request) {
        throw new Error("Connection request not found");
      }

      connectedSites.add(request.origin);
      pendingConnections.delete(requestId);

      return { success: true, data: { address: unlockedWallet?.address } };
    }

    case "REJECT_CONNECTION": {
      const { requestId } = payload as { requestId: string };
      pendingConnections.delete(requestId);
      return { success: true };
    }

    case "REQUEST_TRANSACTION": {
      const origin = new URL(senderUrl || "").origin;
      if (!connectedSites.has(origin)) {
        throw new Error("Site not connected");
      }

      const { coin, from, to, amount } = payload as {
        coin: string;
        from: string;
        to: string;
        amount: string;
      };

      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      const settings = await getSettings();
      const nonce = await fetchNonce(settings.rpcUrl, from);

      const requestId = `tx-${Date.now()}-${Math.random()}`;
      pendingTransactions.set(requestId, {
        id: requestId,
        origin,
        nonce,
        coin,
        from,
        to,
        amount,
        timestamp: Date.now(),
      });

      chrome.windows.create({
        url: chrome.runtime.getURL(`popup.html?approve=transaction&id=${requestId}`),
        type: "popup",
        width: 400,
        height: 600,
      });

      return { success: true, data: { pending: true, requestId } };
    }

    case "APPROVE_TRANSACTION": {
      const { requestId } = payload as { requestId: string };
      const request = pendingTransactions.get(requestId);
      if (!request) {
        throw new Error("Transaction request not found");
      }

      if (!unlockedWallet) {
        throw new Error("Wallet is locked");
      }

      const wasm = await import("./wasm/nunchi_wallet_crypto");
      const signed = wasm.sign_transfer(
        unlockedWallet.privateKeyHex,
        BigInt(request.nonce),
        request.coin,
        request.from,
        request.to,
        request.amount
      );

      const settings = await getSettings();
      const hash = await submitTransaction(settings.rpcUrl, signed.transaction_hex);

      await addActivity({
        hash,
        timestamp: Date.now(),
        coin: request.coin,
        to: request.to,
        amount: request.amount,
      });

      pendingTransactions.delete(requestId);

      return { success: true, data: { hash } };
    }

    case "REJECT_TRANSACTION": {
      const { requestId } = payload as { requestId: string };
      pendingTransactions.delete(requestId);
      return { success: true };
    }

    case "GET_CONNECTED_SITES": {
      return { success: true, data: Array.from(connectedSites) };
    }

    case "DISCONNECT_SITE": {
      const { origin } = payload as { origin: string };
      connectedSites.delete(origin);
      return { success: true };
    }

    case "GET_SETTINGS": {
      const settings = await getSettings();
      return { success: true, data: settings };
    }

    case "UPDATE_SETTINGS": {
      const settings = payload as Settings;
      await chrome.storage.local.set({ settings });
      return { success: true };
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
