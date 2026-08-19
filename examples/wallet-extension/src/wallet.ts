import type {
  Message,
  MessageType,
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

export const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
export const AUTO_LOCK_MS = 15 * 60 * 1000;
export const MIN_PASSWORD_LENGTH = 8;
export const LOCKOUT_STORAGE = "unlockLockout";
export const MAX_UNLOCK_ATTEMPTS = 5;
export const LOCKOUT_DURATION = 5 * 60 * 1000;

export const PRIVILEGED_TYPES = new Set<MessageType>([
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

export interface WalletKeyPair {
  private_key_hex: string;
  public_key_hex: string;
  address: string;
  curve: string;
}

export interface WalletWasm {
  generate_ed25519_keypair(): WalletKeyPair;
  generate_secp256r1_keypair(): WalletKeyPair;
  import_private_key(privateKeyHex: string): WalletKeyPair;
  sign_transfer(
    privateKeyHex: string,
    nonce: bigint,
    coin: string,
    from: string,
    to: string,
    amount: string
  ): { transaction_hex: string; digest_hex: string };
}

export interface WalletHost {
  now(): number;
  storageGet(keys: string | string[]): Promise<Record<string, unknown>>;
  storageSet(items: Record<string, unknown>): Promise<void>;
  storageRemove(keys: string[]): Promise<void>;
  extensionId: string;
  openApproval(path: string): Promise<number | undefined>;
  rpc(url: string, body: unknown): Promise<{ error?: { message: string }; result?: unknown }>;
  wasm(): Promise<WalletWasm>;
  approvalTimeoutMs?: number;
}

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

const DEFAULT_SETTINGS: Settings = {
  rpcUrl: "http://localhost:8545",
  network: "local",
  chainId: "nunchi-local",
  displayCoin: "",
};

export class Wallet {
  private unlockedWallet: UnlockedWallet | null = null;
  private connectedSites: Set<string> = new Set();
  private pendingConnections: Map<string, PendingConnection> = new Map();
  private pendingTransactions: Map<string, PendingTransaction> = new Map();
  private hydrated = false;
  private lastActive: number;
  private approvalTimers: Set<ReturnType<typeof setTimeout>> = new Set();

  constructor(private readonly host: WalletHost) {
    this.lastActive = host.now();
  }

  /** Drop approval timers without settling requests. Simulates service-worker shutdown. */
  shutdown(): void {
    for (const timer of this.approvalTimers) {
      clearTimeout(timer);
    }
    this.approvalTimers.clear();
  }

  rejectWindow(windowId: number): void {
    for (const [requestId, request] of this.pendingConnections) {
      if (request.windowId === windowId) {
        this.settlePending(this.pendingConnections, requestId, { success: false, error: "User rejected" });
      }
    }
    for (const [requestId, request] of this.pendingTransactions) {
      if (request.windowId === windowId) {
        this.settlePending(this.pendingTransactions, requestId, { success: false, error: "User rejected" });
      }
    }
  }

  async handleMessage(
    message: Message,
    sender: { origin?: string; url?: string; tab?: { url?: string } }
  ): Promise<Response> {
    await this.hydrate();
    this.applyAutoLock();
    const { type, payload } = message;
    const isPrivileged = originIsPrivileged(sender, `chrome-extension://${this.host.extensionId}`);
    const origin = senderOrigin(sender);
    if (isPrivileged) {
      this.markActive();
    }

    if (PRIVILEGED_TYPES.has(type) && !isPrivileged) {
      console.warn(`[Nunchi Wallet] Blocked privileged message ${type} from ${origin}`);
      throw new Error("Unauthorized: privileged operation");
    }

    switch (type) {
      case "CREATE_WALLET": {
        const existingWallet = await this.getWalletState();
        if (existingWallet) {
          throw new Error("Wallet already exists. Delete it in Settings before creating a new one.");
        }

        const { curve, password: rawPassword } = payload as {
          curve: "Ed25519" | "Secp256r1";
          password: string;
        };
        const password = requirePassword(rawPassword);
        const wasm = await this.host.wasm();
        const keyPair =
          curve === "Ed25519" ? wasm.generate_ed25519_keypair() : wasm.generate_secp256r1_keypair();
        const verifyKeyPair = wasm.import_private_key(keyPair.private_key_hex);
        if (verifyKeyPair.address !== keyPair.address) {
          throw new Error("Address mismatch: key derivation failed");
        }

        const { encrypted, salt } = await encryptPrivateKey(keyPair.private_key_hex, password);
        await this.setWalletState({
          encrypted,
          salt,
          address: keyPair.address,
          curve: keyPair.curve,
          needsBackup: true,
        });
        this.unlockedWallet = {
          privateKeyHex: keyPair.private_key_hex,
          publicKeyHex: keyPair.public_key_hex,
          address: keyPair.address,
          curve: keyPair.curve,
        };
        return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: true } };
      }

      case "IMPORT_WALLET": {
        const existingWallet = await this.getWalletState();
        if (existingWallet) {
          throw new Error("Wallet already exists. Delete it in Settings before importing another.");
        }
        const { private_key_hex, password: rawPassword } = payload as {
          private_key_hex: string;
          password: string;
        };
        const password = requirePassword(rawPassword);
        const wasm = await this.host.wasm();
        const keyPair = wasm.import_private_key(private_key_hex);
        const { encrypted, salt } = await encryptPrivateKey(private_key_hex, password);
        await this.setWalletState({
          encrypted,
          salt,
          address: keyPair.address,
          curve: keyPair.curve,
          needsBackup: false,
        });
        this.unlockedWallet = {
          privateKeyHex: private_key_hex,
          publicKeyHex: keyPair.public_key_hex,
          address: keyPair.address,
          curve: keyPair.curve,
        };
        return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: false } };
      }

      case "REVEAL_BACKUP": {
        const wallet = await this.getWalletState();
        if (!wallet?.needsBackup) {
          throw new Error("No pending backup");
        }
        const { password } = (payload || {}) as { password?: string };
        let privateKeyHex = this.unlockedWallet?.privateKeyHex;
        if (!privateKeyHex) {
          if (!password) {
            throw new Error("Password required to reveal backup");
          }
          privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
        }
        return { success: true, data: { private_key_hex: privateKeyHex } };
      }

      case "CONFIRM_BACKUP": {
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        await this.setWalletState({ ...wallet, needsBackup: false });
        return { success: true };
      }

      case "EXPORT_PRIVATE_KEY": {
        const { password } = payload as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
        return { success: true, data: { private_key_hex: privateKeyHex } };
      }

      case "DELETE_WALLET": {
        const { password } = payload as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
        this.unlockedWallet = null;
        this.connectedSites.clear();
        this.pendingConnections.clear();
        this.pendingTransactions.clear();
        await this.host.storageRemove([
          "wallet",
          "activity",
          "connectedSites",
          "pendingConnections",
          "pendingTransactions",
          LOCKOUT_STORAGE,
        ]);
        await this.persistPending();
        return { success: true };
      }

      case "UNLOCK_WALLET": {
        const { password } = payload as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        const now = this.host.now();
        const attempts = await this.readLockout(origin);
        if (attempts.count >= MAX_UNLOCK_ATTEMPTS) {
          const timeSinceLastAttempt = now - attempts.lastAttempt;
          if (timeSinceLastAttempt < LOCKOUT_DURATION) {
            const remainingMs = LOCKOUT_DURATION - timeSinceLastAttempt;
            throw new Error(`Too many failed attempts. Try again in ${Math.ceil(remainingMs / 1000)}s`);
          }
          await this.writeLockout(origin, null);
          attempts.count = 0;
          attempts.lastAttempt = 0;
        }
        try {
          const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, password);
          const wasm = await this.host.wasm();
          const keyPair = wasm.import_private_key(privateKeyHex);
          if (keyPair.address !== wallet.address) {
            throw new Error("Address mismatch: stored address does not match derived address");
          }
          this.unlockedWallet = {
            privateKeyHex,
            publicKeyHex: keyPair.public_key_hex,
            address: keyPair.address,
            curve: wallet.curve,
          };
          await this.writeLockout(origin, null);
          this.markActive();
          return { success: true, data: { address: wallet.address, needsBackup: !!wallet.needsBackup } };
        } catch (error) {
          attempts.count++;
          attempts.lastAttempt = now;
          await this.writeLockout(origin, attempts);
          throw error;
        }
      }

      case "LOCK_WALLET": {
        this.unlockedWallet = null;
        return { success: true };
      }

      case "GET_STATE": {
        const wallet = await this.getWalletState();
        return {
          success: true,
          data: {
            hasWallet: !!wallet,
            isUnlocked: !!this.unlockedWallet,
            address: wallet?.address,
            curve: wallet?.curve,
            needsBackup: !!wallet?.needsBackup,
          },
        };
      }

      case "GET_PENDING_REQUEST": {
        const { requestId } = payload as { requestId: string };
        const connection = this.pendingConnections.get(requestId);
        if (connection) {
          return {
            success: true,
            data: {
              kind: "connection",
              origin: connection.origin,
              timestamp: connection.timestamp,
              address: this.unlockedWallet?.address,
            },
          };
        }
        const transaction = this.pendingTransactions.get(requestId);
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
        if (this.connectedSites.has(origin)) {
          if (!this.unlockedWallet) {
            throw new Error("Wallet is locked");
          }
          return { success: true, data: { address: this.unlockedWallet.address } };
        }
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const requestId = randomRequestId("conn");
        return this.waitForApproval(
          requestId,
          this.pendingConnections,
          { origin, timestamp: this.host.now(), resolve: () => undefined },
          `popup.html?approve=connection&id=${encodeURIComponent(requestId)}`
        );
      }

      case "APPROVE_CONNECTION": {
        const { requestId } = payload as { requestId: string };
        const request = this.pendingConnections.get(requestId);
        if (!request) {
          throw new Error("Connection request not found or expired");
        }
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        this.connectedSites.add(request.origin);
        await this.persistConnectedSites();
        const address = this.unlockedWallet.address;
        this.settlePending(this.pendingConnections, requestId, { success: true, data: { address } });
        return { success: true, data: { address } };
      }

      case "REJECT_CONNECTION": {
        const { requestId } = payload as { requestId: string };
        if (!this.settlePending(this.pendingConnections, requestId, { success: false, error: "User rejected" })) {
          throw new Error("Connection request not found or expired");
        }
        return { success: true };
      }

      case "REQUEST_TRANSACTION":
      case "REQUEST_SIGN": {
        requireOrigin(origin);
        if (!isPrivileged && !this.connectedSites.has(origin)) {
          throw new Error("Site not connected. Call nunchi_requestAccounts first.");
        }
        const { coin, to, amount } = payload as { coin: string; to: string; amount: string };
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const requestId = randomRequestId("tx");
        return this.waitForApproval(
          requestId,
          this.pendingTransactions,
          {
            id: requestId,
            origin,
            nonce: 0,
            coin,
            from: this.unlockedWallet.address,
            to,
            amount,
            timestamp: this.host.now(),
            submit: type === "REQUEST_TRANSACTION",
            resolve: () => undefined,
          },
          `popup.html?approve=transaction&id=${encodeURIComponent(requestId)}`
        );
      }

      case "APPROVE_TRANSACTION": {
        const { requestId } = payload as { requestId: string };
        const request = this.pendingTransactions.get(requestId);
        if (!request) {
          throw new Error("Transaction request not found or expired");
        }
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        if (request.from !== this.unlockedWallet.address) {
          this.settlePending(this.pendingTransactions, requestId, {
            success: false,
            error: "Transaction from address must match unlocked wallet",
          });
          throw new Error("Transaction from address must match unlocked wallet");
        }
        try {
          const settings = await this.getSettings();
          const nonce = await this.fetchNonce(settings.rpcUrl, this.unlockedWallet.address);
          const result = request.submit
            ? await this.signAndSubmit(this.unlockedWallet, nonce, request.coin, request.from, request.to, request.amount)
            : await this.signOnly(this.unlockedWallet, nonce, request.coin, request.from, request.to, request.amount);
          this.settlePending(this.pendingTransactions, requestId, { success: true, data: result });
          return { success: true, data: result };
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          this.settlePending(this.pendingTransactions, requestId, { success: false, error: message });
          throw error;
        }
      }

      case "REJECT_TRANSACTION": {
        const { requestId } = payload as { requestId: string };
        if (!this.settlePending(this.pendingTransactions, requestId, { success: false, error: "User rejected" })) {
          throw new Error("Transaction request not found or expired");
        }
        return { success: true };
      }

      case "SEND_TRANSACTION": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { from, to, amount, coin } = payload as {
          from: string;
          to: string;
          amount: string;
          coin: string;
        };
        if (from !== this.unlockedWallet.address) {
          throw new Error("from address must match unlocked wallet");
        }
        const settings = await this.getSettings();
        const nonce = await this.fetchNonce(settings.rpcUrl, this.unlockedWallet.address);
        return { success: true, data: await this.signAndSubmit(this.unlockedWallet, nonce, coin, from, to, amount) };
      }

      case "GET_CONNECTED_SITES": {
        return { success: true, data: Array.from(this.connectedSites) };
      }

      case "DISCONNECT_SITE": {
        const { origin: siteOrigin } = payload as { origin: string };
        this.connectedSites.delete(siteOrigin);
        await this.persistConnectedSites();
        return { success: true };
      }

      case "GET_SETTINGS": {
        return { success: true, data: await this.getSettings() };
      }

      case "UPDATE_SETTINGS": {
        const incoming = payload as Partial<Settings>;
        const current = await this.getSettings();
        const settings: Settings = { ...current, ...incoming };
        parseRpcUrl(settings.rpcUrl);
        if (!settings.chainId) {
          settings.chainId = settings.network || DEFAULT_SETTINGS.chainId;
        }
        await this.host.storageSet({ settings });
        return { success: true, data: settings };
      }

      case "GET_CHAIN_ID": {
        const settings = await this.getSettings();
        return { success: true, data: { chainId: settings.chainId || settings.network || DEFAULT_SETTINGS.chainId } };
      }

      case "GET_NONCE": {
        const { address } = payload as { address: string };
        const settings = await this.getSettings();
        return { success: true, data: { nonce: await this.fetchNonce(settings.rpcUrl, address) } };
      }

      case "GET_BALANCE": {
        const { address, coin } = payload as { address: string; coin: string };
        const settings = await this.getSettings();
        return { success: true, data: { balance: await this.fetchBalance(settings.rpcUrl, address, coin) } };
      }

      case "GET_ACTIVITY": {
        return { success: true, data: await this.getActivity() };
      }

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  private applyAutoLock(): void {
    if (this.unlockedWallet && this.host.now() - this.lastActive > AUTO_LOCK_MS) {
      this.unlockedWallet = null;
    }
  }

  private markActive(): void {
    this.lastActive = this.host.now();
  }

  private async hydrate(): Promise<void> {
    if (this.hydrated) {
      return;
    }
    this.hydrated = true;
    const stored = await this.host.storageGet(["connectedSites", "pendingConnections", "pendingTransactions"]);
    if (Array.isArray(stored.connectedSites)) {
      this.connectedSites.clear();
      for (const site of stored.connectedSites) {
        if (typeof site === "string" && site) {
          this.connectedSites.add(site);
        }
      }
    }
    if (Array.isArray(stored.pendingConnections)) {
      for (const item of stored.pendingConnections as StoredConnection[]) {
        if (!item?.id || !item.origin) {
          continue;
        }
        this.pendingConnections.set(item.id, {
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
        this.pendingTransactions.set(item.id, {
          ...item,
          submit: item.submit !== false,
          resolve: () => undefined,
        });
      }
    }
  }

  private async persistConnectedSites(): Promise<void> {
    await this.host.storageSet({ connectedSites: Array.from(this.connectedSites) });
  }

  private async persistPending(): Promise<void> {
    const connections: StoredConnection[] = [];
    for (const [id, request] of this.pendingConnections) {
      connections.push({ id, origin: request.origin, timestamp: request.timestamp, windowId: request.windowId });
    }
    const transactions: StoredTransaction[] = [];
    for (const request of this.pendingTransactions.values()) {
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
    await this.host.storageSet({ pendingConnections: connections, pendingTransactions: transactions });
  }

  private async getWalletState(): Promise<WalletState | null> {
    const result = await this.host.storageGet("wallet");
    return (result.wallet as WalletState) || null;
  }

  private async setWalletState(wallet: WalletState): Promise<void> {
    await this.host.storageSet({ wallet });
  }

  private async getSettings(): Promise<Settings> {
    const result = await this.host.storageGet("settings");
    return { ...DEFAULT_SETTINGS, ...((result.settings as Settings) || {}) };
  }

  private async getActivity(): Promise<SubmittedTx[]> {
    const result = await this.host.storageGet("activity");
    return (result.activity as SubmittedTx[]) || [];
  }

  private async addActivity(tx: SubmittedTx): Promise<void> {
    const activity = await this.getActivity();
    activity.unshift(tx);
    await this.host.storageSet({ activity: activity.slice(0, 50) });
  }

  private async readLockout(origin: string): Promise<{ count: number; lastAttempt: number }> {
    const stored = await this.host.storageGet(LOCKOUT_STORAGE);
    const map = (stored[LOCKOUT_STORAGE] as Record<string, { count: number; lastAttempt: number }>) || {};
    return map[origin] || { count: 0, lastAttempt: 0 };
  }

  private async writeLockout(origin: string, value: { count: number; lastAttempt: number } | null): Promise<void> {
    const stored = await this.host.storageGet(LOCKOUT_STORAGE);
    const map = { ...((stored[LOCKOUT_STORAGE] as Record<string, { count: number; lastAttempt: number }>) || {}) };
    if (value) {
      map[origin] = value;
    } else {
      delete map[origin];
    }
    await this.host.storageSet({ [LOCKOUT_STORAGE]: map });
  }

  private settlePending<T extends { resolve: (response: Response) => void }>(
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
    void this.persistPending();
    return true;
  }

  private waitForApproval<T extends { windowId?: number; resolve: (response: Response) => void }>(
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
      void this.persistPending();

      const timer = setTimeout(() => {
        this.approvalTimers.delete(timer);
        this.settlePending(map, requestId, { success: false, error: "Request timed out" });
      }, this.host.approvalTimeoutMs ?? APPROVAL_TIMEOUT_MS);
      this.approvalTimers.add(timer);

      const originalResolve = request.resolve;
      request.resolve = (response) => {
        clearTimeout(timer);
        this.approvalTimers.delete(timer);
        originalResolve(response);
      };

      this.host
        .openApproval(popupPath)
        .then((windowId) => {
          const entry = map.get(requestId);
          if (!entry) {
            return;
          }
          if (windowId === undefined) {
            this.settlePending(map, requestId, { success: false, error: "Failed to open approval window" });
            return;
          }
          entry.windowId = windowId;
          void this.persistPending();
        })
        .catch(() => {
          this.settlePending(map, requestId, { success: false, error: "Failed to open approval window" });
        });
    });
  }

  private async signOnly(
    wallet: UnlockedWallet,
    nonce: number,
    coin: string,
    from: string,
    to: string,
    amount: string
  ): Promise<{ digest: string; transaction: string }> {
    const wasm = await this.host.wasm();
    const signed = wasm.sign_transfer(wallet.privateKeyHex, BigInt(nonce), coin, from, to, amount);
    return { digest: signed.digest_hex, transaction: signed.transaction_hex };
  }

  private async signAndSubmit(
    wallet: UnlockedWallet,
    nonce: number,
    coin: string,
    from: string,
    to: string,
    amount: string
  ): Promise<{ hash: string; digest: string; transaction: string }> {
    const signed = await this.signOnly(wallet, nonce, coin, from, to, amount);
    const settings = await this.getSettings();
    const hash = await this.submitTransaction(settings.rpcUrl, signed.transaction);
    await this.addActivity({ hash, timestamp: this.host.now(), coin, to, amount });
    return { hash, digest: signed.digest, transaction: signed.transaction };
  }

  private async fetchNonce(rpcUrl: string, address: string): Promise<number> {
    const data = await this.host.rpc(rpcUrl, {
      jsonrpc: "2.0",
      id: this.host.now(),
      method: "coins.nonce",
      params: { account: address },
    });
    if (data.error) {
      throw new Error(data.error.message);
    }
    return (data.result as { nonce: number }).nonce;
  }

  private async fetchBalance(rpcUrl: string, address: string, coin: string): Promise<string> {
    const data = await this.host.rpc(rpcUrl, {
      jsonrpc: "2.0",
      id: this.host.now(),
      method: "coins.balance",
      params: { account: address, coin },
    });
    if (data.error) {
      throw new Error(data.error.message);
    }
    return (data.result as { amount: string }).amount;
  }

  private async submitTransaction(rpcUrl: string, transactionHex: string): Promise<string> {
    const data = await this.host.rpc(rpcUrl, {
      jsonrpc: "2.0",
      id: this.host.now(),
      method: "coins.submit_transaction",
      params: { transaction: transactionHex },
    });
    if (data.error) {
      throw new Error(data.error.message);
    }
    return (data.result as { hash: string }).hash;
  }
}

function requirePassword(password: unknown): string {
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  return password;
}

function requireOrigin(origin: string): string {
  if (!origin) {
    throw new Error("Missing sender origin");
  }
  return origin;
}
