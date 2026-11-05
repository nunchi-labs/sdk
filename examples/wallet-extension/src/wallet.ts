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
import { requirePageOrigin, senderOrigin } from "./origin";
import { isAllowedPageMessage } from "./page-messages";
import { isPrivilegedSender as originIsPrivileged } from "./privilege";
import { parseRpcUrl } from "./rpc";
import {
  MIN_PASSWORD_LENGTH,
  requireAddress,
  requireAmount,
  requireCoinHex,
  requireCurve,
  requireDecimals,
  requireLabel,
  requirePassword,
  requirePositiveAmount,
  requirePrivateKeyHex,
  requireRequestId,
  requireSignerPubKeys,
  requireThreshold,
  requireTokenName,
  requireTokenSymbol,
} from "./validate";

export { MIN_PASSWORD_LENGTH };

export const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
export const AUTO_LOCK_MS = 15 * 60 * 1000;
export const LOCKOUT_STORAGE = "unlockLockout";
export const NONCE_CURSOR_STORAGE = "nonceCursor";
export const FACTORY_CURSOR_STORAGE = "factoryCursor";
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
  "CREATE_TOKEN",
  "MINT",
  "BURN",
  "REGISTER_ACCOUNT_POLICY",
  "UPDATE_SETTINGS",
  "GET_STATE",
  "GET_SETTINGS",
  "GET_CONNECTED_SITES",
  "DISCONNECT_SITE",
  "GET_NONCE",
  "GET_BALANCE",
  "GET_ACTIVITY",
  "GET_PENDING_REQUEST",
  "SWITCH_ACCOUNT",
  "ADD_ACCOUNT",
  "IMPORT_ACCOUNT",
  "RENAME_ACCOUNT",
  "GET_HOLDINGS",
  "GET_SWAP_QUOTE",
  "SWAP",
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
  sign_create_token(
    privateKeyHex: string,
    nonce: bigint,
    symbol: string,
    name: string,
    decimals: number,
    initialSupply: string,
    maxSupply: string
  ): { transaction_hex: string; digest_hex: string };
  sign_mint(
    privateKeyHex: string,
    nonce: bigint,
    coin: string,
    to: string,
    amount: string
  ): { transaction_hex: string; digest_hex: string };
  sign_burn(
    privateKeyHex: string,
    nonce: bigint,
    coin: string,
    from: string,
    amount: string
  ): { transaction_hex: string; digest_hex: string };
  sign_register_account_policy(
    privateKeyHex: string,
    nonce: bigint,
    threshold: number,
    signerPubKeys: string
  ): { transaction_hex: string; digest_hex: string; account: string };
  derive_coin_id(
    issuer: string,
    nonce: bigint,
    symbol: string,
    name: string,
    decimals: number,
    initialSupply: string,
    maxSupply: string
  ): string;
  derive_multisig_account(threshold: number, signerPubKeys: string): string;
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
  broadcast?(origin: string, event: string, params: unknown): void;
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

function parseNonce(value: unknown): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error("Invalid nonce");
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Nonce exceeds JavaScript safe integer range");
    }
    return BigInt(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return BigInt(value);
  }
  throw new Error("Invalid nonce");
}

function nonceToJson(nonce: bigint): number | string {
  if (nonce <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(nonce);
  }
  return nonce.toString();
}

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
  private hydratePromise: Promise<void> | null = null;
  private lastActive: number;
  private busy = false;
  private backupRevealed = false;
  private approvalTimers: Set<ReturnType<typeof setTimeout>> = new Set();
  /** Serializes sign+submit so two transfers cannot take the same account nonce. */
  private submitQueue: Promise<void> = Promise.resolve();
  /** Bumps on every accountsChanged broadcast so a late port snapshot cannot overwrite it. */
  private accountEpoch = 0;
  /** Next nonce to allocate per account when the chain has not caught up yet. */
  private nonceCursor = new Map<string, bigint>();
  /** Next factory nonce to predict when our own create is still in flight. */
  private factoryCursor: bigint | null = null;

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

  /** Check and apply auto-lock if timeout exceeded. Called periodically by alarm. */
  checkAutoLock(): void {
    this.applyAutoLock();
  }

  /** Monotonic count of accountsChanged broadcasts. */
  accountRevision(): number {
    return this.accountEpoch;
  }

  /**
   * Accounts a freshly connected page port should show. Empty when the worker
   * restarted and the key is no longer in memory, even if the site stayed connected.
   */
  async connectedAccounts(origin: string): Promise<string[]> {
    await this.hydrate();
    this.applyAutoLock();
    if (!this.connectedSites.has(origin) || !this.unlockedWallet) {
      return [];
    }
    return [this.unlockedWallet.address];
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
    } else {
      if (PRIVILEGED_TYPES.has(type) || !isAllowedPageMessage(type)) {
        console.warn(`[Nunchi Wallet] Blocked privileged message ${type} from ${origin}`);
        throw new Error("Unauthorized: privileged operation");
      }
      requirePageOrigin(origin);
    }

    switch (type) {
      case "CREATE_WALLET": {
        return this.withBusy(async () => {
          const existingWallet = await this.getWalletState();
          if (existingWallet) {
            throw new Error("Wallet already exists. Delete it in Settings before creating a new one.");
          }

          const { curve: rawCurve, password: rawPassword } = (payload || {}) as {
            curve: "Ed25519" | "Secp256r1";
            password: string;
          };
          const curve = requireCurve(rawCurve);
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
          this.backupRevealed = false;
          await this.host.storageSet({ backupRevealed: false });
          this.unlockedWallet = {
            privateKeyHex: keyPair.private_key_hex,
            publicKeyHex: keyPair.public_key_hex,
            address: keyPair.address,
            curve: keyPair.curve,
          };
          return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: true } };
        });
      }

      case "IMPORT_WALLET": {
        return this.withBusy(async () => {
          const existingWallet = await this.getWalletState();
          if (existingWallet) {
            throw new Error("Wallet already exists. Delete it in Settings before importing another.");
          }
          const { private_key_hex, password: rawPassword } = (payload || {}) as {
            private_key_hex: string;
            password: string;
          };
          const password = requirePassword(rawPassword);
          const privateKeyHex = requirePrivateKeyHex(private_key_hex);
          const wasm = await this.host.wasm();
          const keyPair = wasm.import_private_key(privateKeyHex);
          const { encrypted, salt } = await encryptPrivateKey(privateKeyHex, password);
          await this.setWalletState({
            encrypted,
            salt,
            address: keyPair.address,
            curve: keyPair.curve,
            needsBackup: false,
          });
          this.backupRevealed = false;
          await this.host.storageSet({ backupRevealed: false });
          this.unlockedWallet = {
            privateKeyHex,
            publicKeyHex: keyPair.public_key_hex,
            address: keyPair.address,
            curve: keyPair.curve,
          };
          return { success: true, data: { address: keyPair.address, curve: keyPair.curve, needsBackup: false } };
        });
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
          privateKeyHex = await this.decryptWithLockout(wallet, password);
        }
        this.backupRevealed = true;
        await this.host.storageSet({ backupRevealed: true });
        return { success: true, data: { private_key_hex: privateKeyHex } };
      }

      case "CONFIRM_BACKUP": {
        const wallet = await this.getWalletState();
        if (!wallet?.needsBackup) {
          throw new Error("No pending backup");
        }
        if (!this.backupRevealed) {
          throw new Error("Backup has not been revealed");
        }
        await this.setWalletState({ ...wallet, needsBackup: false });
        this.backupRevealed = false;
        await this.host.storageSet({ backupRevealed: false });
        return { success: true };
      }

      case "EXPORT_PRIVATE_KEY": {
        const { password } = (payload || {}) as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        const privateKeyHex = await this.decryptWithLockout(wallet, password);
        return { success: true, data: { private_key_hex: privateKeyHex } };
      }

      case "DELETE_WALLET": {
        const { password } = (payload || {}) as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        await this.decryptWithLockout(wallet, password);
        await this.withSubmitLock(async () => {
          this.notifyAllAccounts([]);
          this.rejectOutstanding("Wallet deleted");
          this.unlockedWallet = null;
          this.backupRevealed = false;
          this.connectedSites.clear();
          await this.clearNonceCursors();
          await this.host.storageRemove([
            "wallet",
            "activity",
            "connectedSites",
            "pendingConnections",
            "pendingTransactions",
            "backupRevealed",
            LOCKOUT_STORAGE,
          ]);
          await this.persistPending();
        });
        return { success: true };
      }

      case "UNLOCK_WALLET": {
        const { password } = (payload || {}) as { password: string };
        const wallet = await this.getWalletState();
        if (!wallet) {
          throw new Error("No wallet found");
        }
        const privateKeyHex = await this.decryptWithLockout(wallet, password);
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
        this.markActive();
        this.notifyAllAccounts([wallet.address]);
        return { success: true, data: { address: wallet.address, needsBackup: !!wallet.needsBackup } };
      }

      case "LOCK_WALLET": {
        this.notifyAllAccounts([]);
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
        const { requestId: rawId } = (payload || {}) as { requestId: string };
        const requestId = requireRequestId(rawId);
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
        const { requestId: rawId } = (payload || {}) as { requestId: string };
        const requestId = requireRequestId(rawId);
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
        this.notifyAccounts(request.origin, [address]);
        this.settlePending(this.pendingConnections, requestId, { success: true, data: { address } });
        return { success: true, data: { address } };
      }

      case "REJECT_CONNECTION": {
        const { requestId: rawId } = (payload || {}) as { requestId: string };
        const requestId = requireRequestId(rawId);
        if (!this.settlePending(this.pendingConnections, requestId, { success: false, error: "User rejected" })) {
          throw new Error("Connection request not found or expired");
        }
        return { success: true };
      }

      case "REQUEST_TRANSACTION":
      case "REQUEST_SIGN": {
        if (!this.connectedSites.has(origin)) {
          throw new Error("Site not connected. Call nunchi_requestAccounts first.");
        }
        const { coin: rawCoin, to: rawTo, amount: rawAmount, from: rawFrom } = (payload || {}) as {
          coin: string;
          to: string;
          amount: string;
          from?: string;
        };
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        if (rawFrom !== undefined && rawFrom !== this.unlockedWallet.address) {
          throw new Error("from address must match unlocked wallet");
        }
        const coin = requireCoinHex(rawCoin);
        const to = requireAddress(rawTo);
        const amount = requirePositiveAmount(rawAmount);
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
        const { requestId: rawId } = (payload || {}) as { requestId: string };
        const requestId = requireRequestId(rawId);
        const request = this.pendingTransactions.get(requestId);
        if (!request) {
          throw new Error("Transaction request not found or expired");
        }
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const coin = requireCoinHex(request.coin);
        const to = requireAddress(request.to);
        const amount = requirePositiveAmount(request.amount);
        if (request.from !== this.unlockedWallet.address) {
          this.settlePending(this.pendingTransactions, requestId, {
            success: false,
            error: "Transaction from address must match unlocked wallet",
          });
          throw new Error("Transaction from address must match unlocked wallet");
        }
        try {
          const result = await this.withSubmitLock(async () => {
            if (!this.unlockedWallet) {
              throw new Error("Wallet is locked");
            }
            return this.authorizeTransfer(
              this.unlockedWallet,
              coin,
              request.from,
              to,
              amount,
              request.submit
            );
          });
          this.settlePending(this.pendingTransactions, requestId, { success: true, data: result });
          return { success: true, data: result };
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          this.settlePending(this.pendingTransactions, requestId, { success: false, error: message });
          throw error;
        }
      }

      case "REJECT_TRANSACTION": {
        const { requestId: rawId } = (payload || {}) as { requestId: string };
        const requestId = requireRequestId(rawId);
        if (!this.settlePending(this.pendingTransactions, requestId, { success: false, error: "User rejected" })) {
          throw new Error("Transaction request not found or expired");
        }
        return { success: true };
      }

      case "SEND_TRANSACTION": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { from, to: rawTo, amount: rawAmount, coin: rawCoin } = payload as {
          from: string;
          to: string;
          amount: string;
          coin: string;
        };
        if (from !== this.unlockedWallet.address) {
          throw new Error("from address must match unlocked wallet");
        }
        const to = requireAddress(rawTo);
        const amount = requirePositiveAmount(rawAmount);
        const coin = requireCoinHex(rawCoin);
        const wallet = this.unlockedWallet;
        return {
          success: true,
          data: await this.withSubmitLock(() => this.authorizeTransfer(wallet, coin, from, to, amount, true)),
        };
      }

      case "CREATE_TOKEN": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { symbol, name, decimals, initial_supply, max_supply } = (payload || {}) as {
          symbol: string;
          name: string;
          decimals: number;
          initial_supply: string;
          max_supply?: string;
        };
        const tokenSymbol = requireTokenSymbol(symbol);
        const tokenName = requireTokenName(name);
        const tokenDecimals = requireDecimals(decimals);
        const initialSupply = requireAmount(initial_supply);
        const maxSupply = max_supply ? requireAmount(max_supply) : "";
        if (maxSupply !== "" && BigInt(initialSupply) > BigInt(maxSupply)) {
          throw new Error("Initial supply exceeds max supply");
        }
        const wallet = this.unlockedWallet;
        return this.withSubmitLock(async () => {
          this.requireUnlocked(wallet);
          const settings = await this.getSettings();
          const nonce = await this.allocateNonce(settings.rpcUrl, wallet.address);
          const factoryNonce = await this.allocateFactoryNonce(settings.rpcUrl);
          const wasm = await this.host.wasm();
          const signed = wasm.sign_create_token(
            wallet.privateKeyHex,
            nonce,
            tokenSymbol,
            tokenName,
            tokenDecimals,
            initialSupply,
            maxSupply
          );
          const coin = wasm.derive_coin_id(
            wallet.address,
            factoryNonce,
            tokenSymbol,
            tokenName,
            tokenDecimals,
            initialSupply,
            maxSupply
          );
          const submitted = await this.submitSigned(signed, { coin, to: wallet.address, amount: initialSupply });
          await this.commitCursors({
            address: wallet.address,
            nextNonce: nonce + 1n,
            factoryNonce: factoryNonce + 1n,
          });
          return { success: true, data: { ...submitted, coin, factoryNonce: nonceToJson(factoryNonce) } };
        });
      }

      case "MINT": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { coin: rawCoin, to: rawTo, amount: rawAmount } = payload as {
          coin: string;
          to: string;
          amount: string;
        };
        const coin = requireCoinHex(rawCoin);
        const to = requireAddress(rawTo);
        const amount = requirePositiveAmount(rawAmount);
        const wallet = this.unlockedWallet;
        return this.withSubmitLock(async () => {
          this.requireUnlocked(wallet);
          const settings = await this.getSettings();
          const nonce = await this.allocateNonce(settings.rpcUrl, wallet.address);
          const wasm = await this.host.wasm();
          const signed = wasm.sign_mint(wallet.privateKeyHex, nonce, coin, to, amount);
          const submitted = await this.submitSigned(signed, { coin, to, amount });
          await this.commitCursors({ address: wallet.address, nextNonce: nonce + 1n });
          return { success: true, data: submitted };
        });
      }

      case "BURN": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { coin: rawCoin, amount: rawAmount } = payload as { coin: string; amount: string };
        const coin = requireCoinHex(rawCoin);
        const amount = requirePositiveAmount(rawAmount);
        const wallet = this.unlockedWallet;
        return this.withSubmitLock(async () => {
          this.requireUnlocked(wallet);
          const settings = await this.getSettings();
          const nonce = await this.allocateNonce(settings.rpcUrl, wallet.address);
          const wasm = await this.host.wasm();
          const signed = wasm.sign_burn(wallet.privateKeyHex, nonce, coin, wallet.address, amount);
          const submitted = await this.submitSigned(signed, { coin, to: wallet.address, amount });
          await this.commitCursors({ address: wallet.address, nextNonce: nonce + 1n });
          return { success: true, data: submitted };
        });
      }

      case "REGISTER_ACCOUNT_POLICY": {
        if (!this.unlockedWallet) {
          throw new Error("Wallet is locked");
        }
        const { threshold, signer_pub_keys } = (payload || {}) as {
          threshold?: number;
          signer_pub_keys?: string;
        };
        const wallet = this.unlockedWallet;
        const ownKey = wallet.publicKeyHex.toLowerCase();
        const keys =
          signer_pub_keys === undefined || signer_pub_keys === ""
            ? ownKey
            : requireSignerPubKeys(signer_pub_keys);
        const parts = keys.split(",").filter(Boolean);
        if (!parts.includes(ownKey)) {
          throw new Error("Policy must include the unlocked wallet public key");
        }
        const required = requireThreshold(threshold ?? 1, parts.length);
        // The extension holds one key, so it can only produce one signature.
        // A higher threshold verifies as InvalidSignature and can never land.
        if (required > 1) {
          throw new Error("This wallet can only authorize a one-signature policy");
        }
        return this.withSubmitLock(async () => {
          this.requireUnlocked(wallet);
          const settings = await this.getSettings();
          const wasm = await this.host.wasm();
          const account = wasm.derive_multisig_account(required, keys);
          const nonce = await this.allocateNonce(settings.rpcUrl, account);
          const signed = wasm.sign_register_account_policy(wallet.privateKeyHex, nonce, required, keys);
          const accountId = signed.account ?? account;
          const submitted = await this.submitSigned(signed, {
            coin: "",
            to: accountId,
            amount: "0",
          });
          await this.commitCursors({ address: accountId, nextNonce: nonce + 1n });
          return { success: true, data: { ...submitted, account: accountId } };
        });
      }

      case "GET_CONNECTED_SITES": {
        return { success: true, data: Array.from(this.connectedSites) };
      }

      case "GET_ACCOUNTS": {
        // Pages get `{ accounts: string[] }`. The popup probes the same type
        // expecting AccountSummary[], so privileged callers must miss so the
        // account switcher stays hidden on a real (single-key) wallet.
        if (isPrivileged) {
          throw new Error("Unknown message type: GET_ACCOUNTS");
        }
        if (!this.connectedSites.has(origin) || !this.unlockedWallet) {
          return { success: true, data: { accounts: [] } };
        }
        return { success: true, data: { accounts: [this.unlockedWallet.address] } };
      }

      case "DISCONNECT": {
        this.connectedSites.delete(origin);
        await this.persistConnectedSites();
        this.notifyAccounts(origin, []);
        return { success: true };
      }

      case "DISCONNECT_SITE": {
        const { origin: rawOrigin } = (payload || {}) as { origin: string };
        const siteOrigin = requirePageOrigin(rawOrigin);
        this.connectedSites.delete(siteOrigin);
        await this.persistConnectedSites();
        this.notifyAccounts(siteOrigin, []);
        return { success: true };
      }

      case "GET_SETTINGS": {
        return { success: true, data: await this.getSettings() };
      }

      case "UPDATE_SETTINGS": {
        const incoming = (payload || {}) as Partial<Settings>;
        const current = await this.getSettings();
        const settings: Settings = {
          rpcUrl: typeof incoming.rpcUrl === "string" ? incoming.rpcUrl : current.rpcUrl,
          network: requireLabel(
            typeof incoming.network === "string" ? incoming.network : current.network,
            "Network"
          ),
          chainId: requireLabel(
            typeof incoming.chainId === "string" ? incoming.chainId : current.chainId,
            "Chain ID"
          ),
          displayCoin: current.displayCoin,
        };
        parseRpcUrl(settings.rpcUrl);
        if (incoming.displayCoin) {
          settings.displayCoin = requireCoinHex(incoming.displayCoin);
        } else if (incoming.displayCoin === "") {
          settings.displayCoin = "";
        }
        // Cursors are the next nonce on one chain. Another RPC has its own
        // sequence, so drop them before publishing the switch. Hold the submit
        // lock so an in-flight send cannot rewrite the old cursor afterward.
        if (settings.rpcUrl !== current.rpcUrl) {
          await this.withSubmitLock(async () => {
            await this.clearNonceCursors();
            await this.host.storageSet({ settings });
          });
        } else {
          await this.host.storageSet({ settings });
        }
        return { success: true, data: settings };
      }

      case "GET_CHAIN_ID": {
        const settings = await this.getSettings();
        return { success: true, data: { chainId: settings.chainId || settings.network || DEFAULT_SETTINGS.chainId } };
      }

      case "GET_NONCE": {
        const { address } = payload as { address: string };
        const settings = await this.getSettings();
        const nonce = await this.readChainNonce(settings.rpcUrl, requireAddress(address));
        return {
          success: true,
          data: { nonce: nonceToJson(nonce) },
        };
      }

      case "GET_BALANCE": {
        const { address, coin } = payload as { address: string; coin: string };
        const settings = await this.getSettings();
        return {
          success: true,
          data: {
            balance: await this.fetchBalance(settings.rpcUrl, requireAddress(address), requireCoinHex(coin)),
          },
        };
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
      this.notifyAllAccounts([]);
      this.unlockedWallet = null;
    }
  }

  private markActive(): void {
    this.lastActive = this.host.now();
  }

  private notifyAccounts(origin: string, accounts: string[]): void {
    this.accountEpoch += 1;
    this.host.broadcast?.(origin, "accountsChanged", accounts);
  }

  private notifyAllAccounts(accounts: string[]): void {
    for (const origin of this.connectedSites) {
      this.notifyAccounts(origin, accounts);
    }
  }

  private async hydrate(): Promise<void> {
    if (!this.hydratePromise) {
      this.hydratePromise = this.loadPersisted().catch((error) => {
        this.hydratePromise = null;
        throw error;
      });
    }
    await this.hydratePromise;
  }

  private async loadPersisted(): Promise<void> {
    const stored = await this.host.storageGet([
      "connectedSites",
      "pendingConnections",
      "pendingTransactions",
      "backupRevealed",
      NONCE_CURSOR_STORAGE,
      FACTORY_CURSOR_STORAGE,
    ]);
    if (Array.isArray(stored.connectedSites)) {
      this.connectedSites.clear();
      for (const site of stored.connectedSites) {
        if (typeof site === "string" && site) {
          this.connectedSites.add(site);
        }
      }
    }
    if (typeof stored.backupRevealed === "boolean") {
      this.backupRevealed = stored.backupRevealed;
    }
    const cursors = stored[NONCE_CURSOR_STORAGE];
    if (cursors && typeof cursors === "object") {
      for (const [address, value] of Object.entries(cursors as Record<string, unknown>)) {
        if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
          this.nonceCursor.set(address, BigInt(value));
        }
      }
    }
    const factoryCursor = stored[FACTORY_CURSOR_STORAGE];
    if (typeof factoryCursor === "string" && /^(0|[1-9][0-9]*)$/.test(factoryCursor)) {
      this.factoryCursor = BigInt(factoryCursor);
    }
    if (Array.isArray(stored.pendingConnections)) {
      for (const item of stored.pendingConnections as StoredConnection[]) {
        if (!item?.id || !item.origin) {
          continue;
        }
        try {
          requireRequestId(item.id);
          requirePageOrigin(item.origin);
        } catch {
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
        try {
          requireRequestId(item.id);
          requirePageOrigin(item.origin);
          requireCoinHex(item.coin);
          requireAddress(item.to);
          requireAmount(item.amount);
        } catch {
          continue;
        }
        this.pendingTransactions.set(item.id, {
          ...item,
          submit: item.submit === true,
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

  private async readLockout(): Promise<{ count: number; lastAttempt: number }> {
    const stored = await this.host.storageGet(LOCKOUT_STORAGE);
    const value = stored[LOCKOUT_STORAGE] as { count?: number; lastAttempt?: number } | undefined;
    if (value && typeof value.count === "number") {
      return { count: value.count, lastAttempt: value.lastAttempt || 0 };
    }
    return { count: 0, lastAttempt: 0 };
  }

  private async writeLockout(value: { count: number; lastAttempt: number } | null): Promise<void> {
    if (!value) {
      await this.host.storageRemove([LOCKOUT_STORAGE]);
      return;
    }
    await this.host.storageSet({ [LOCKOUT_STORAGE]: value });
  }

  private async decryptWithLockout(wallet: WalletState, password: unknown): Promise<string> {
    const secret = requirePassword(password);
    const now = this.host.now();
    const attempts = await this.readLockout();
    if (attempts.count >= MAX_UNLOCK_ATTEMPTS) {
      const timeSinceLastAttempt = now - attempts.lastAttempt;
      if (timeSinceLastAttempt < LOCKOUT_DURATION) {
        const remainingMs = LOCKOUT_DURATION - timeSinceLastAttempt;
        throw new Error(`Too many failed attempts. Try again in ${Math.ceil(remainingMs / 1000)}s`);
      }
      await this.writeLockout(null);
      attempts.count = 0;
      attempts.lastAttempt = 0;
    }
    try {
      const privateKeyHex = await decryptPrivateKey(wallet.encrypted, wallet.salt, secret);
      await this.writeLockout(null);
      return privateKeyHex;
    } catch (error) {
      attempts.count += 1;
      attempts.lastAttempt = now;
      await this.writeLockout(attempts);
      throw error;
    }
  }

  private async withBusy<T>(fn: () => Promise<T>): Promise<T> {
    if (this.busy) {
      throw new Error("Wallet is busy");
    }
    this.busy = true;
    try {
      return await fn();
    } finally {
      this.busy = false;
    }
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

  private rejectOutstanding(error: string): void {
    for (const requestId of [...this.pendingConnections.keys()]) {
      const request = this.pendingConnections.get(requestId);
      if (!request) {
        continue;
      }
      this.pendingConnections.delete(requestId);
      request.resolve({ success: false, error });
    }
    for (const requestId of [...this.pendingTransactions.keys()]) {
      const request = this.pendingTransactions.get(requestId);
      if (!request) {
        continue;
      }
      this.pendingTransactions.delete(requestId);
      request.resolve({ success: false, error });
    }
  }

  private async withSubmitLock<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.submitQueue;
    let release: () => void = () => undefined;
    this.submitQueue = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private requireUnlocked(wallet: UnlockedWallet): void {
    if (this.unlockedWallet?.privateKeyHex !== wallet.privateKeyHex) {
      throw new Error("Wallet is locked");
    }
  }

  private async authorizeTransfer(
    wallet: UnlockedWallet,
    coin: string,
    from: string,
    to: string,
    amount: string,
    submit: boolean
  ): Promise<{ hash?: string; digest: string; transaction: string }> {
    this.requireUnlocked(wallet);
    const settings = await this.getSettings();
    const nonce = await this.allocateNonce(settings.rpcUrl, from);
    const signed = await this.signOnly(wallet, nonce, coin, from, to, amount);
    if (!submit) {
      return { digest: signed.digest, transaction: signed.transaction };
    }
    const hash = await this.submitTransaction(settings.rpcUrl, signed.transaction);
    await this.commitCursors({ address: from, nextNonce: nonce + 1n });
    await this.addActivity({ hash, timestamp: this.host.now(), coin, to, amount });
    return { hash, digest: signed.digest, transaction: signed.transaction };
  }

  private async signOnly(
    wallet: UnlockedWallet,
    nonce: bigint,
    coin: string,
    from: string,
    to: string,
    amount: string
  ): Promise<{ digest: string; transaction: string }> {
    const wasm = await this.host.wasm();
    const signed = wasm.sign_transfer(wallet.privateKeyHex, nonce, coin, from, to, amount);
    return { digest: signed.digest_hex, transaction: signed.transaction_hex };
  }

  private async submitSigned(
    signed: { digest_hex: string; transaction_hex: string },
    activity: { coin: string; to: string; amount: string }
  ): Promise<{ hash: string; digest: string; transaction: string }> {
    const settings = await this.getSettings();
    const hash = await this.submitTransaction(settings.rpcUrl, signed.transaction_hex);
    await this.addActivity({
      hash,
      timestamp: this.host.now(),
      coin: activity.coin,
      to: activity.to,
      amount: activity.amount,
    });
    return { hash, digest: signed.digest_hex, transaction: signed.transaction_hex };
  }

  private async clearNonceCursors(): Promise<void> {
    this.nonceCursor.clear();
    this.factoryCursor = null;
    await this.host.storageRemove([NONCE_CURSOR_STORAGE, FACTORY_CURSOR_STORAGE]);
  }

  private async allocateNonce(rpcUrl: string, address: string): Promise<bigint> {
    const chain = await this.readChainNonce(rpcUrl, address);
    const reserved = this.nonceCursor.get(address);
    if (reserved !== undefined && reserved > chain) {
      return reserved;
    }
    return chain;
  }

  private async allocateFactoryNonce(rpcUrl: string): Promise<bigint> {
    const chain = await this.readFactoryNonce(rpcUrl);
    if (this.factoryCursor !== null && this.factoryCursor > chain) {
      return this.factoryCursor;
    }
    return chain;
  }

  private async commitCursors(update: {
    address: string;
    nextNonce: bigint;
    factoryNonce?: bigint;
  }): Promise<void> {
    this.nonceCursor.set(update.address, update.nextNonce);
    if (update.factoryNonce !== undefined) {
      this.factoryCursor = update.factoryNonce;
    }
    const stored = await this.host.storageGet([NONCE_CURSOR_STORAGE, FACTORY_CURSOR_STORAGE]);
    const cursors = {
      ...((stored[NONCE_CURSOR_STORAGE] as Record<string, string> | undefined) ?? {}),
    };
    cursors[update.address] = update.nextNonce.toString();
    const items: Record<string, unknown> = { [NONCE_CURSOR_STORAGE]: cursors };
    if (update.factoryNonce !== undefined) {
      items[FACTORY_CURSOR_STORAGE] = update.factoryNonce.toString();
    }
    await this.host.storageSet(items);
  }

  private async readChainNonce(rpcUrl: string, address: string): Promise<bigint> {
    const data = await this.host.rpc(rpcUrl, {
      jsonrpc: "2.0",
      id: this.host.now(),
      method: "coins.nonce",
      params: { account: address },
    });
    if (data.error) {
      throw new Error(data.error.message);
    }
    const result = data.result as { nonce?: unknown } | undefined;
    return parseNonce(result?.nonce);
  }

  private async readFactoryNonce(rpcUrl: string): Promise<bigint> {
    const data = await this.host.rpc(rpcUrl, {
      jsonrpc: "2.0",
      id: this.host.now(),
      method: "coins.factory_nonce",
      params: {},
    });
    if (data.error) {
      throw new Error(data.error.message);
    }
    const result = data.result as { nonce?: unknown } | undefined;
    return parseNonce(result?.nonce);
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
