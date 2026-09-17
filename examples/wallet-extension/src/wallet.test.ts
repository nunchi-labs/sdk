import { describe, it, expect } from "vitest";
import type { Message, MessageType, Response } from "./types";
import {
  AUTO_LOCK_MS,
  LOCKOUT_DURATION,
  MAX_UNLOCK_ATTEMPTS,
  MIN_PASSWORD_LENGTH,
  PRIVILEGED_TYPES,
  Wallet,
  type WalletHost,
  type WalletWasm,
} from "./wallet";

const EXTENSION_ID = "abcdefghijklmnopqrstuvwxyzabcdef";
const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}`;
const PAGE_ORIGIN = "https://dapp.example";
const PASSWORD = "correct-password";
const GENERATED_KEY = "aa".repeat(32);
const IMPORTED_KEY = "cc".repeat(32);
const COIN = "aa".repeat(32);
const NCH_ZERO = "nch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf5f4ay";

const popup = { origin: EXTENSION_ORIGIN };
const page = { origin: PAGE_ORIGIN, tab: { url: `${PAGE_ORIGIN}/` } };

class MemoryStorage {
  private readonly data = new Map<string, unknown>();

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const list = Array.isArray(keys) ? keys : [keys];
    const out: Record<string, unknown> = {};
    for (const key of list) {
      if (this.data.has(key)) {
        out[key] = this.data.get(key);
      }
    }
    return out;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(items)) {
      this.data.set(key, value);
    }
  }

  async remove(keys: string[]): Promise<void> {
    for (const key of keys) {
      this.data.delete(key);
    }
  }
}

class FakeClock {
  nowMs = 1_700_000_000_000;

  now(): number {
    return this.nowMs;
  }

  advance(ms: number): void {
    this.nowMs += ms;
  }
}

function keyPair(privateKeyHex: string, curve = "ed25519") {
  return {
    private_key_hex: privateKeyHex,
    public_key_hex: `pub-${privateKeyHex.slice(0, 8)}`,
    address: `addr-${privateKeyHex.slice(0, 16)}`,
    curve,
  };
}

function mockWasm(): WalletWasm & { signed: Array<{ nonce: bigint; submitHint: string }> } {
  const signed: Array<{ nonce: bigint; submitHint: string }> = [];
  return {
    signed,
    generate_ed25519_keypair: () => keyPair(GENERATED_KEY),
    generate_secp256r1_keypair: () => keyPair(GENERATED_KEY, "secp256r1"),
    import_private_key: (privateKeyHex: string) => keyPair(privateKeyHex),
    sign_transfer: (_privateKeyHex, nonce, coin, from, to, amount) => {
      signed.push({ nonce, submitHint: `${coin}:${from}:${to}:${amount}` });
      return {
        transaction_hex: `tx:${nonce}:${coin}:${from}:${to}:${amount}`,
        digest_hex: `digest:${nonce}`,
      };
    },
    sign_create_token: (_privateKeyHex, nonce) => ({
      transaction_hex: `create:${nonce}`,
      digest_hex: `digest:${nonce}`,
    }),
    sign_mint: (_privateKeyHex, nonce, coin, to, amount) => ({
      transaction_hex: `mint:${nonce}:${coin}:${to}:${amount}`,
      digest_hex: `digest:${nonce}`,
    }),
    sign_burn: (_privateKeyHex, nonce, coin, from, amount) => ({
      transaction_hex: `burn:${nonce}:${coin}:${from}:${amount}`,
      digest_hex: `digest:${nonce}`,
    }),
    sign_register_account_policy: (_privateKeyHex, nonce) => ({
      transaction_hex: `policy:${nonce}`,
      digest_hex: `digest:${nonce}`,
      account: "nch1policy",
    }),
    derive_coin_id: () => "cc".repeat(32),
    derive_multisig_account: () => "nch1policy",
  };
}

function parseRequestId(path: string): string {
  const query = path.split("?")[1] ?? "";
  const id = new URLSearchParams(query).get("id");
  if (!id) {
    throw new Error(`missing request id in ${path}`);
  }
  return id;
}

function createHarness(options?: { storage?: MemoryStorage; clock?: FakeClock }) {
  const storage = options?.storage ?? new MemoryStorage();
  const clock = options?.clock ?? new FakeClock();
  const wasm = mockWasm();
  const approvalPaths: string[] = [];
  let nextWindowId = 100;
  let lastWindowId = 0;
  let nonce = 7;
  const rpcCalls: Array<{ method: string; params: unknown }> = [];

  const host: WalletHost = {
    now: () => clock.now(),
    storageGet: (keys) => storage.get(keys),
    storageSet: (items) => storage.set(items),
    storageRemove: (keys) => storage.remove(keys),
    extensionId: EXTENSION_ID,
    approvalTimeoutMs: 5_000,
    openApproval: async (path) => {
      approvalPaths.push(path);
      nextWindowId += 1;
      return nextWindowId;
    },
    rpc: async (_url, body) => {
      const request = body as { method: string; params: unknown };
      rpcCalls.push(request);
      if (request.method === "coins.nonce") {
        return { result: { nonce } };
      }
      if (request.method === "coins.factory_nonce") {
        return { result: { nonce: 1 } };
      }
      if (request.method === "coins.balance") {
        return { result: { amount: "42" } };
      }
      if (request.method === "coins.submit_transaction") {
        return { result: { hash: "0xabc" } };
      }
      return { error: { message: `unknown method ${request.method}` } };
    },
    wasm: async () => wasm,
  };

  return {
    wallet: new Wallet(host),
    host,
    storage,
    clock,
    wasm,
    approvalPaths,
    rpcCalls,
    setNonce: (value: number) => {
      nonce = value;
    },
    restart(): Wallet {
      return new Wallet(host);
    },
  };
}

async function send(
  wallet: Wallet,
  type: MessageType,
  sender: { origin?: string; url?: string; tab?: { url?: string } },
  payload?: unknown
): Promise<Response> {
  try {
    return await wallet.handleMessage({ type, payload } as Message, sender);
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : String(error) };
  }
}

async function waitForApproval(paths: string[], seen = 0): Promise<string> {
  for (let i = 0; i < 50; i++) {
    if (paths.length > seen) {
      return parseRequestId(paths[paths.length - 1]);
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("approval window was not opened");
}

async function createWallet(wallet: Wallet): Promise<Response> {
  return send(wallet, "CREATE_WALLET", popup, { curve: "Ed25519", password: PASSWORD });
}

async function connectSite(harness: ReturnType<typeof createHarness>): Promise<void> {
  const seen = harness.approvalPaths.length;
  const pending = harness.wallet.handleMessage({ type: "REQUEST_CONNECTION" }, page);
  const requestId = await waitForApproval(harness.approvalPaths, seen);
  const approved = await send(harness.wallet, "APPROVE_CONNECTION", popup, { requestId });
  expect(approved.success).toBe(true);
  expect((await pending).success).toBe(true);
}

describe("wallet message table", () => {
  it("rejects every privileged type from a page origin", async () => {
    const { wallet } = createHarness();
    expect(PRIVILEGED_TYPES.size).toBeGreaterThan(0);

    for (const type of PRIVILEGED_TYPES) {
      const response = await send(wallet, type, page, {});
      expect(response.success, type).toBe(false);
      expect(response.error, type).toBe("Unauthorized: privileged operation");
    }
  });

  it("allows unprivileged page messages", async () => {
    const { wallet } = createHarness();
    const chain = await send(wallet, "GET_CHAIN_ID", page);
    expect(chain).toEqual({ success: true, data: { chainId: "nunchi-local" } });

    const accounts = await send(wallet, "GET_ACCOUNTS", page);
    expect(accounts).toEqual({ success: true, data: { accounts: [] } });

    const connection = await send(wallet, "REQUEST_CONNECTION", page);
    expect(connection.success).toBe(false);
    expect(connection.error).toBe("Wallet is locked");
  });

  it("rejects an unsupported curve", async () => {
    const { wallet } = createHarness();
    const created = await send(wallet, "CREATE_WALLET", popup, { curve: "secp256k1", password: PASSWORD });
    expect(created.success).toBe(false);
    expect(created.error).toBe("Unsupported curve");
  });

  it("rejects dApp requests with an empty sender origin", async () => {
    const { wallet } = createHarness();
    const response = await send(wallet, "REQUEST_CONNECTION", {});
    expect(response.success).toBe(false);
    expect(response.error).toBe("Missing sender origin");
  });
});

describe("create, backup, and delete", () => {
  it("creates a wallet without returning the private key", async () => {
    const { wallet } = createHarness();
    const created = await createWallet(wallet);
    expect(created.success).toBe(true);
    expect(created.data).toEqual({
      address: keyPair(GENERATED_KEY).address,
      curve: "ed25519",
      needsBackup: true,
    });
    expect(created.data).not.toHaveProperty("private_key_hex");
    expect(created.data).not.toHaveProperty("privateKeyHex");
  });

  it("enforces the background password minimum", async () => {
    const { wallet } = createHarness();
    const created = await send(wallet, "CREATE_WALLET", popup, {
      curve: "Ed25519",
      password: "1234567",
    });
    expect(created.success).toBe(false);
    expect(created.error).toBe(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  });

  it("reveals the backup only until confirm, then deletes with the password", async () => {
    const { wallet } = createHarness();
    expect((await createWallet(wallet)).success).toBe(true);

    const revealed = await send(wallet, "REVEAL_BACKUP", popup, {});
    expect(revealed).toEqual({ success: true, data: { private_key_hex: GENERATED_KEY } });

    expect((await send(wallet, "CONFIRM_BACKUP", popup)).success).toBe(true);
    const afterConfirm = await send(wallet, "REVEAL_BACKUP", popup, {});
    expect(afterConfirm.success).toBe(false);
    expect(afterConfirm.error).toBe("No pending backup");

    const state = await send(wallet, "GET_STATE", popup);
    expect(state.data).toMatchObject({ hasWallet: true, needsBackup: false, isUnlocked: true });

    const deleted = await send(wallet, "DELETE_WALLET", popup, { password: PASSWORD });
    expect(deleted.success).toBe(true);
    const afterDelete = await send(wallet, "GET_STATE", popup);
    expect(afterDelete.data).toMatchObject({ hasWallet: false, isUnlocked: false });
  });
});

describe("coin operations", () => {
  it("creates, mints, burns, and registers a policy through the wallet", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);

    const created = await send(harness.wallet, "CREATE_TOKEN", popup, {
      symbol: "WLT",
      name: "Wallet",
      decimals: 6,
      initial_supply: "1000",
      max_supply: "5000",
    });
    expect(created.success, created.error).toBe(true);
    expect(created.data).toMatchObject({
      hash: "0xabc",
      coin: "cc".repeat(32),
      factoryNonce: 1,
    });

    const minted = await send(harness.wallet, "MINT", popup, {
      coin: COIN,
      to: NCH_ZERO,
      amount: "10",
    });
    expect(minted.success, minted.error).toBe(true);
    expect(minted.data).toMatchObject({ hash: "0xabc" });

    const burned = await send(harness.wallet, "BURN", popup, { coin: COIN, amount: "3" });
    expect(burned.success, burned.error).toBe(true);

    const registered = await send(harness.wallet, "REGISTER_ACCOUNT_POLICY", popup, {});
    expect(registered.success, registered.error).toBe(true);
    expect(registered.data).toMatchObject({ account: "nch1policy", hash: "0xabc" });
    expect(harness.rpcCalls.map((call) => call.method)).toEqual([
      "coins.nonce",
      "coins.factory_nonce",
      "coins.submit_transaction",
      "coins.nonce",
      "coins.submit_transaction",
      "coins.nonce",
      "coins.submit_transaction",
      "coins.nonce",
      "coins.submit_transaction",
    ]);
  });
});

describe("sign versus submit", () => {
  it("signs without submitting and fetches nonce only at confirm", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);

    harness.setNonce(3);
    const seen = harness.approvalPaths.length;
    const signPending = harness.wallet.handleMessage(
      { type: "REQUEST_SIGN", payload: { coin: COIN, to: NCH_ZERO, amount: "1" } },
      page
    );
    const signId = await waitForApproval(harness.approvalPaths, seen);
    const pending = await send(harness.wallet, "GET_PENDING_REQUEST", popup, { requestId: signId });
    expect(pending.data).toMatchObject({ kind: "transaction", nonce: 0, submit: false });
    expect(harness.rpcCalls.map((call) => call.method)).not.toContain("coins.nonce");

    harness.setNonce(42);
    const approved = await send(harness.wallet, "APPROVE_TRANSACTION", popup, { requestId: signId });
    expect(approved.success).toBe(true);
    expect(approved.data).toEqual({ digest: "digest:42", transaction: expect.stringContaining("tx:42:") });
    expect((await signPending).success).toBe(true);
    expect(harness.wasm.signed[0]?.nonce).toBe(42n);
    expect(harness.rpcCalls.map((call) => call.method)).toEqual(["coins.nonce"]);
  });

  it("submits when the dApp requested a transaction", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);

    const seen = harness.approvalPaths.length;
    const sendPending = harness.wallet.handleMessage(
      { type: "REQUEST_TRANSACTION", payload: { coin: COIN, to: NCH_ZERO, amount: "2" } },
      page
    );
    const requestId = await waitForApproval(harness.approvalPaths, seen);
    const pending = await send(harness.wallet, "GET_PENDING_REQUEST", popup, { requestId });
    expect(pending.data).toMatchObject({ submit: true, nonce: 0 });

    const approved = await send(harness.wallet, "APPROVE_TRANSACTION", popup, { requestId });
    expect(approved.success).toBe(true);
    expect(approved.data).toMatchObject({ hash: "0xabc" });
    expect((await sendPending).data).toMatchObject({ hash: "0xabc" });
    expect(harness.rpcCalls.map((call) => call.method)).toContain("coins.submit_transaction");
  });
});

describe("lockout and auto-lock", () => {
  it("persists unlock lockout across a worker restart", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    expect((await send(harness.wallet, "LOCK_WALLET", popup)).success).toBe(true);

    for (let i = 0; i < MAX_UNLOCK_ATTEMPTS; i++) {
      const failed = await send(harness.wallet, "UNLOCK_WALLET", popup, { password: "wrong-password" });
      expect(failed.success).toBe(false);
      expect(failed.error).toBe("Invalid password");
    }

    const lockedOut = await send(harness.wallet, "UNLOCK_WALLET", popup, { password: PASSWORD });
    expect(lockedOut.success).toBe(false);
    expect(lockedOut.error).toMatch(/Too many failed attempts/);

    harness.wallet.shutdown();
    const restarted = harness.restart();
    const stillLocked = await send(restarted, "UNLOCK_WALLET", popup, { password: PASSWORD });
    expect(stillLocked.success).toBe(false);
    expect(stillLocked.error).toMatch(/Too many failed attempts/);

    harness.clock.advance(LOCKOUT_DURATION + 1);
    const unlocked = await send(restarted, "UNLOCK_WALLET", popup, { password: PASSWORD });
    expect(unlocked.success).toBe(true);
    expect(unlocked.data).toMatchObject({ address: keyPair(GENERATED_KEY).address });
  }, 30_000);

  it("auto-locks after 15 minutes of idle time", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);

    const before = await send(harness.wallet, "GET_STATE", popup);
    expect(before.data).toMatchObject({ isUnlocked: true });

    harness.clock.advance(AUTO_LOCK_MS + 1);
    const after = await send(harness.wallet, "GET_STATE", popup);
    expect(after.data).toMatchObject({ hasWallet: true, isUnlocked: false });
  });
});

describe("persisted sites and pending requests", () => {
  it("reloads connected sites after a worker restart", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);
    harness.wallet.shutdown();

    const restarted = harness.restart();
    expect((await send(restarted, "UNLOCK_WALLET", popup, { password: PASSWORD })).success).toBe(true);
    const sites = await send(restarted, "GET_CONNECTED_SITES", popup);
    expect(sites.data).toEqual([PAGE_ORIGIN]);

    const reconnect = await send(restarted, "REQUEST_CONNECTION", page);
    expect(reconnect).toEqual({ success: true, data: { address: keyPair(GENERATED_KEY).address } });
  });

  it("reloads a pending request after a worker restart", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);

    const seen = harness.approvalPaths.length;
    void harness.wallet.handleMessage(
      { type: "REQUEST_TRANSACTION", payload: { coin: COIN, to: NCH_ZERO, amount: "3" } },
      page
    );
    const requestId = await waitForApproval(harness.approvalPaths, seen);
    for (let i = 0; i < 50; i++) {
      const stored = await harness.storage.get("pendingTransactions");
      const items = stored.pendingTransactions as Array<{ id: string }> | undefined;
      if (items?.some((item) => item.id === requestId)) {
        break;
      }
      if (i === 49) {
        throw new Error("pending request was not persisted");
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    harness.wallet.shutdown();

    const restarted = harness.restart();
    expect((await send(restarted, "UNLOCK_WALLET", popup, { password: PASSWORD })).success).toBe(true);
    const stored = await send(restarted, "GET_PENDING_REQUEST", popup, { requestId });
    expect(stored.data).toMatchObject({
      kind: "transaction",
      origin: PAGE_ORIGIN,
      submit: true,
      nonce: 0,
      amount: "3",
    });

    const approved = await send(restarted, "APPROVE_TRANSACTION", popup, { requestId });
    expect(approved.success).toBe(true);
    expect(approved.data).toMatchObject({ hash: "0xabc" });
  });
});

describe("accounts, disconnect, and validation", () => {
  it("returns connected accounts only while unlocked", async () => {
    const events: Array<{ origin: string; event: string; params: unknown }> = [];
    const harness = createHarness();
    harness.host.broadcast = (origin, event, params) => {
      events.push({ origin, event, params });
    };
    expect((await createWallet(harness.wallet)).success).toBe(true);

    const before = await send(harness.wallet, "GET_ACCOUNTS", page);
    expect(before).toEqual({ success: true, data: { accounts: [] } });

    await connectSite(harness);
    const connected = await send(harness.wallet, "GET_ACCOUNTS", page);
    expect(connected).toEqual({
      success: true,
      data: { accounts: [keyPair(GENERATED_KEY).address] },
    });
    expect(events).toContainEqual({
      origin: PAGE_ORIGIN,
      event: "accountsChanged",
      params: [keyPair(GENERATED_KEY).address],
    });

    expect((await send(harness.wallet, "LOCK_WALLET", popup)).success).toBe(true);
    const locked = await send(harness.wallet, "GET_ACCOUNTS", page);
    expect(locked).toEqual({ success: true, data: { accounts: [] } });
    expect(events).toContainEqual({ origin: PAGE_ORIGIN, event: "accountsChanged", params: [] });

    expect((await send(harness.wallet, "UNLOCK_WALLET", popup, { password: PASSWORD })).success).toBe(true);
    expect((await send(harness.wallet, "GET_ACCOUNTS", page)).data).toEqual({
      accounts: [keyPair(GENERATED_KEY).address],
    });

    expect((await send(harness.wallet, "DISCONNECT", page)).success).toBe(true);
    expect((await send(harness.wallet, "GET_ACCOUNTS", page)).data).toEqual({ accounts: [] });
    const sites = await send(harness.wallet, "GET_CONNECTED_SITES", popup);
    expect(sites.data).toEqual([]);
  });

  it("rejects invalid transfer fields before opening approval", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);

    const invalid = await send(harness.wallet, "REQUEST_TRANSACTION", page, {
      coin: "aa".repeat(16),
      to: "not-an-address",
      amount: "1",
    });
    expect(invalid.success).toBe(false);
    expect(invalid.error).toBe("Coin id must be 32 bytes hex");
    expect(harness.approvalPaths).toHaveLength(1);

    const badAmount = await send(harness.wallet, "SEND_TRANSACTION", popup, {
      from: keyPair(GENERATED_KEY).address,
      to: NCH_ZERO,
      coin: COIN,
      amount: "1.5",
    });
    expect(badAmount.success).toBe(false);
    expect(badAmount.error).toBe("Amount must be a whole number");
  });

  it("normalizes display coin hex when saving settings", async () => {
    const { wallet } = createHarness();
    const updated = await send(wallet, "UPDATE_SETTINGS", popup, {
      displayCoin: `0x${"AB".repeat(32)}`,
    });
    expect(updated.success).toBe(true);
    expect(updated.data).toMatchObject({ displayCoin: "ab".repeat(32) });
  });
});

describe("import", () => {
  it("imports a key without a pending backup", async () => {
    const { wallet } = createHarness();
    const imported = await send(wallet, "IMPORT_WALLET", popup, {
      private_key_hex: IMPORTED_KEY,
      password: PASSWORD,
    });
    expect(imported).toEqual({
      success: true,
      data: { address: keyPair(IMPORTED_KEY).address, curve: "ed25519", needsBackup: false },
    });
  });
});

describe("security hardening", () => {
  it("does not let a page confirm backup, export, or send", async () => {
    const { wallet } = createHarness();
    expect((await createWallet(wallet)).success).toBe(true);
    for (const type of ["CONFIRM_BACKUP", "EXPORT_PRIVATE_KEY", "SEND_TRANSACTION", "GET_BALANCE"] as MessageType[]) {
      const response = await send(wallet, type, page, { password: PASSWORD });
      expect(response.error, type).toBe("Unauthorized: privileged operation");
    }
  });

  it("rejects opaque and file origins for page messages", async () => {
    const { wallet } = createHarness();
    for (const origin of ["null", "file://", ""]) {
      const response = await send(wallet, "GET_CHAIN_ID", { origin });
      expect(response.success, origin).toBe(false);
      expect(response.error, origin).toBe("Missing sender origin");
    }
  });

  it("rejects a second create and parallel creates", async () => {
    const { wallet } = createHarness();
    const first = wallet.handleMessage(
      { type: "CREATE_WALLET", payload: { curve: "Ed25519", password: PASSWORD } },
      popup
    );
    const second = wallet.handleMessage(
      { type: "CREATE_WALLET", payload: { curve: "Ed25519", password: PASSWORD } },
      popup
    );
    const results = await Promise.all([
      first.then((response) => ({ ok: true, response })).catch((error) => ({
        ok: false,
        response: { success: false, error: error instanceof Error ? error.message : String(error) },
      })),
      second.then((response) => ({ ok: true, response })).catch((error) => ({
        ok: false,
        response: { success: false, error: error instanceof Error ? error.message : String(error) },
      })),
    ]);
    const errors = results.filter((result) => !result.response.success).map((result) => result.response.error);
    const successes = results.filter((result) => result.response.success);
    expect(successes).toHaveLength(1);
    expect(errors.some((error) => error === "Wallet is busy" || error?.includes("already exists"))).toBe(true);

    const again = await send(wallet, "CREATE_WALLET", popup, { curve: "Ed25519", password: PASSWORD });
    expect(again.success).toBe(false);
    expect(again.error).toMatch(/already exists/);
  });

  it("does not confirm a backup that was never revealed", async () => {
    const { wallet } = createHarness();
    expect((await createWallet(wallet)).success).toBe(true);
    const confirmed = await send(wallet, "CONFIRM_BACKUP", popup);
    expect(confirmed.success).toBe(false);
    expect(confirmed.error).toBe("Backup has not been revealed");
  });

  it("shares lockout across unlock and export", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    expect((await send(harness.wallet, "LOCK_WALLET", popup)).success).toBe(true);
    for (let i = 0; i < MAX_UNLOCK_ATTEMPTS; i++) {
      const failed = await send(harness.wallet, "UNLOCK_WALLET", popup, { password: "wrong-password" });
      expect(failed.error).toBe("Invalid password");
    }
    const exported = await send(harness.wallet, "EXPORT_PRIVATE_KEY", popup, { password: PASSWORD });
    expect(exported.success).toBe(false);
    expect(exported.error).toMatch(/Too many failed attempts/);
  });

  it("rejects a transfer from address that is not the unlocked wallet", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);
    const mismatch = await send(harness.wallet, "REQUEST_TRANSACTION", page, {
      coin: COIN,
      from: NCH_ZERO,
      to: NCH_ZERO,
      amount: "1",
    });
    expect(mismatch.success).toBe(false);
    expect(mismatch.error).toBe("from address must match unlocked wallet");
    expect(harness.approvalPaths).toHaveLength(1);
  });

  it("rejects page transfers before the site is connected", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    const response = await send(harness.wallet, "REQUEST_TRANSACTION", page, {
      coin: COIN,
      to: NCH_ZERO,
      amount: "1",
    });
    expect(response.success).toBe(false);
    expect(response.error).toMatch(/not connected/);
    expect(harness.approvalPaths).toHaveLength(0);
  });

  it("ignores unknown settings fields", async () => {
    const { wallet } = createHarness();
    const updated = await send(wallet, "UPDATE_SETTINGS", popup, {
      displayCoin: COIN,
      encrypted: "steal-the-keystore",
    });
    expect(updated.success).toBe(true);
    expect(updated.data).not.toHaveProperty("encrypted");
    expect(updated.data).toMatchObject({ displayCoin: COIN, rpcUrl: "http://localhost:8545" });
  });

  it("rejects whitespace passwords at the wallet boundary", async () => {
    const { wallet } = createHarness();
    const created = await send(wallet, "CREATE_WALLET", popup, { curve: "Ed25519", password: "        " });
    expect(created.success).toBe(false);
    expect(created.error).toBe("Password contains invalid characters");
  });

  it("rejects empty token metadata before touching RPC", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    const created = await send(harness.wallet, "CREATE_TOKEN", popup, {
      symbol: "",
      name: "Wallet",
      decimals: 6,
      initial_supply: "1000",
    });
    expect(created.success).toBe(false);
    expect(created.error).toBe("Token symbol is required");
    expect(harness.rpcCalls).toEqual([]);
  });

  it("rejects a policy threshold of zero", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    const registered = await send(harness.wallet, "REGISTER_ACCOUNT_POLICY", popup, { threshold: 0 });
    expect(registered.success).toBe(false);
    expect(registered.error).toBe("Threshold must be a positive integer");
  });

  it("broadcasts accountsChanged when auto-lock fires", async () => {
    const events: Array<{ origin: string; event: string; params: unknown }> = [];
    const harness = createHarness();
    harness.host.broadcast = (origin, event, params) => {
      events.push({ origin, event, params });
    };
    expect((await createWallet(harness.wallet)).success).toBe(true);
    await connectSite(harness);
    harness.clock.advance(AUTO_LOCK_MS + 1);
    const chain = await send(harness.wallet, "GET_CHAIN_ID", page);
    expect(chain.success).toBe(true);
    expect(events).toContainEqual({ origin: PAGE_ORIGIN, event: "accountsChanged", params: [] });
    const accounts = await send(harness.wallet, "GET_ACCOUNTS", page);
    expect(accounts.data).toEqual({ accounts: [] });
  });

  it("does not extend auto-lock when a page reads chain id", async () => {
    const harness = createHarness();
    expect((await createWallet(harness.wallet)).success).toBe(true);
    harness.clock.advance(AUTO_LOCK_MS - 1);
    expect((await send(harness.wallet, "GET_CHAIN_ID", page)).success).toBe(true);
    harness.clock.advance(2);
    const state = await send(harness.wallet, "GET_STATE", popup);
    expect(state.data).toMatchObject({ isUnlocked: false });
  });
});
