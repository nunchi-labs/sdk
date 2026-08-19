import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import type { Message, MessageType, Response } from "./types";
import { Wallet, type WalletHost, type WalletKeyPair, type WalletWasm } from "./wallet";

const EXTENSION_ID = "abcdefghijklmnopqrstuvwxyzabcdef";
const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}`;
const PASSWORD = "correct-password";
const popup = { origin: EXTENSION_ORIGIN };

const rpcUrl = process.env.NUNCHI_LIVE_RPC;
const accountsPath = process.env.NUNCHI_LIVE_ACCOUNTS;

interface LiveAccount {
  seed: number;
  private_key_hex: string;
  address: string;
}

interface LiveAccounts {
  coin: string;
  issuer: string;
  initial_balance: string;
  accounts: LiveAccount[];
}

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

function rawHex(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
}

function asRecord(value: unknown): Record<string, string> {
  if (value instanceof Map) {
    return Object.fromEntries(value) as Record<string, string>;
  }
  if (value && typeof value === "object") {
    return value as Record<string, string>;
  }
  throw new Error(`unexpected wasm return: ${typeof value}`);
}

function asKeyPair(value: unknown): WalletKeyPair {
  const record = asRecord(value);
  return {
    private_key_hex: record.private_key_hex,
    public_key_hex: record.public_key_hex,
    address: record.address,
    curve: record.curve,
  };
}

async function loadWalletWasm(): Promise<WalletWasm> {
  const wasmDir = join(dirname(fileURLToPath(import.meta.url)), "wasm");
  const wasmJs = join(wasmDir, "nunchi_wallet_crypto.js");
  const wasmBin = join(wasmDir, "nunchi_wallet_crypto_bg.wasm");
  if (!existsSync(wasmJs) || !existsSync(wasmBin)) {
    throw new Error("wallet wasm is missing; run npm run build:wasm");
  }

  const module = (await import(pathToFileURL(wasmJs).href)) as {
    default: (input?: unknown) => Promise<unknown>;
    generate_ed25519_keypair: () => unknown;
    generate_secp256r1_keypair: () => unknown;
    import_private_key: (privateKeyHex: string) => unknown;
    sign_transfer: (
      privateKeyHex: string,
      nonce: bigint,
      coin: string,
      from: string,
      to: string,
      amount: string
    ) => unknown;
  };
  await module.default({ module_or_path: await readFile(wasmBin) });
  return {
    generate_ed25519_keypair: () => asKeyPair(module.generate_ed25519_keypair()),
    generate_secp256r1_keypair: () => asKeyPair(module.generate_secp256r1_keypair()),
    import_private_key: (privateKeyHex: string) => asKeyPair(module.import_private_key(privateKeyHex)),
    sign_transfer: (privateKeyHex, nonce, coin, from, to, amount) => {
      const signed = asRecord(module.sign_transfer(privateKeyHex, nonce, coin, from, to, amount));
      return { transaction_hex: signed.transaction_hex, digest_hex: signed.digest_hex };
    },
  };
}

async function rpc<T>(method: string, params: unknown): Promise<T> {
  if (!rpcUrl) {
    throw new Error("NUNCHI_LIVE_RPC is not set");
  }
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  const data = (await response.json()) as { error?: { message: string }; result?: T };
  if (data.error) {
    throw new Error(data.error.message);
  }
  if (data.result === undefined) {
    throw new Error(`${method} returned no result`);
  }
  return data.result;
}

function createHost(wasm: WalletWasm): WalletHost {
  const storage = new MemoryStorage();
  return {
    now: () => Date.now(),
    storageGet: (keys) => storage.get(keys),
    storageSet: (items) => storage.set(items),
    storageRemove: (keys) => storage.remove(keys),
    extensionId: EXTENSION_ID,
    openApproval: async () => {
      throw new Error("live tests should not open an approval window");
    },
    rpc: async (url, body) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      return response.json();
    },
    wasm: async () => wasm,
  };
}

async function send(
  wallet: Wallet,
  type: MessageType,
  payload?: unknown
): Promise<Response> {
  return wallet.handleMessage({ type, payload } as Message, popup);
}

async function waitForFinalized(hash: string): Promise<{ status: string; height?: number }> {
  for (let i = 0; i < 90; i++) {
    const status = await rpc<{ status: string; height?: number; drop_reason?: string }>(
      "coins.transaction_status",
      { hash }
    );
    if (status.status === "finalized") {
      return status;
    }
    if (status.status === "dropped") {
      throw new Error(`transaction dropped: ${status.drop_reason ?? "unknown"}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${hash} was not finalized`);
}

describe("wallet live chain", () => {
  if (!rpcUrl || !accountsPath) {
    throw new Error("NUNCHI_LIVE_RPC and NUNCHI_LIVE_ACCOUNTS must be set");
  }
  it("imports a funded key and broadcasts a transfer", async () => {
    const fixture = JSON.parse(await readFile(accountsPath as string, "utf8")) as LiveAccounts;
    expect(fixture.accounts.length).toBeGreaterThanOrEqual(2);

    const sender = fixture.accounts[0];
    const recipient = fixture.accounts[1];
    const coin = rawHex(fixture.coin);
    const wasm = await loadWalletWasm();
    const wallet = new Wallet(createHost(wasm));

    const imported = await send(wallet, "IMPORT_WALLET", {
      private_key_hex: rawHex(sender.private_key_hex),
      password: PASSWORD,
    });
    expect(imported.success).toBe(true);
    expect(imported.data).toMatchObject({ address: sender.address });

    const settings = await send(wallet, "UPDATE_SETTINGS", { rpcUrl, network: "local", chainId: "nunchi-local" });
    expect(settings.success).toBe(true);

    const before = await send(wallet, "GET_BALANCE", { address: sender.address, coin });
    expect(before.success).toBe(true);
    expect(before.data).toMatchObject({ balance: fixture.initial_balance });

    const nonce = await send(wallet, "GET_NONCE", { address: sender.address });
    expect(nonce.success).toBe(true);
    expect(nonce.data).toMatchObject({ nonce: 0 });

    const sent = await send(wallet, "SEND_TRANSACTION", {
      from: sender.address,
      to: recipient.address,
      amount: "1",
      coin,
    });
    expect(sent.success, sent.error).toBe(true);
    const hash = (sent.data as { hash: string }).hash;
    expect(hash).toBeTruthy();

    const finalized = await waitForFinalized(hash);
    expect(finalized.status).toBe("finalized");

    const afterSender = await send(wallet, "GET_BALANCE", { address: sender.address, coin });
    const afterRecipient = await send(wallet, "GET_BALANCE", { address: recipient.address, coin });
    expect(afterSender.data).toMatchObject({
      balance: (BigInt(fixture.initial_balance) - 1n).toString(),
    });
    expect(afterRecipient.data).toMatchObject({
      balance: (BigInt(fixture.initial_balance) + 1n).toString(),
    });

    const afterNonce = await send(wallet, "GET_NONCE", { address: sender.address });
    expect(afterNonce.data).toMatchObject({ nonce: 1 });
  });
});
