/**
 * Demo mode — a fake wallet backend for clicking through the popup UI without
 * creating a wallet, typing a password, or running a chain node.
 *
 * It is compiled in only when VITE_DEMO=1 (`npm run build:demo`) or under the
 * Vite dev server. In a normal `npm run build` both checks fold to `false`,
 * the bypass button is never rendered, and Rollup drops this module's payload.
 *
 * Nothing here touches key material, chrome.storage, or the real unlock path:
 * it answers popup messages from an in-memory fixture and forgets everything
 * when the popup closes. Treat every value below as scenery.
 */
import type { Message, Response, Settings, SubmittedTx } from "./types";
import { TOKENS } from "./tokens";
import { coinIdPrice, getPrices } from "./prices";

const DEMO_ADDRESS = "nch10u5u8drwre8q7ycme2vnlpnk3p07h6jyt5ffznhaf9jagnfwu9ns9kczn6";
/** The demo holds Hexy, so amounts resolve to its 6 decimals in the UI. */
const DEMO_COIN = TOKENS[0].coinId;


const PEERS = {
  alice: "nch132k4z29rwdg9adv3tf5q0up6hqf5uuzuphcs8fvj52yuvj7ck8cq6jmgsf",
  bob: "nch16pvgtdxmj6cclqdylf9palfw4nxwgy2lxmz84nefj8z22ukwxduq2g8kku",
  dex: "nch1m3myyz8trvzdlrjg2a8snrhyfg5udzqsxwvrtcauh70f9whjfstsa80qjf",
  faucet: "nch1ddddht05rfq0nmd5hr6alsa889yn4aqy02r6jwrzy5gwnuwhr8gsa36k5c",
} as const;

/** Handed out in order as accounts are added, so demo addresses stay valid bech32. */
const SPARE_ADDRESSES = [
  "nch1crtd62tmc93ug5vakyam7ehdwpzgdfpklmac967twhw276z6jd7q8uuztv",
  "nch1rfzn9qaktgmesshlx3e7h99taae6ufpp4kljzc9pttuqxyrypl9qxqq9lg",
  "nch1h72h97ljpf2422r88ma38tn8ktdduywrpmwn7tk4ncf72nfxr4pqdvdygz",
  "nch1eyxpj4xlyah92e8ewfr5xml286wq8vgftvwahafuqk9d8ry87c3qr7yg2j",
  "nch1n4rh3kmrrzj7rhv338glu7aw3eqszxwhyv8e3npwhszt8ry8z9fs6vd64l",
  "nch1cu8gpqlz85dj86t05ysm552dp3fc8ttyeg0zy4286qm25saaxz4qzt49sz",
];

/** Coin id for a symbol; the registry is the single source for both. */
function sym(symbol: string): string {
  const token = TOKENS.find((entry) => entry.symbol === symbol);
  if (!token) throw new Error(`Demo fixture references unknown token ${symbol}`);
  return token.coinId;
}

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** Deterministic 32-byte hex, so the seeded fixture looks the same on every open. */
function seededHash(seed: number): string {
  let state = seed >>> 0;
  let out = "";
  while (out.length < 64) {
    state = (state * 1664525 + 1013904223) >>> 0;
    out += state.toString(16).padStart(8, "0");
  }
  return `0x${out.slice(0, 64)}`;
}

function randomHash(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** Spread the fixture across today/yesterday/last week so the date grouping has something to group. */
function seedActivity(now: number): SubmittedTx[] {
  const at = (offset: number, to: string, amount: string, seed: number): SubmittedTx => ({
    hash: seededHash(seed),
    timestamp: now - offset,
    coin: DEMO_COIN,
    to,
    amount,
  });
  // Base units at Hexy's 6 decimals: 1,250 / 4,500 / 820.5 / 15,000 / 50,000 Hexy.
  return [
    at(2 * HOUR, PEERS.alice, "1250000000", 0xa1b2c3d4),
    at(6 * HOUR, PEERS.dex, "4500000000", 0x5e6f7a8b),
    at(DAY + 3 * HOUR, PEERS.bob, "820500000", 0x11223344),
    at(DAY + 9 * HOUR, PEERS.alice, "15000000000", 0x99aabbcc),
    at(5 * DAY, PEERS.faucet, "50000000000", 0xdeadbeef),
    {
      hash: seededHash(0x4c0ffee1),
      timestamp: now - (DAY + HOUR),
      kind: "swap",
      coin: sym("BTC"),
      to: "swap-pool",
      amount: "100000000", //        1 BTC out
      toCoin: sym("USDC"),
      toAmount: "77140000000", // 77,140 USDC back
    },
  ];
}

interface DemoAccount {
  id: string;
  label: string;
  address: string;
  curve: string;
  /** Base units per coin id, so an account can hold more than one token. */
  holdings: Record<string, bigint>;
  activity: SubmittedTx[];
}

interface DemoState {
  isUnlocked: boolean;
  accounts: DemoAccount[];
  activeId: string;
  settings: Settings;
  sites: string[];
}

function initialState(now: number): DemoState {
  return {
    isUnlocked: true,
    accounts: [
      {
        id: "acc-1",
        label: "Main account",
        address: DEMO_ADDRESS,
        curve: "Ed25519",
        holdings: {
          [sym("Hexy")]: 482_750_000_000n, //    482,750 Hexy
          [sym("USDC")]: 12_480_500_000n, //      12,480.50 USDC
          [sym("ETH")]: 2_400_000_000_000_000_000n, // 2.4 ETH
          [sym("BTC")]: 31_500_000n, //            0.315 BTC
          [sym("SOL")]: 86_250_000_000n, //       86.25 SOL
          [sym("DAI")]: 940_000_000_000_000_000n, //   0.94 DAI
          [sym("USDT")]: 4_200n, //                0.0042 USDT — exercises the <$0.01 case
        },
        activity: seedActivity(now),
      },
      {
        id: "acc-2",
        label: "Savings",
        address: SPARE_ADDRESSES[0],
        curve: "Ed25519",
        holdings: {
          [sym("Hexy")]: 128_400_000_000n,
          [sym("WBTC")]: 5_000_000n, // 0.05 WBTC
        },
        activity: [],
      },
    ],
    activeId: "acc-1",
    settings: {
      rpcUrl: "http://localhost:8545",
      network: "local",
      chainId: "nunchi-local",
      displayCoin: DEMO_COIN,
    },
    sites: ["https://app.nunchi.trade", "https://swap.example.com", "http://localhost:3000"],
  };
}

const ok = <T>(data?: T): Response<T> => ({ success: true, data });
const fail = (error: string): Response => ({ success: false, error });

/**
 * Replaces chrome.runtime.sendMessage with an in-memory stand-in, and stubs the
 * handful of other chrome APIs the popup touches so the UI also runs on the bare
 * Vite dev server (where `chrome` does not exist at all).
 */
export function installDemoBackend(): void {
  const state = initialState(Date.now());

  const active = () =>
    state.accounts.find((account) => account.id === state.activeId) ?? state.accounts[0];

  const summary = () =>
    state.accounts.map(({ id, label, address, curve }) => ({
      id,
      label,
      address,
      curve,
      active: id === state.activeId,
    }));

  async function handle(message: Message): Promise<Response> {
    // A touch of latency so loading states are visible rather than instant.
    await new Promise((resolve) => setTimeout(resolve, 120));
    const payload = (message.payload || {}) as Record<string, string>;

    switch (message.type) {
      case "GET_ACCOUNTS":
        return ok(summary());

      case "RENAME_ACCOUNT": {
        const label = payload.label?.trim();
        if (!label) return fail("Name cannot be empty");
        const account = state.accounts.find((entry) => entry.id === payload.id);
        if (!account) return fail("Unknown account");
        account.label = label;
        return ok({ id: account.id, label });
      }

      case "GET_SWAP_QUOTE": {
        if (payload.from === payload.to) return fail("Pick two different coins");
        const prices = await getPrices();
        const fromPrice = coinIdPrice(prices, payload.from);
        const toPrice = coinIdPrice(prices, payload.to);
        if (!fromPrice || !toPrice) return fail("No route for that pair");
        const amount = BigInt(payload.amount || "0");
        if (amount <= 0n) return fail("Amount must be greater than zero");

        const fromToken = TOKENS.find((entry) => entry.coinId === payload.from);
        const toToken = TOKENS.find((entry) => entry.coinId === payload.to);
        if (!fromToken || !toToken) return fail("No route for that pair");

        // Price ratio, then re-scale for the two coins' differing decimals, all
        // in integer maths so precision survives an 18-decimal leg.
        const rate = fromPrice / toPrice;
        const SCALE = 10n ** 12n;
        const scaledRate = BigInt(Math.round(rate * 1e12));
        const decimalShift = BigInt(toToken.decimals) - BigInt(fromToken.decimals);
        let gross = (amount * scaledRate) / SCALE;
        gross =
          decimalShift >= 0n
            ? gross * 10n ** decimalShift
            : gross / 10n ** -decimalShift;
        const fee = (gross * 30n) / 10_000n;

        return ok({
          out: (gross - fee).toString(),
          rate: rate.toString(),
          feeBps: 30,
          stale: prices.stale,
        });
      }

      case "SWAP": {
        const account = active();
        const amount = BigInt(payload.amount || "0");
        if (amount <= 0n) return fail("Amount must be greater than zero");
        if (amount > (account.holdings[payload.from] ?? 0n)) return fail("Insufficient balance");
        if (payload.from === payload.to) return fail("Pick two different coins");
        const prices = await getPrices();
        if (!coinIdPrice(prices, payload.from) || !coinIdPrice(prices, payload.to)) {
          return fail("No route for that pair");
        }
        // Debit the sold coin and credit the bought one, so the token list moves.
        const quote = await handle({ type: "GET_SWAP_QUOTE", payload: message.payload } as Message);
        account.holdings[payload.from] = (account.holdings[payload.from] ?? 0n) - amount;
        let received = "0";
        if (quote.success) {
          received = (quote.data as { out: string }).out;
          account.holdings[payload.to] = (account.holdings[payload.to] ?? 0n) + BigInt(received);
        }
        const tx: SubmittedTx = {
          hash: randomHash(),
          timestamp: Date.now(),
          kind: "swap",
          coin: payload.from,
          to: "swap-pool",
          amount: payload.amount,
          toCoin: payload.to,
          toAmount: received,
        };
        account.activity = [tx, ...account.activity];
        return ok({ hash: tx.hash });
      }

      case "SWITCH_ACCOUNT": {
        if (!state.accounts.some((account) => account.id === payload.id)) {
          return fail("Unknown account");
        }
        state.activeId = payload.id;
        return ok({ address: active().address });
      }

      case "ADD_ACCOUNT":
      case "IMPORT_ACCOUNT": {
        if (!payload.password) return fail("Password is required");
        if (message.type === "IMPORT_ACCOUNT" && !/^[0-9a-fA-F]{64}$/.test(payload.privateKeyHex || "")) {
          return fail("Private key must be 64 hex characters");
        }
        const spare = SPARE_ADDRESSES[state.accounts.length - 1];
        if (!spare) return fail("Demo mode has run out of spare addresses");
        const account: DemoAccount = {
          id: `acc-${state.accounts.length + 1}`,
          label: payload.label?.trim() || `Account ${state.accounts.length + 1}`,
          address: spare,
          curve: payload.curve || "Ed25519",
          holdings: {},
          activity: [],
        };
        state.accounts = [...state.accounts, account];
        state.activeId = account.id;
        return ok({ id: account.id, address: account.address });
      }

      case "GET_STATE":
        return ok({
          hasWallet: true,
          isUnlocked: state.isUnlocked,
          address: active().address,
          curve: active().curve,
          needsBackup: false,
        });

      case "UNLOCK_WALLET":
        state.isUnlocked = true;
        return ok({ address: active().address, needsBackup: false });

      case "LOCK_WALLET":
        state.isUnlocked = false;
        return ok({});

      case "GET_SETTINGS":
        return ok(state.settings);

      case "UPDATE_SETTINGS":
        state.settings = { ...state.settings, ...(message.payload as Settings) };
        return ok(state.settings);

      case "GET_BALANCE":
        return ok({ balance: (active().holdings[payload.coin] ?? 0n).toString() });

      case "GET_HOLDINGS":
        // Only what the account actually holds, richest first.
        return ok(
          Object.entries(active().holdings)
            .filter(([, amount]) => amount > 0n)
            .map(([coinId, amount]) => ({ coinId, balance: amount.toString() })),
        );

      case "GET_ACTIVITY":
        return ok(active().activity);

      case "GET_CONNECTED_SITES":
        return ok(state.sites);

      case "DISCONNECT_SITE":
        state.sites = state.sites.filter((site) => site !== payload.origin);
        return ok({});

      case "SEND_TRANSACTION": {
        const account = active();
        const coin = payload.coin || DEMO_COIN;
        const amount = BigInt(payload.amount || "0");
        if (amount <= 0n) return fail("Amount must be greater than zero");
        if (amount > (account.holdings[coin] ?? 0n)) return fail("Insufficient balance");
        account.holdings[coin] = (account.holdings[coin] ?? 0n) - amount;
        const tx: SubmittedTx = {
          hash: randomHash(),
          timestamp: Date.now(),
          coin: payload.coin || DEMO_COIN,
          to: payload.to,
          amount: payload.amount,
        };
        account.activity = [tx, ...account.activity];
        return ok({ hash: tx.hash });
      }

      case "EXPORT_PRIVATE_KEY":
        return ok({ private_key_hex: `demo-key-not-real-${"0".repeat(48)}` });

      case "REVEAL_BACKUP":
        return ok({ mnemonic: "demo mode does not hold a real recovery phrase" });

      case "CONFIRM_BACKUP":
      case "DELETE_WALLET":
      case "CREATE_WALLET":
      case "IMPORT_WALLET":
        return ok({ address: active().address, curve: active().curve, needsBackup: false });

      case "GET_PENDING_REQUEST":
        return fail("No pending request in demo mode");

      default:
        return fail(`Demo mode has no handler for ${message.type}`);
    }
  }

  const runtime = { sendMessage: (message: Message) => handle(message), id: "demo" };
  const existing = (globalThis as { chrome?: Record<string, unknown> }).chrome;
  if (existing?.runtime) {
    Object.assign(existing.runtime, runtime);
  } else {
    (globalThis as { chrome?: unknown }).chrome = {
      runtime,
      permissions: { request: async () => true },
      storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } },
    };
  }
}
