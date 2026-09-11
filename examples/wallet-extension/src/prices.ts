/**
 * Live USD prices for the coins in the swap picker.
 *
 * Prices come from CoinGecko's public API. Two things to be clear about:
 *
 *  - Hexy is a placeholder token with no market, so it has no live price and
 *    keeps a fixed reference value. Everything else is quoted live.
 *  - If the fetch fails (offline, rate limited, permission not granted) the
 *    cached or fallback table is used and `stale` is set, so the UI can say so
 *    rather than presenting an old number as current.
 */
import { TOKENS } from "./tokens";

/** CoinGecko ids for the tokens that actually trade. */
export const COINGECKO_IDS: Record<string, string> = {
  USDC: "usd-coin",
  USDT: "tether",
  DAI: "dai",
  BTC: "bitcoin",
  WBTC: "wrapped-bitcoin",
  ETH: "ethereum",
  SOL: "solana",
};

/**
 * Hexy has no public market, so there is no quote to fetch. This is the
 * client's own cost basis: roughly 10-12 cents per coin, held here at the
 * midpoint. It is the single source for that number — change it here.
 */
export const HEXY_USD = 0.11;

/** Used until the first successful fetch, and whenever one fails. */
const FALLBACK_USD: Record<string, number> = {
  Hexy: HEXY_USD,
  USDC: 1,
  USDT: 1,
  DAI: 1,
  BTC: 64_000,
  WBTC: 64_000,
  ETH: 3_100,
  SOL: 148,
};

/** Merged into every snapshot: these coins are priced by reference, not quoted. */
const UNLISTED_USD: Record<string, number> = { Hexy: HEXY_USD };

export interface PriceSnapshot {
  usd: Record<string, number>;
  /**
   * 24h move as a percentage, by symbol. Only present for coins that actually
   * trade — Hexy has no market, so it has no entry here and the UI shows no
   * change rather than inventing a flat 0%.
   */
  change24h: Record<string, number>;
  /** True when these are fallback or cached numbers rather than a fresh fetch. */
  stale: boolean;
  fetchedAt: number;
}

const ENDPOINT = "https://api.coingecko.com/api/v3/simple/price";
const TTL_MS = 60_000;

let cache: PriceSnapshot | null = null;
let inflight: Promise<PriceSnapshot> | null = null;

export function priceOfSymbol(snapshot: PriceSnapshot | null, symbol: string): number | undefined {
  return snapshot?.usd[symbol] ?? FALLBACK_USD[symbol];
}

/** True when the coin actually trades, so history and market data can exist. */
export function hasMarket(coinId: string): boolean {
  const token = TOKENS.find((entry) => entry.coinId === coinId);
  return Boolean(token && COINGECKO_IDS[token.symbol]);
}

export function coinIdPrice(snapshot: PriceSnapshot | null, coinId: string): number | undefined {
  const token = TOKENS.find((entry) => entry.coinId === coinId);
  return token ? priceOfSymbol(snapshot, token.symbol) : undefined;
}

/** Undefined for coins without a market — callers must render nothing, not 0%. */
export function coinIdChange(snapshot: PriceSnapshot | null, coinId: string): number | undefined {
  const token = TOKENS.find((entry) => entry.coinId === coinId);
  return token ? snapshot?.change24h[token.symbol] : undefined;
}

/**
 * `force` skips the cache for an explicit user refresh — someone who taps
 * refresh means now, not "within the last minute". An in-flight request is
 * still shared, so a double tap does not fire two fetches.
 */
export async function getPrices(force = false): Promise<PriceSnapshot> {
  const now = Date.now();
  if (!force && cache && now - cache.fetchedAt < TTL_MS) return cache;
  if (inflight) return inflight;

  inflight = (async (): Promise<PriceSnapshot> => {
    const ids = Array.from(new Set(Object.values(COINGECKO_IDS))).join(",");
    try {
      const response = await fetch(
        `${ENDPOINT}?ids=${ids}&vs_currencies=usd&include_24hr_change=true`,
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as Record<
        string,
        { usd?: number; usd_24h_change?: number }
      >;

      const usd: Record<string, number> = { ...UNLISTED_USD };
      const change24h: Record<string, number> = {};
      let missing = false;
      for (const [symbol, id] of Object.entries(COINGECKO_IDS)) {
        const value = body[id]?.usd;
        if (typeof value === "number" && value > 0) {
          usd[symbol] = value;
        } else {
          missing = true;
          usd[symbol] = FALLBACK_USD[symbol];
        }
        const move = body[id]?.usd_24h_change;
        if (typeof move === "number" && Number.isFinite(move)) change24h[symbol] = move;
      }
      cache = { usd, change24h, stale: missing, fetchedAt: Date.now() };
      return cache;
    } catch {
      // Keep the previous snapshot if there is one, but mark it stale.
      cache = {
        usd: cache?.usd ?? { ...FALLBACK_USD },
        // A failed refresh must not leave yesterday's move on screen.
        change24h: {},
        stale: true,
        fetchedAt: Date.now(),
      };
      return cache;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}
