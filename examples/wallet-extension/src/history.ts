/**
 * Portfolio value over time.
 *
 * An important caveat, surfaced in the UI: this applies *today's* holdings to
 * historical prices. It answers "what would what I hold now have been worth
 * back then", which is a market-movement chart — not a record of what the
 * wallet actually held. Past deposits, sends and swaps are not reflected,
 * because the wallet keeps no balance history to reconstruct them from.
 *
 * Hexy has no market, so it is held flat at its reference price; a portfolio
 * weighted towards it will look correspondingly flat.
 */
import { TOKENS } from "./tokens";
import { COINGECKO_IDS, HEXY_USD } from "./prices";

export type RangeId = "1H" | "1D" | "1W" | "1M" | "1Y" | "ALL";

const DAY_MS = 86_400_000;

/**
 * `days` is what gets fetched; `window` is what gets shown. The three longest
 * ranges all read from one `days=max` response and slice it, so moving between
 * them costs no requests at all — which matters on an API that 429s a burst of
 * six. Only 1D and 1W need their own finer-grained fetch.
 */
export const RANGES: { id: RangeId; label: string; days: string; window: number }[] = [
  // 1H reuses the 1D fetch (5-minute granularity) and slices the tail.
  { id: "1H", label: "1H", days: "1", window: 60 * 60 * 1000 },
  { id: "1D", label: "1D", days: "1", window: DAY_MS },
  { id: "1W", label: "1W", days: "7", window: 7 * DAY_MS },
  { id: "1M", label: "1M", days: "max", window: 30 * DAY_MS },
  { id: "1Y", label: "1Y", days: "max", window: 365 * DAY_MS },
  { id: "ALL", label: "All", days: "max", window: Infinity },
];

export interface SeriesPoint {
  t: number;
  v: number;
}

export interface PortfolioSeries {
  points: SeriesPoint[];
  /** True when a coin's history could not be fetched and was held flat. */
  partial: boolean;
  /** True when any holding has no market and contributes a constant. */
  hasUnlisted: boolean;
  /**
   * Set when every traded holding failed to load. The caller must show an
   * error, never a flat line — "we could not fetch this" and "your balance did
   * not move" look identical on a chart and mean completely different things.
   */
  failed: boolean;
}

const ENDPOINT = "https://api.coingecko.com/api/v3/coins";
const TTL_MS = 5 * 60_000;
/** Enough resolution for a 320px-wide chart without oversampling the source. */
const GRID_POINTS = 120;

/**
 * CoinGecko's free tier has no batch history endpoint and 429s on a burst of
 * six. Only the largest traded holdings are fetched — they set the shape of
 * the curve — and the rest are held flat, which keeps the total's magnitude
 * right. Requests are staggered rather than fired in parallel for the same
 * reason, and `partial` tells the UI to say so.
 */
const MAX_HISTORY_LEGS = 3;
const STAGGER_MS = 400;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const cache = new Map<string, { at: number; series: SeriesPoint[] }>();

async function coinHistory(coingeckoId: string, days: string): Promise<SeriesPoint[] | null> {
  const key = `${coingeckoId}:${days}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.series;

  try {
    const url = `${ENDPOINT}/${coingeckoId}/market_chart?vs_currency=usd&days=${days}`;
    // The free tier throttles hard; back off and retry rather than giving up
    // on the first 429.
    let response = await fetch(url);
    for (let attempt = 0; attempt < 2 && response.status === 429; attempt++) {
      await wait(1200 * (attempt + 1));
      response = await fetch(url);
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as { prices?: [number, number][] };
    if (!body.prices?.length) throw new Error("no prices");
    const series = body.prices.map(([t, v]) => ({ t, v }));
    cache.set(key, { at: Date.now(), series });
    return series;
  } catch {
    return null;
  }
}

/** Last known value at or before `t`; series are ascending so this walks forward. */
function sampler(series: SeriesPoint[]) {
  let i = 0;
  return (t: number): number => {
    while (i + 1 < series.length && series[i + 1].t <= t) i++;
    return series[i].v;
  };
}

/** Price series for a single coin, for the asset page's chart. */
export async function getTokenHistory(coinId: string, range: RangeId): Promise<PortfolioSeries> {
  const spec = RANGES.find((r) => r.id === range) ?? RANGES[2];
  const token = TOKENS.find((entry) => entry.coinId === coinId);
  const geckoId = token ? COINGECKO_IDS[token.symbol] : undefined;
  if (!geckoId) return { points: [], partial: false, hasUnlisted: true, failed: false };

  const series = await coinHistory(geckoId, spec.days);
  if (!series) return { points: [], partial: true, hasUnlisted: false, failed: true };

  const end = series[series.length - 1].t;
  const start = Number.isFinite(spec.window) ? Math.max(series[0].t, end - spec.window) : series[0].t;
  const points = series.filter((p) => p.t >= start);
  return {
    points: points.length > 1 ? points : series.slice(-2),
    partial: false,
    hasUnlisted: false,
    failed: false,
  };
}

export async function getPortfolioHistory(
  holdings: { coinId: string; balance: string }[],
  range: RangeId,
  currentPrice: (coinId: string) => number | undefined,
): Promise<PortfolioSeries> {
  const spec = RANGES.find((r) => r.id === range) ?? RANGES[1];
  const days = spec.days;

  const legs = holdings
    .map((holding) => {
      const token = TOKENS.find((entry) => entry.coinId === holding.coinId);
      if (!token || !/^\d+$/.test(holding.balance)) return null;
      const units = Number(holding.balance) / 10 ** token.decimals;
      if (units === 0) return null;
      return { token, units, coingeckoId: COINGECKO_IDS[token.symbol] };
    })
    .filter((leg): leg is NonNullable<typeof leg> => leg !== null);

  if (legs.length === 0) return { points: [], partial: false, hasUnlisted: false, failed: false };

  // Biggest traded positions first, so the ones that move the curve most are
  // the ones that get real history.
  const priority = legs
    .map((leg, index) => ({ index, value: leg.units * (currentPrice(leg.token.coinId) ?? 0) }))
    .filter(({ index }) => legs[index].coingeckoId)
    .sort((a, b) => b.value - a.value)
    .slice(0, MAX_HISTORY_LEGS)
    .map(({ index }) => index);

  const fetched: (SeriesPoint[] | null)[] = legs.map(() => null);
  let attempted = 0;
  let loaded = 0;
  for (const [n, index] of priority.entries()) {
    if (n > 0) await wait(STAGGER_MS);
    attempted++;
    const series = await coinHistory(legs[index].coingeckoId!, days);
    fetched[index] = series;
    if (series) loaded++;
  }

  if (attempted > 0 && loaded === 0) {
    return { points: [], partial: true, hasUnlisted: false, failed: true };
  }

  let partial = false;
  let hasUnlisted = false;

  // Grid spans the widest window any leg returned, so legs with different
  // spacings (5-minute vs daily) combine without one truncating the rest.
  let start = Infinity;
  let end = -Infinity;
  for (const series of fetched) {
    if (!series) continue;
    start = Math.min(start, series[0].t);
    end = Math.max(end, series[series.length - 1].t);
  }
  // Trim the fetched span down to the range actually being shown.
  if (Number.isFinite(start) && Number.isFinite(spec.window)) {
    start = Math.max(start, end - spec.window);
  }
  if (!Number.isFinite(start)) {
    // Nothing has a market: a flat line at the current total is the honest answer.
    const now = Date.now();
    const total = legs.reduce((sum, leg) => sum + leg.units * (currentPrice(leg.token.coinId) ?? 0), 0);
    return {
      points: [
        { t: now - 86_400_000, v: total },
        { t: now, v: total },
      ],
      partial: false,
      hasUnlisted: true,
      failed: false,
    };
  }

  const step = (end - start) / (GRID_POINTS - 1);
  const grid = Array.from({ length: GRID_POINTS }, (_, i) => start + i * step);

  const samplers = legs.map((leg, i) => {
    const series = fetched[i];
    if (series) return sampler(series);
    // Held flat rather than dropped, so the total keeps the right magnitude
    // even though this leg contributes no shape.
    if (leg.coingeckoId) partial = true;
    else hasUnlisted = true;
    const flat = leg.token.symbol === "Hexy" ? HEXY_USD : (currentPrice(leg.token.coinId) ?? 0);
    return () => flat;
  });

  const points = grid.map((t) => ({
    t,
    v: legs.reduce((sum, leg, i) => sum + leg.units * samplers[i](t), 0),
  }));

  return { points, partial, hasUnlisted, failed: false };
}
