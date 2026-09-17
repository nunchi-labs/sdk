/**
 * Reference data for a coin: market cap, supply, description and links.
 *
 * One CoinGecko request per coin, cached for the session — the free tier
 * rate-limits hard, and none of this changes minute to minute. Coins with no
 * market (Hexy) have nothing to fetch, so the caller renders only what the
 * wallet itself knows.
 */
import { TOKENS } from "./tokens";
import { COINGECKO_IDS } from "./prices";

export interface TokenInfo {
  marketCapUsd?: number;
  totalSupply?: number;
  circulatingSupply?: number;
  created?: string;
  description?: string;
  links: { label: string; url: string }[];
}

const ENDPOINT = "https://api.coingecko.com/api/v3/coins";
const TTL_MS = 30 * 60_000;

const cache = new Map<string, { at: number; info: TokenInfo | null }>();

export async function getTokenInfo(coinId: string): Promise<TokenInfo | null> {
  const token = TOKENS.find((entry) => entry.coinId === coinId);
  const geckoId = token ? COINGECKO_IDS[token.symbol] : undefined;
  if (!geckoId) return null;

  const hit = cache.get(geckoId);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.info;

  try {
    const response = await fetch(
      `${ENDPOINT}/${geckoId}?localization=false&tickers=false&market_data=true` +
        `&community_data=false&developer_data=false&sparkline=false`,
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as {
      genesis_date?: string | null;
      description?: { en?: string };
      links?: { homepage?: string[]; chat_url?: string[]; twitter_screen_name?: string };
      market_data?: {
        market_cap?: { usd?: number };
        total_supply?: number | null;
        circulating_supply?: number | null;
      };
    };

    const links: TokenInfo["links"] = [];
    const homepage = body.links?.homepage?.find(Boolean);
    if (homepage) links.push({ label: "Website", url: homepage });
    const chat = body.links?.chat_url?.find(Boolean);
    if (chat) links.push({ label: "Community", url: chat });
    if (body.links?.twitter_screen_name) {
      links.push({ label: "X", url: `https://x.com/${body.links.twitter_screen_name}` });
    }

    const info: TokenInfo = {
      marketCapUsd: body.market_data?.market_cap?.usd,
      totalSupply: body.market_data?.total_supply ?? undefined,
      circulatingSupply: body.market_data?.circulating_supply ?? undefined,
      created: body.genesis_date ?? undefined,
      description: body.description?.en?.trim() || undefined,
      links,
    };
    cache.set(geckoId, { at: Date.now(), info });
    return info;
  } catch {
    cache.set(geckoId, { at: Date.now(), info: null });
    return null;
  }
}

/** 358270000 -> "$358.27M". Keeps big figures readable in a narrow table. */
export function compactUsd(value: number): string {
  const units: [number, string][] = [
    [1e12, "T"],
    [1e9, "B"],
    [1e6, "M"],
    [1e3, "K"],
  ];
  for (const [size, suffix] of units) {
    if (Math.abs(value) >= size) return `$${(value / size).toFixed(2)}${suffix}`;
  }
  return `$${value.toFixed(2)}`;
}

/** Same, without the currency prefix — for supply counts. */
export function compactNumber(value: number): string {
  return compactUsd(value).slice(1);
}
