/**
 * Display registry for the coins the UI offers in pickers.
 *
 * These coin IDs are PLACEHOLDERS — they are derived from the symbol, not read
 * from a Nunchi network, so they will not match real coins on any chain. Swap
 * the ids here for the real ones per network before this is pointed at
 * anything live. The wallet always transacts on `coinId`, never the symbol.
 */
export interface Token {
  symbol: string;
  name: string;
  decimals: number;
  coinId: string;
  /** Disc colour for the placeholder logo. */
  color: string;
  /**
   * Official artwork under public/tokens, shipped with the extension so there
   * are no runtime requests to a CDN. Omitted for coins that have no official
   * mark, which fall back to the generated glyph below.
   */
  logo?: string;
  /** Generated fallback mark. See TokenLogo. */
  glyph: "hex" | "diamond" | "ring" | "bars" | "orbit" | "chevrons" | "dollar" | "blocks";
}

export const TOKENS: Token[] = [
  { symbol: "Hexy", name: "Hexy", decimals: 6, coinId: "d73f8e024f28cd20b70f8abf001b35cf11f4d0db497d184c01fbd4ee2808bf55", color: "#f2761b", glyph: "hex" },
  { symbol: "USDC", name: "USD Coin", decimals: 6, coinId: "884e5cb003045ffe42f22c52d810157ce2347e7fb2d340a400848baf0b833419", color: "#2775ca", logo: "tokens/usdc.png", glyph: "dollar" },
  { symbol: "USDT", name: "Tether", decimals: 6, coinId: "3c13f050269dbfceff1ed81e5e016d26b818bbf7fabde1a9f49179317ff68561", color: "#26a17b", logo: "tokens/usdt.png", glyph: "ring" },
  { symbol: "BTC", name: "Bitcoin", decimals: 8, coinId: "4469b06790a5de2abd885b55d96d78fcfa09c73af52fb5901af40b0e99feefd0", color: "#f7931a", logo: "tokens/btc.png", glyph: "orbit" },
  { symbol: "WBTC", name: "Wrapped Bitcoin", decimals: 8, coinId: "490af9cd233a36b740412123248708211e9f5d9572c844abff5984874fe4f694", color: "#e08b2c", logo: "tokens/wbtc.png", glyph: "blocks" },
  { symbol: "ETH", name: "Ether", decimals: 18, coinId: "cf1e4a0eda696123eacfefbdf008078d0afcdac1694e08690e9b2b486ebd56c4", color: "#627eea", logo: "tokens/eth.png", glyph: "diamond" },
  { symbol: "SOL", name: "Solana", decimals: 9, coinId: "45a00fc365452540fb3f85dcf143f94e4c954b721b0a52a0a7a3a346c0f6d6ce", color: "#8c5cf5", logo: "tokens/sol.png", glyph: "bars" },
  { symbol: "DAI", name: "Dai", decimals: 18, coinId: "75c2a45b7fafae3eb8e87ebc08538ab8603b450629f0e7ea259a7b5a80b3c31d", color: "#f5ac37", logo: "tokens/dai.png", glyph: "chevrons" },
];

export function tokenByCoinId(coinId: string): Token | undefined {
  return TOKENS.find((token) => token.coinId === coinId);
}

/** Falls back to a shortened coin id so unknown coins still render sensibly. */
export function tokenLabel(coinId: string): string {
  const token = tokenByCoinId(coinId);
  if (token) return token.symbol;
  return coinId ? `${coinId.slice(0, 6)}…${coinId.slice(-4)}` : "—";
}

/**
 * Renders a base-unit integer as a human amount, e.g. 48275000 at 6 decimals
 * becomes "48.275". Always keeps at least two decimal places so amounts read
 * as money rather than as whole counts, and never loses precision on the way:
 * the split is done on the digit string, not through a float.
 */
export function formatUnits(baseUnits: string, decimals: number, maxFractionDigits = 6): string {
  if (!/^\d+$/.test(baseUnits)) return baseUnits;

  const padded = baseUnits.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals) || "0";
  let fraction = decimals > 0 ? padded.slice(padded.length - decimals) : "";

  // Show at most `maxFractionDigits`, but never fewer than two.
  fraction = fraction.slice(0, Math.max(2, maxFractionDigits));
  fraction = fraction.replace(/0+$/, "");
  while (fraction.length < 2) fraction += "0";

  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${grouped}.${fraction}`;
}

/**
 * US dollars, always with cents. A non-zero amount below a cent renders as
 * "<$0.01" — rounding a real holding to $0.00 reads as "you have nothing".
 */
export function formatUsd(value: number): string {
  const magnitude = Math.abs(value);
  if (magnitude > 0 && magnitude < 0.005) return "<$0.01";
  return value.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

/** Base units -> USD, done in floating point only after the unit scaling. */
export function usdValue(baseUnits: string, decimals: number, unitPrice: number): number {
  if (!/^\d+$/.test(baseUnits)) return 0;
  return (Number(baseUnits) / 10 ** decimals) * unitPrice;
}

/**
 * Inverse of formatUnits: turns a typed amount like "1.5" into base units for
 * a coin's decimals. Done on the digit string so no float ever touches a
 * balance. Extra precision beyond the coin's decimals is truncated, the way a
 * wallet has to — those digits cannot be represented on chain.
 *
 * Returns null for anything that is not a plain positive decimal.
 */
export function parseUnits(value: string, decimals: number): string | null {
  const cleaned = value.replace(/,/g, "").trim();
  if (!cleaned || !/^\d*\.?\d*$/.test(cleaned) || cleaned === ".") return null;

  const [whole = "", fraction = ""] = cleaned.split(".");
  const truncated = fraction.slice(0, decimals).padEnd(decimals, "0");
  const base = `${whole || "0"}${truncated}`.replace(/^0+/, "");
  return base || "0";
}

/** Groups the integer part of a partially-typed amount, leaving the decimal alone. */
export function groupTypedAmount(raw: string): string {
  const [whole, fraction] = raw.split(".");
  const grouped = (whole || "").replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return fraction === undefined ? grouped : `${grouped}.${fraction}`;
}
