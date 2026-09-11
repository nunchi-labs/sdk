/**
 * Asset page: price, chart, your position, reference data, and recent activity
 * for one coin.
 *
 * Everything shown comes from somewhere real. Coins with no market (Hexy) have
 * no price history, market cap or description to show, so those sections are
 * omitted rather than filled with placeholders.
 */
import { useEffect, useState } from "react";
import { ArrowLeft, Copy, CreditCard, Repeat, Send as SendIcon } from "lucide-react";
import { TokenLogo } from "./TokenLogo";
import { ValueChart, useScrub } from "./ValueChart";
import { getTokenHistory, type PortfolioSeries, type RangeId } from "./history";
import { getTokenInfo, compactUsd, compactNumber, type TokenInfo } from "./tokenInfo";
import { coinIdChange, coinIdPrice, hasMarket, type PriceSnapshot } from "./prices";
import { formatUnits, formatUsd, tokenByCoinId, tokenLabel } from "./tokens";
import { MASK } from "./privacy";
import type { Settings, SubmittedTx } from "./types";

const CHART_RANGES: RangeId[] = ["1H", "1D", "1W", "1M", "1Y", "ALL"];

export function AssetDetail({
  coinId,
  balance,
  prices,
  settings,
  activity,
  hidden,
  onBack,
  onSend,
  onSwap,
  onReceive,
  onBuy,
}: {
  coinId: string;
  balance: string | null;
  prices: PriceSnapshot | null;
  settings: Settings | null;
  activity: SubmittedTx[];
  hidden?: boolean;
  onBack: () => void;
  onSend: (coinId: string) => void;
  onSwap: () => void;
  onReceive: () => void;
  onBuy: () => void;
}) {
  const [range, setRange] = useState<RangeId>("1D");
  const [series, setSeries] = useState<PortfolioSeries | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloads, setReloads] = useState(0);
  const [info, setInfo] = useState<TokenInfo | null>(null);
  const [expanded, setExpanded] = useState(false);

  const token = tokenByCoinId(coinId);
  const price = coinIdPrice(prices, coinId);
  // A reference price is not a market price: without one there is no history
  // to chart, so the chart and its range tabs are left out entirely.
  const traded = hasMarket(coinId);
  const percent = coinIdChange(prices, coinId);
  const { hover, setHover, ref, scrub } = useScrub(series?.points ?? []);

  useEffect(() => {
    if (!traded) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setHover(null);
    void getTokenHistory(coinId, range).then((next) => {
      if (!cancelled) {
        setSeries(next);
        setLoading(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [coinId, range, reloads, traded]);

  useEffect(() => {
    void getTokenInfo(coinId).then(setInfo);
  }, [coinId]);

  const points = series?.points ?? [];
  const shown = hover !== null && points[hover] ? points[hover] : null;
  const first = points[0]?.v ?? 0;
  const spot = shown ? shown.v : (points[points.length - 1]?.v ?? price ?? 0);
  const delta = points.length > 1 ? spot - first : 0;
  const rangePercent = first === 0 ? (percent ?? 0) : (delta / first) * 100;
  const up = delta >= 0;

  const units = token && balance && /^\d+$/.test(balance) ? Number(balance) / 10 ** token.decimals : 0;
  const positionUsd = price ? units * price : undefined;
  const mine = activity.filter((tx) => tx.coin === coinId || tx.toCoin === coinId).slice(0, 3);

  const rows: [string, string][] = [
    ["Name", token?.name ?? "Unknown"],
    ["Symbol", tokenLabel(coinId)],
    ["Network", settings?.network || settings?.chainId || "—"],
  ];
  if (info?.marketCapUsd) rows.push(["Market cap", compactUsd(info.marketCapUsd)]);
  if (info?.totalSupply) rows.push(["Total supply", compactNumber(info.totalSupply)]);
  if (info?.circulatingSupply) rows.push(["Circulating supply", compactNumber(info.circulatingSupply)]);
  if (info?.created) {
    rows.push([
      "Created",
      new Date(info.created).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      }),
    ]);
  }

  return (
    <>
      <div className="pageHeader">
        <button className="back" onClick={onBack} aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <h2 className="assetTitle">
          <TokenLogo coinId={coinId} size={22} />
          {token?.name ?? tokenLabel(coinId)}
        </h2>
      </div>

      <div className="pageContent">
        {price ? (
          <div className="assetPriceHero">
            <span className="assetPrice">{formatUsd(spot)}</span>
            {points.length > 1 && (
              <span className={`chartDelta ${up ? "up" : "down"}`}>
                {up ? "+" : "-"}
                {formatUsd(Math.abs(delta))}
                <span className="changePill">
                  {up ? "+" : "-"}
                  {Math.abs(rangePercent).toFixed(2)}%
                </span>
              </span>
            )}
            <span className="chartWhen">
              {shown
                ? new Date(shown.t).toLocaleString(undefined, {
                    month: "short",
                    day: "numeric",
                    hour: "numeric",
                    minute: "2-digit",
                  })
                : traded
                  ? "\u00a0"
                  : "Reference price \u2014 no public market"}
            </span>
          </div>
        ) : (
          <div className="assetPriceHero">
            <span className="assetPrice">{tokenLabel(coinId)}</span>
            <span className="chartWhen">No market price</span>
          </div>
        )}

        {traded && (
          <ValueChart
            series={series}
            loading={loading}
            range={range}
            onRange={setRange}
            hover={hover}
            setHover={setHover}
            svgRef={ref}
            scrub={scrub}
            onRetry={() => setReloads((n) => n + 1)}
            ranges={CHART_RANGES}
          />
        )}

        <div className="quickActions assetActions">
          <button className="actionTile" onClick={() => onSend(coinId)}>
            <SendIcon size={20} />
            <span>Send</span>
          </button>
          <button className="actionTile" onClick={onSwap}>
            <Repeat size={20} />
            <span>Swap</span>
          </button>
          <button className="actionTile" onClick={onReceive}>
            <Copy size={20} />
            <span>Receive</span>
          </button>
          <button className="actionTile" onClick={onBuy}>
            <CreditCard size={20} />
            <span>Buy</span>
          </button>
        </div>

        <div className="assetsHeading">Position</div>
        <div className="positionGrid">
          <div className="positionCard">
            <span className="positionLabel">Value</span>
            <span className="positionValue">
              {hidden ? MASK : positionUsd !== undefined ? formatUsd(positionUsd) : "—"}
            </span>
          </div>
          <div className="positionCard">
            <span className="positionLabel">Balance</span>
            <span className="positionValue">
              {hidden
                ? MASK
                : `${token ? formatUnits(balance ?? "0", token.decimals, Math.min(token.decimals, 8)) : (balance ?? "0")} ${tokenLabel(coinId)}`}
            </span>
          </div>
        </div>

        <div className="assetsHeading">Info</div>
        <div className="infoTable">
          {rows.map(([label, value]) => (
            <div className="infoRow" key={label}>
              <span>{label}</span>
              <span className="infoValue">{value}</span>
            </div>
          ))}
        </div>

        {info?.description && (
          <>
            <div className="assetsHeading">About</div>
            <p className={`assetAbout ${expanded ? "open" : ""}`}>{info.description}</p>
            <button className="linkButton" onClick={() => setExpanded((v) => !v)}>
              {expanded ? "Show less" : "Show more"}
            </button>
          </>
        )}

        {info?.links.length ? (
          <div className="linkChips">
            {info.links.map((link) => (
              <a key={link.url} className="linkChip" href={link.url} target="_blank" rel="noreferrer noopener">
                {link.label}
              </a>
            ))}
          </div>
        ) : null}

        {mine.length > 0 && (
          <>
            <div className="assetsHeading">Activity</div>
            <div className="activityList">
              {mine.map((tx) => (
                <div key={tx.hash} className="activityItem static">
                  <TokenLogo coinId={tx.coin} size={30} />
                  <div className="activityDetails">
                    <div className="activityTitle">{tx.kind === "swap" ? "Swap" : "Sent"}</div>
                    <div className="activitySub">
                      {new Date(tx.timestamp).toLocaleDateString(undefined, {
                        month: "short",
                        day: "numeric",
                      })}
                    </div>
                  </div>
                  <div className="activityAmount">
                    {hidden
                      ? MASK
                      : `-${token ? formatUnits(tx.amount, token.decimals, Math.min(token.decimals, 8)) : tx.amount}`}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </>
  );
}
