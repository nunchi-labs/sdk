/**
 * Portfolio value over the selected range.
 *
 * Drawn as inline SVG rather than pulling in a charting library: it is one
 * polyline and a fill, and a library would cost more than the feature.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { formatUsd } from "./tokens";
import {
  RANGES,
  getPortfolioHistory,
  type PortfolioSeries,
  type RangeId,
  type SeriesPoint,
} from "./history";

const W = 320;
const H = 132;
const PAD = 6;

function buildPath(points: SeriesPoint[], min: number, max: number) {
  const span = max - min || 1;
  const x = (i: number) => (i / Math.max(1, points.length - 1)) * W;
  const y = (v: number) => PAD + (1 - (v - min) / span) * (H - PAD * 2);
  const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(2)} ${y(p.v).toFixed(2)}`);
  return {
    line: line.join(" "),
    area: `${line.join(" ")} L${W} ${H} L0 ${H} Z`,
    x,
    y,
  };
}

export function PortfolioChart({
  holdings,
  currentPrice,
  currentTotal,
  onBack,
}: {
  holdings: { coinId: string; balance: string }[];
  currentPrice: (coinId: string) => number | undefined;
  /** Known from the wallet itself, so the header stays truthful even if history fails. */
  currentTotal: number;
  onBack: () => void;
}) {
  const [range, setRange] = useState<RangeId>("1W");
  const [series, setSeries] = useState<PortfolioSeries | null>(null);
  const [loading, setLoading] = useState(true);
  const [hover, setHover] = useState<number | null>(null);
  const [reloads, setReloads] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setHover(null);
    void getPortfolioHistory(holdings, range, currentPrice).then((next) => {
      if (cancelled) return;
      setSeries(next);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [range, reloads]);

  const points = series?.points ?? [];
  const { min, max } = useMemo(() => {
    if (!points.length) return { min: 0, max: 1 };
    const values = points.map((p) => p.v);
    return { min: Math.min(...values), max: Math.max(...values) };
  }, [points]);

  const hasSeries = points.length > 1;
  const first = points[0]?.v ?? 0;
  const last = points[points.length - 1]?.v ?? 0;
  const shown = hover !== null && points[hover] ? points[hover] : null;
  // Without history the header falls back to the balance we do know, rather
  // than rendering $0.00 from an empty series.
  const value = shown ? shown.v : hasSeries ? last : currentTotal;
  const delta = hasSeries ? (shown ? shown.v : last) - first : 0;
  const percent = first === 0 ? 0 : (delta / first) * 100;
  const up = delta >= 0;

  const geometry = points.length > 1 ? buildPath(points, min, max) : null;

  function scrub(clientX: number) {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || points.length < 2) return;
    const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    setHover(Math.round(ratio * (points.length - 1)));
  }

  return (
    <>
      <div className="pageHeader">
        <button className="back" onClick={onBack} aria-label="Back">
          <ArrowLeft size={20} />
        </button>
        <h2>Balance</h2>
      </div>

      <div className="pageContent">
        <div className="chartSummary">
          <span className="chartValue">{formatUsd(value)}</span>
          {hasSeries && (
            <span className={`chartDelta ${up ? "up" : "down"}`}>
              {up ? "+" : "-"}
              {formatUsd(Math.abs(delta))}
              <span className="changePill">
                {up ? "+" : "-"}
                {Math.abs(percent).toFixed(2)}%
              </span>
            </span>
          )}
          <span className="chartWhen">
            {!hasSeries && !loading
              ? "Balance now"
              : shown
              ? new Date(shown.t).toLocaleString(undefined, {
                  month: "short",
                  day: "numeric",
                  hour: "numeric",
                  minute: "2-digit",
                })
              : RANGES.find((r) => r.id === range)?.id === "ALL"
                ? "All time"
                : `Past ${RANGES.find((r) => r.id === range)?.label}`}
          </span>
        </div>

        <div className="chartFrame">
          {loading ? (
            <div className="chartLoading">
              <div className="loadingSpinner" />
            </div>
          ) : geometry ? (
            <svg
              ref={svgRef}
              className={`chart ${up ? "up" : "down"}`}
              viewBox={`0 0 ${W} ${H}`}
              preserveAspectRatio="none"
              role="img"
              aria-label={`Balance over the past ${range}`}
              onMouseMove={(e) => scrub(e.clientX)}
              onMouseLeave={() => setHover(null)}
              onTouchStart={(e) => scrub(e.touches[0].clientX)}
              onTouchMove={(e) => scrub(e.touches[0].clientX)}
              onTouchEnd={() => setHover(null)}
            >
              <path className="chartArea" d={geometry.area} />
              <path className="chartLine" d={geometry.line} vectorEffect="non-scaling-stroke" />
              {shown && (
                <g>
                  <line
                    className="chartCursor"
                    x1={geometry.x(hover!)}
                    x2={geometry.x(hover!)}
                    y1={0}
                    y2={H}
                    vectorEffect="non-scaling-stroke"
                  />
                  <circle
                    className="chartDot"
                    cx={geometry.x(hover!)}
                    cy={geometry.y(shown.v)}
                    r={4}
                    vectorEffect="non-scaling-stroke"
                  />
                </g>
              )}
            </svg>
          ) : series?.failed ? (
            <div className="chartLoading chartFailed">
              <p className="subtitle">Could not load price history</p>
              <button className="secondary" onClick={() => setReloads((n) => n + 1)}>
                Try again
              </button>
            </div>
          ) : (
            <div className="chartLoading">
              <p className="subtitle">No history available</p>
            </div>
          )}
        </div>

        <div className="rangeTabs" role="tablist" aria-label="Chart range">
          {RANGES.map((entry) => (
            <button
              key={entry.id}
              role="tab"
              aria-selected={range === entry.id}
              className={`rangeTab ${range === entry.id ? "active" : ""}`}
              onClick={() => setRange(entry.id)}
            >
              {entry.label}
            </button>
          ))}
        </div>

        <p className="chartNote">
          Based on what you hold today priced at historical rates, so it tracks the market rather
          than past deposits or sends.
          {series?.hasUnlisted && " Hexy has no market and is held flat."}
          {series?.partial && " Some price history could not be loaded."}
        </p>
      </div>
    </>
  );
}
