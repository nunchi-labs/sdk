/**
 * The chart body: line, area fill, scrub cursor and range tabs.
 *
 * Shared by the portfolio chart and the per-asset page so the two cannot drift.
 * The caller owns fetching; this only draws what it is handed.
 */
import { useMemo, useRef, useState } from "react";
import { RANGES, type PortfolioSeries, type RangeId, type SeriesPoint } from "./history";

const W = 320;
const H = 132;
const PAD = 6;

export function useScrub(points: SeriesPoint[]) {
  const [hover, setHover] = useState<number | null>(null);
  const ref = useRef<SVGSVGElement>(null);
  function scrub(clientX: number) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || points.length < 2) return;
    const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    setHover(Math.round(ratio * (points.length - 1)));
  }
  return { hover, setHover, ref, scrub };
}

export function ValueChart({
  series,
  loading,
  range,
  onRange,
  hover,
  setHover,
  svgRef,
  scrub,
  onRetry,
  ranges = RANGES.map((r) => r.id),
}: {
  series: PortfolioSeries | null;
  loading: boolean;
  range: RangeId;
  onRange: (range: RangeId) => void;
  hover: number | null;
  setHover: (index: number | null) => void;
  svgRef: React.RefObject<SVGSVGElement>;
  scrub: (clientX: number) => void;
  onRetry?: () => void;
  ranges?: RangeId[];
}) {
  const points = series?.points ?? [];
  const { min, max } = useMemo(() => {
    if (!points.length) return { min: 0, max: 1 };
    const values = points.map((p) => p.v);
    return { min: Math.min(...values), max: Math.max(...values) };
  }, [points]);

  const first = points[0]?.v ?? 0;
  const last = points[points.length - 1]?.v ?? 0;
  const up = last - first >= 0;
  const shown = hover !== null && points[hover] ? points[hover] : null;

  const geometry = useMemo(() => {
    if (points.length < 2) return null;
    const span = max - min || 1;
    const x = (i: number) => (i / (points.length - 1)) * W;
    const y = (v: number) => PAD + (1 - (v - min) / span) * (H - PAD * 2);
    const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(2)} ${y(p.v).toFixed(2)}`);
    return { line: line.join(" "), area: `${line.join(" ")} L${W} ${H} L0 ${H} Z`, x, y };
  }, [points, min, max]);

  const tabs = RANGES.filter((entry) => ranges.includes(entry.id));

  return (
    <>
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
            aria-label={`Value over the past ${range}`}
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
            {onRetry && (
              <button className="secondary" onClick={onRetry}>
                Try again
              </button>
            )}
          </div>
        ) : (
          <div className="chartLoading">
            <p className="subtitle">No history available</p>
          </div>
        )}
      </div>

      <div
        className="rangeTabs"
        role="tablist"
        aria-label="Chart range"
        style={{ "--range-count": tabs.length } as React.CSSProperties}
      >
        {tabs.map((entry) => (
          <button
            key={entry.id}
            role="tab"
            aria-selected={range === entry.id}
            className={`rangeTab ${range === entry.id ? "active" : ""}`}
            onClick={() => onRange(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </div>
    </>
  );
}
