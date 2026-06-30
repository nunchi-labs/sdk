import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, CircleAlert, PlugZap, RefreshCw, Search, Server, Wifi, WifiOff } from "lucide-react";
import { compactHex, httpBase, wsBase } from "./utils";
import "./styles.css";

type Connection = "offline" | "connecting" | "online";

type Settings = {
  backendUrl: string;
  identity: string;
  participants: string;
};

type EventRow = {
  id: number;
  kind: string;
  view: number | null;
  height: number | null;
  digest: string;
  timestamp: number;
};

type BlockTiming = {
  height: number;
  digest: string;
  view: number | null;
  blockTimestamp: number;
  notarizedAt?: number;
  finalizedAt?: number;
  notarizationMs?: number;
  finalizationMs?: number;
  deltaMs?: number;
};

type SummaryEvent = {
  kind: string;
  view: number | null;
  height: number | null;
  digest: string | null;
  blockTimestamp: number | null;
  observedAt: number;
};

const STORAGE_KEY = "nunchi.coins.frontend.settings";
const WS_RENDER_INTERVAL_MS = 25;
const LOCAL_INDEXER_URL = "http://localhost:8080";
const APP_TITLE = import.meta.env.VITE_APP_TITLE ?? "Nunchi Coins";
const APP_SUBTITLE = import.meta.env.VITE_APP_SUBTITLE ?? "indexer console";
const DEFAULT_BACKEND_URL =
  import.meta.env.VITE_INDEXER_URL ?? (window.location.port === "5173" ? LOCAL_INDEXER_URL : window.location.origin);
const DEFAULT_SETTINGS: Settings = {
  backendUrl: DEFAULT_BACKEND_URL,
  identity: import.meta.env.VITE_INDEXER_IDENTITY ?? "",
  participants: import.meta.env.VITE_INDEXER_PARTICIPANTS ?? "1",
};

function readSettings(): Settings {
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (!saved) return DEFAULT_SETTINGS;
  try {
    const settings = { ...DEFAULT_SETTINGS, ...(JSON.parse(saved) as Partial<Settings>) };
    if (settings.backendUrl === LOCAL_INDEXER_URL) {
      return { ...settings, backendUrl: DEFAULT_SETTINGS.backendUrl };
    }
    return settings;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function App() {
  const [settings, setSettings] = useState<Settings>(() => readSettings());
  const [draft, setDraft] = useState<Settings>(() => readSettings());
  const [health, setHealth] = useState<"checking" | "ok" | "down">("checking");
  const [connection, setConnection] = useState<Connection>("offline");
  const [latest, setLatest] = useState<SummaryEvent | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [timings, setTimings] = useState<BlockTiming[]>([]);
  const [error, setError] = useState("");
  const eventId = useRef(0);
  const timingByHeight = useRef<Map<number, BlockTiming>>(new Map());
  const pendingEvents = useRef<EventRow[]>([]);
  const pendingLatest = useRef<SummaryEvent | null>(null);
  const flushTimer = useRef<number | undefined>(undefined);

  const backend = useMemo(() => httpBase(settings.backendUrl), [settings.backendUrl]);

  useEffect(() => {
    document.title = APP_TITLE;
  }, []);

  const flushSummaryUpdates = useCallback(() => {
    flushTimer.current = undefined;
    setTimings(
      Array.from(timingByHeight.current.values())
        .sort((a, b) => b.height - a.height)
        .slice(0, 64),
    );
    if (pendingEvents.current.length > 0) {
      const next = pendingEvents.current.reverse();
      pendingEvents.current = [];
      setEvents((rows) => [...next, ...rows].slice(0, 64));
    }
    if (pendingLatest.current) {
      setLatest(pendingLatest.current);
      pendingLatest.current = null;
    }
  }, []);

  const scheduleSummaryFlush = useCallback(() => {
    if (flushTimer.current !== undefined) return;
    flushTimer.current = window.setTimeout(flushSummaryUpdates, WS_RENDER_INTERVAL_MS);
  }, [flushSummaryUpdates]);

  const updateHealth = useCallback(async () => {
    setHealth("checking");
    try {
      const response = await fetch(`${backend}/health`, { cache: "no-store" });
      setHealth(response.ok ? "ok" : "down");
    } catch {
      setHealth("down");
    }
  }, [backend]);

  const updateLatest = useCallback(async () => {
    try {
      const response = await fetch(`${backend}/consensus/summary/latest`, { cache: "no-store" });
      if (!response.ok) {
        setLatest(null);
        return;
      }
      setLatest(normalizeSummary(await response.json()));
    } catch (err) {
      setError(String(err));
    }
  }, [backend]);

  useEffect(() => {
    updateHealth();
    const timer = window.setInterval(updateHealth, 5000);
    return () => window.clearInterval(timer);
  }, [updateHealth]);

  useEffect(() => {
    updateLatest();
    const timer = window.setInterval(updateLatest, 2000);
    return () => window.clearInterval(timer);
  }, [updateLatest]);

  useEffect(() => {
    let stopped = false;
    let socket: WebSocket | null = null;
    let retry: number | undefined;

    const connect = () => {
      if (stopped) return;
      setConnection("connecting");
      socket = new WebSocket(`${wsBase(backend)}/consensus/summary/ws`);

      socket.onopen = () => setConnection("online");
      socket.onerror = () => {
        setConnection("offline");
        setError("websocket connection failed");
      };
      socket.onclose = () => {
        setConnection("offline");
        if (!stopped) {
          retry = window.setTimeout(connect, 1000);
        }
      };
      socket.onmessage = (message) => {
        const displayAt = Date.now();
        const parsed = parseSummaryMessage(message.data);
        if (!parsed) return;
        const { kind, view, height, blockTimestamp } = parsed;
        const digestHex = parsed.digest ?? "";
        if ((kind === "notarization" || kind === "finalization") && height !== null && blockTimestamp !== null) {
          updateTiming(timingByHeight.current, {
            kind,
            height,
            digest: digestHex,
            view,
            blockTimestamp,
            observedAt: parsed.observedAt,
          });
        }
        eventId.current += 1;
        pendingEvents.current.push({
          id: eventId.current,
          kind,
          view,
          height,
          digest: digestHex,
          timestamp: displayAt,
        });
        if (kind === "finalization") {
          pendingLatest.current = parsed;
        }
        scheduleSummaryFlush();
      };
    };

    connect();

    return () => {
      stopped = true;
      if (retry !== undefined) {
        window.clearTimeout(retry);
      }
      if (flushTimer.current !== undefined) {
        window.clearTimeout(flushTimer.current);
        flushTimer.current = undefined;
      }
      socket?.close();
    };
  }, [backend, scheduleSummaryFlush]);

  function saveSettings() {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(draft));
    setSettings(draft);
    setEvents([]);
    timingByHeight.current.clear();
    pendingEvents.current = [];
    pendingLatest.current = null;
    setTimings([]);
    setLatest(null);
    setError("");
  }

  const latestDigest = latest?.digest ?? "";
  const latestHeight = latest?.height ?? null;
  const latestView = latest?.view ?? null;

  return (
    <main className="shell">
      <section className="topbar">
        <div>
          <h1>{APP_TITLE}</h1>
          <div className="subtle">{APP_SUBTITLE}</div>
        </div>
        <div className="statusStrip">
          <StatusPill label="API" ok={health === "ok"} busy={health === "checking"} />
          <StatusPill label="HTTP" ok={health === "ok"} busy={health === "checking"} />
          <StatusPill label="WS" ok={connection === "online"} busy={connection === "connecting"} />
        </div>
      </section>

      <section className="workspace">
        <aside className="settingsPanel">
          <div className="panelHead">
            <PlugZap size={18} />
            <span>Endpoint</span>
          </div>
          <label>
            <span>Backend</span>
            <input value={draft.backendUrl} onChange={(event) => setDraft({ ...draft, backendUrl: event.target.value })} />
          </label>
          <button className="primary" onClick={saveSettings}>
            <RefreshCw size={16} />
            Apply
          </button>
          <div className="notice ok">
            <Server size={16} />
            <span>server-verified stream</span>
          </div>
          {error && <div className="notice warn"><CircleAlert size={16} /><span>{error}</span></div>}
        </aside>

        <section className="mainPanel">
          <div className="metrics">
            <Metric label="Height" value={latestHeight?.toString() ?? "-"} />
            <Metric label="View" value={latestView?.toString() ?? "-"} />
            <Metric label="Digest" value={compactHex(latestDigest ?? undefined)} wide />
          </div>

          <LatencyTimeline timings={timings} />

          <ChainRail events={events} />

          <div className="tableHeader">
            <div className="panelHead">
              <Activity size={18} />
              <span>Consensus</span>
            </div>
            <button className="ghost" onClick={updateLatest} aria-label="Refresh latest block">
              <Search size={16} />
            </button>
          </div>
          <div className="eventTable">
            <div className="eventRow eventHead">
              <span>Kind</span>
              <span>View</span>
              <span>Height</span>
              <span>Digest</span>
              <span>Observed</span>
            </div>
            {events.length === 0 ? (
              <div className="empty">waiting for consensus events</div>
            ) : events.map((event) => (
              <div className="eventRow" key={event.id}>
                <span className={`kind ${event.kind}`}>{event.kind}</span>
                <span>{event.view ?? "-"}</span>
                <span>{event.height ?? "-"}</span>
                <span className="mono">{compactHex(event.digest)}</span>
                <span>{new Date(event.timestamp).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

function StatusPill({ label, ok, busy }: { label: string; ok: boolean; busy: boolean }) {
  return (
    <div className={`statusPill ${ok ? "ok" : busy ? "busy" : "down"}`}>
      {ok ? <Wifi size={15} /> : <WifiOff size={15} />}
      <span>{label}</span>
    </div>
  );
}

function Metric({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={`metric ${wide ? "wide" : ""}`}>
      <div className="metricLabel">{label}</div>
      <div className="metricValue">{value}</div>
    </div>
  );
}

function LatencyTimeline({ timings }: { timings: BlockTiming[] }) {
  const recent = timings.slice(0, 18);
  const notarizationMedian = median(recent.map((timing) => timing.notarizationMs));
  const finalizationMedian = median(recent.map((timing) => timing.finalizationMs));
  const deltaMedian = median(recent.map((timing) => timing.deltaMs));
  const maxLatency = Math.max(
    100,
    ...recent.flatMap((timing) => [timing.notarizationMs ?? 0, timing.finalizationMs ?? 0]),
  );

  return (
    <section className="timelinePanel">
      <div className="timelineHead">
        <div className="panelHead">
          <Activity size={18} />
          <span>Latency</span>
        </div>
        <div className="timelineStats">
          <span>lock {formatMs(notarizationMedian)}</span>
          <span>final {formatMs(finalizationMedian)}</span>
          <span>delta {formatMs(deltaMedian)}</span>
        </div>
      </div>
      <div className="timelineRows">
        {recent.length === 0 ? (
          <div className="empty">waiting for notarized and finalized blocks</div>
        ) : recent.map((timing) => (
          <TimelineRow key={timing.height} timing={timing} maxLatency={maxLatency} />
        ))}
      </div>
    </section>
  );
}

function TimelineRow({ timing, maxLatency }: { timing: BlockTiming; maxLatency: number }) {
  const notarizedPct = percent(timing.notarizationMs, maxLatency);
  const finalizedPct = percent(timing.finalizationMs, maxLatency);
  return (
    <div className="timelineRow">
      <div className="timelineBlock">
        <span>#{timing.height}</span>
        <span className="mono">{compactHex(timing.digest)}</span>
      </div>
      <div className="timelineTrack">
        {timing.finalizationMs !== undefined && (
          <div className="timelineFill finalized" style={{ width: `${Math.max(finalizedPct, 2)}%` }} />
        )}
        {timing.notarizationMs !== undefined && (
          <div className="timelineMarker notarized" style={{ left: `${notarizedPct}%` }} />
        )}
        {timing.finalizationMs !== undefined && (
          <div className="timelineMarker finalized" style={{ left: `${finalizedPct}%` }} />
        )}
      </div>
      <div className="timelineTimes">
        <span>N {formatMs(timing.notarizationMs)}</span>
        <span>F {formatMs(timing.finalizationMs)}</span>
        <span>Δ {formatMs(timing.deltaMs)}</span>
      </div>
    </div>
  );
}

function ChainRail({ events }: { events: EventRow[] }) {
  const recent = events.slice(0, 24).reverse();
  return (
    <div className="rail" aria-hidden="true">
      {recent.map((event) => (
        <div className={`railNode ${event.kind}`} key={event.id} style={{ height: `${18 + Math.min(event.height ?? event.view ?? 0, 40)}px` }} />
      ))}
    </div>
  );
}

function updateTiming(
  rows: Map<number, BlockTiming>,
  update: {
    kind: string;
    height: number;
    digest: string;
    view: number | null;
    blockTimestamp: number;
    observedAt: number;
  },
): void {
  const latency = Math.max(0, update.observedAt - update.blockTimestamp);
  const existing = rows.get(update.height);
  const next: BlockTiming = existing ? { ...existing } : {
    height: update.height,
    digest: update.digest,
    view: update.view,
    blockTimestamp: update.blockTimestamp,
  };

  next.digest = update.digest || next.digest;
  next.view = update.view ?? next.view;
  next.blockTimestamp = update.blockTimestamp;
  if (update.kind === "notarization") {
    next.notarizedAt = update.observedAt;
    next.notarizationMs = latency;
  } else if (update.kind === "finalization") {
    next.finalizedAt = update.observedAt;
    next.finalizationMs = latency;
  }
  if (next.notarizedAt !== undefined && next.finalizedAt !== undefined) {
    next.deltaMs = Math.max(0, next.finalizedAt - next.notarizedAt);
  }

  rows.set(update.height, next);
  if (rows.size > 128) {
    const stale = Array.from(rows.keys()).sort((a, b) => b - a).slice(128);
    for (const height of stale) {
      rows.delete(height);
    }
  }
}

function parseSummaryMessage(data: unknown): SummaryEvent | null {
  try {
    return normalizeSummary(JSON.parse(String(data)));
  } catch {
    return null;
  }
}

function normalizeSummary(value: unknown): SummaryEvent | null {
  if (value === null || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (typeof record.kind !== "string") return null;
  const view = optionalNumber(record.view);
  const height = optionalNumber(record.height);
  const blockTimestamp = optionalNumber(record.blockTimestamp);
  const observedAt = optionalNumber(record.observedAt);
  if (observedAt === null) return null;
  return {
    kind: record.kind,
    view,
    height,
    digest: typeof record.digest === "string" ? record.digest : null,
    blockTimestamp,
    observedAt,
  };
}

function optionalNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function median(values: Array<number | undefined>): number | undefined {
  const sorted = values
    .filter((value): value is number => value !== undefined && Number.isFinite(value))
    .sort((a, b) => a - b);
  if (sorted.length === 0) return undefined;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? Math.round((sorted[mid - 1] + sorted[mid]) / 2) : sorted[mid];
}

function percent(value: number | undefined, max: number): number {
  if (value === undefined || max <= 0) return 0;
  return Math.min(100, Math.max(0, (value / max) * 100));
}

function formatMs(value: number | undefined): string {
  return value === undefined ? "-" : `${Math.round(value)}ms`;
}

createRoot(document.getElementById("root")!).render(<App />);
