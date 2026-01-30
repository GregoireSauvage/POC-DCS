import React from "react";
import type { PerfSummaryOut } from "../types/dto";

export type PerfSummaryMap = Record<
  string,
  {
    on: number | null;
    off: number | null;
    onCount: number;
    offCount: number;
    cacheLevel: number | "mixed" | null;
  }
>;

export function buildPerfSummary(rows: PerfSummaryOut[]): PerfSummaryMap {
  const map: PerfSummaryMap = {};
  for (const row of rows) {
    const key = row.action;
    if (!map[key]) {
      map[key] = { on: null, off: null, onCount: 0, offCount: 0, cacheLevel: null };
    }
    if (map[key].cacheLevel === null) {
      map[key].cacheLevel = row.cache_level;
    } else if (map[key].cacheLevel !== row.cache_level) {
      map[key].cacheLevel = "mixed";
    }
    if (row.dcs_enabled) {
      map[key].on = row.avg_total_ms;
      map[key].onCount = row.count;
    } else {
      map[key].off = row.avg_total_ms;
      map[key].offCount = row.count;
    }
  }
  return map;
}

export function PerfSummaryBadge({
  summary,
  action,
}: {
  summary: PerfSummaryMap | null;
  action: string;
}) {
  if (!summary) return null;
  const item = summary[action];
  if (!item) return null;

  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <span className="badge">
        <span className="muted">DCS on avg</span>
        <strong>{fmt(item.on)}</strong>
      </span>
      <span className="badge">
        <span className="muted">DCS off avg</span>
        <strong>{fmt(item.off)}</strong>
      </span>
      {item.cacheLevel !== null ? (
        <span className="badge">
          <span className="muted">Cache</span>
          <strong>{item.cacheLevel === "mixed" ? "mixed" : `L${item.cacheLevel}`}</strong>
        </span>
      ) : null}
    </div>
  );
}

function fmt(v: number | null) {
  if (v == null) return "—";
  return `${v.toFixed(2)} ms`;
}
