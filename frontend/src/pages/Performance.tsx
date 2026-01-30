import React, { useEffect, useMemo, useState } from "react";
import { useAuth } from "../state/auth";
import type { PerfOut } from "../types/dto";
import { listPerf } from "../api/perf";
import { ApiError } from "../api/client";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Performance() {
  const auth = useAuth();
  const token = auth.token!;

  const [rows, setRows] = useState<PerfOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    setLoading(true);
    try {
      const data = await listPerf(token, { limit: 200 });
      setRows(data);
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (auth.role === "admin") refresh();
  }, [auth.role]);

  const summary = useMemo(() => summarize(rows), [rows]);
  const cacheLevel = useMemo(() => summarizeCacheLevel(rows), [rows]);

  if (auth.role !== "admin") {
    return (
      <div className="container">
        <Alert kind="error">Admin only.</Alert>
      </div>
    );
  }

  return (
    <div className="container">
      <Card
        title="Performance"
        subtitle="Compare DCS on/off: total + PIP/PDP/KMS/DB timings (ms)."
        right={<Pill>{auth.role}</Pill>}
      >
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <Button onClick={refresh} disabled={loading}>Refresh</Button>
          <span className="badge">
            <span className="muted">DCS on avg</span>
            <strong>{summary.onAvg} ms</strong>
          </span>
          <span className="badge">
            <span className="muted">DCS off avg</span>
            <strong>{summary.offAvg} ms</strong>
          </span>
          {cacheLevel ? (
            <span className="badge">
              <span className="muted">Cache</span>
              <strong>{cacheLevel}</strong>
            </span>
          ) : null}
        </div>

        {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

        <div style={{ marginTop: 12 }} className="tablewrap">
          <table className="table">
            <thead>
              <tr>
                <th>TS</th>
                <th>Action</th>
                <th>Role</th>
                <th>DCS</th>
                <th>Cache</th>
                <th>Total</th>
                <th>PIP</th>
                <th>PDP</th>
                <th>KMS</th>
                <th>DB</th>
                <th>Request</th>
              </tr>
            </thead>
            <tbody>
              {loading && !rows.length ? (
                <tr><td colSpan={11}><SkeletonRow /></td></tr>
              ) : null}
              {rows.map((r) => (
                <tr key={`${r.request_id}-${r.action}-${r.ts}`}>
                  <td className="mono muted">{fmtTs(r.ts)}</td>
                  <td>{r.action}</td>
                  <td>{r.subject_role ?? "—"}</td>
                  <td>
                    <Pill kind={r.dcs_enabled ? "ok" : "danger"}>
                      {r.dcs_enabled ? "on" : "off"}
                    </Pill>
                  </td>
                  <td className="mono muted">L{r.cache_level}</td>
                  <td><Mono>{fmtMs(r.total_ms)}</Mono></td>
                  <td className="mono muted">{fmtMs(r.pip_ms)}</td>
                  <td className="mono muted">{fmtMs(r.pdp_ms)}</td>
                  <td className="mono muted">{fmtMs(r.kms_ms)}</td>
                  <td className="mono muted">{fmtMs(r.db_ms)}</td>
                  <td className="mono muted">{r.request_id.slice(0, 8)}…</td>
                </tr>
              ))}
              {!loading && !rows.length ? (
                <tr><td colSpan={11} className="muted">No perf logs yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function fmtMs(v: number | null | undefined) {
  if (v == null) return "—";
  return v.toFixed(2);
}

function fmtTs(ts: string) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString();
  } catch {
    return ts;
  }
}

function summarize(rows: PerfOut[]) {
  const onVals = rows.filter((r) => r.dcs_enabled && typeof r.total_ms === "number").map((r) => r.total_ms as number);
  const offVals = rows.filter((r) => !r.dcs_enabled && typeof r.total_ms === "number").map((r) => r.total_ms as number);
  return {
    onAvg: avg(onVals),
    offAvg: avg(offVals),
  };
}

function summarizeCacheLevel(rows: PerfOut[]) {
  if (!rows.length) return "";
  const levels = new Set(rows.map((r) => r.cache_level));
  if (levels.size === 1) return `L${[...levels][0]}`;
  return "mixed";
}

function avg(values: number[]) {
  if (!values.length) return "—";
  const sum = values.reduce((a, b) => a + b, 0);
  return (sum / values.length).toFixed(2);
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
