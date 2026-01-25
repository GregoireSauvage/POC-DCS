import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { AuditOut } from "../types/dto";
import { ApiError } from "../api/client";
import { listAudit } from "../api/cinema";
import { listPerfSummary } from "../api/perf";
import { PerfSummaryBadge, buildPerfSummary, type PerfSummaryMap } from "../components/PerfSummary";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Audit() {
  const auth = useAuth();
  const token = auth.token!;

  const [items, setItems] = useState<AuditOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [perfSummary, setPerfSummary] = useState<PerfSummaryMap | null>(null);

  async function refresh() {
    setError(null);
    setLoading(true);
    try {
      const data = await listAudit(token);
      setItems(data);
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
    await refreshPerf();
  }

  async function refreshPerf() {
    if (auth.role !== "admin") return;
    try {
      const rows = await listPerfSummary(token);
      setPerfSummary(buildPerfSummary(rows));
    } catch {
      setPerfSummary(null);
    }
  }

  useEffect(() => { refresh(); refreshPerf(); }, [auth.role, token]);

  return (
    <div className="container">
      <Card
        title="Audit"
        subtitle="Admin only. Shows enforcement results per request (decrypt/mask/deny)."
        right={
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <Pill kind="ok">{auth.role}</Pill>
            {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="audit.read" /> : null}
          </div>
        }
      >
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <Button onClick={refresh} disabled={loading}>Refresh</Button>
          <span className="badge">
            <span className="muted">You should see</span>
            <strong>fields_decrypted / fields_masked / fields_denied</strong>
          </span>
        </div>

        {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

        <div style={{ marginTop: 12 }} className="tablewrap">
          <table className="table">
            <thead>
              <tr>
                <th>ts</th>
                <th>request_id</th>
                <th>subject</th>
                <th>action</th>
                <th>resource</th>
                <th>outcome</th>
                <th>fields</th>
              </tr>
            </thead>
            <tbody>
              {loading && !items.length ? (
                <tr><td colSpan={7}><SkeletonRow /></td></tr>
              ) : null}
              {items.map((a, idx) => (
                <tr key={a.request_id + idx}>
                  <td className="muted">{a.ts}</td>
                  <td className="mono muted">{a.request_id}</td>
                  <td className="muted">{a.subject_role}:{(a.subject_user_id ?? "").slice(0, 8)}…</td>
                  <td>{a.action}</td>
                  <td className="muted">{a.resource_type}:{(a.resource_id ?? "").slice(0, 8)}…</td>
                  <td>
                    <Pill kind={a.outcome === "allow" ? "ok" : a.outcome === "deny" ? "danger" : "warn"}>
                      {a.outcome}
                    </Pill>
                  </td>
                  <td className="small muted">
                    <div><Mono>d</Mono>: {a.fields_decrypted.join(", ") || "—"}</div>
                    <div><Mono>m</Mono>: {a.fields_masked.join(", ") || "—"}</div>
                    <div><Mono>x</Mono>: {a.fields_denied.join(", ") || "—"}</div>
                  </td>
                </tr>
              ))}
              {!loading && !items.length ? (
                <tr><td colSpan={7} className="muted">No audit events yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
