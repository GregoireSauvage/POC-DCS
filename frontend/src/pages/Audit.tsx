import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { AuditOut } from "../types/dto";
import { ApiError } from "../api/client";
import { listAudit } from "../api/cinema";

export default function Audit() {
  const auth = useAuth();
  const token = auth.token!;

  const [items, setItems] = useState<AuditOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  }

  useEffect(() => { refresh(); }, []);

  return (
    <div className="container">
      <div className="card">
        <h1>Audit</h1>
        <div className="muted">Admin only. Shows decrypt/mask/deny per request.</div>
        <div style={{ height: 10 }} />
        <button className="btn" disabled={loading} onClick={refresh}>Refresh</button>
        {error ? <div className="error" style={{ marginTop: 8 }}>{error}</div> : null}

        <table className="table" style={{ marginTop: 10 }}>
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
            {items.map((a, idx) => (
              <tr key={a.request_id + idx}>
                <td className="muted">{a.ts}</td>
                <td className="muted">{a.request_id}</td>
                <td className="muted">{a.subject_role}:{(a.subject_user_id ?? "").slice(0, 8)}…</td>
                <td>{a.action}</td>
                <td className="muted">{a.resource_type}:{(a.resource_id ?? "").slice(0, 8)}…</td>
                <td>{a.outcome}</td>
                <td className="muted">
                  d:{a.fields_decrypted.join(",") || "—"}<br/>
                  m:{a.fields_masked.join(",") || "—"}<br/>
                  x:{a.fields_denied.join(",") || "—"}
                </td>
              </tr>
            ))}
            {!items.length ? <tr><td colSpan={7} className="muted">No audit events yet.</td></tr> : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
