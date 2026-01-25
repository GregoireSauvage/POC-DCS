import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { HallOut, SpectatorOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createSpectator, listHalls, searchSpectator } from "../api/cinema";
import { listPerfSummary } from "../api/perf";
import { PerfSummaryBadge, buildPerfSummary, type PerfSummaryMap } from "../components/PerfSummary";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Spectators() {
  const auth = useAuth();
  const token = auth.token!;

  const [halls, setHalls] = useState<HallOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [perfSummary, setPerfSummary] = useState<PerfSummaryMap | null>(null);

  const [hallId, setHallId] = useState<string>("");
  const [name, setName] = useState("Alice");
  const [age, setAge] = useState<number>(27);
  const [externalId, setExternalId] = useState("TICKET-001");

  const [searchExternalId, setSearchExternalId] = useState("TICKET-001");
  const [searchResults, setSearchResults] = useState<SpectatorOut[]>([]);

  async function refreshHalls() {
    setError(null);
    setLoading(true);
    try {
      const data = await listHalls(token);
      setHalls(data);
      if (!hallId && data.length) setHallId(data[0].id);
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

  useEffect(() => { refreshHalls(); refreshPerf(); }, [auth.role, token]);

  async function onCreate() {
    if (!hallId) return;
    setError(null);
    setLoading(true);
    try {
      const sp = await createSpectator(token, { hall_id: hallId, name, age, external_id: externalId });
      setSearchResults([sp]);
      await refreshPerf();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  async function onSearch() {
    setError(null);
    setLoading(true);
    try {
      const res = await searchSpectator(token, searchExternalId);
      setSearchResults(res);
      await refreshPerf();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="grid cols-2">
        <Card
          title="Spectators"
          subtitle="Encrypted fields: name / age / ticket. Search uses HMAC lookup (exact match)."
          right={
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Pill>{auth.role}</Pill>
              {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="spectator.create" /> : null}
            </div>
          }
        >
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Button onClick={refreshHalls} disabled={loading}>Refresh halls</Button>
            <span className="badge">
              <span className="muted">Expected</span>
              <strong>agent</strong> age decrypted, PII masked
            </span>
          </div>

          {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

          <hr />

          <h2>Create spectator</h2>
          <div className="field">
            <label>Hall</label>
            <select value={hallId} onChange={(e) => setHallId(e.target.value)}>
              <option value="" disabled>Select hall</option>
              {halls.map((h) => <option key={h.id} value={h.id}>{h.name ?? "Hall"} ({h.id.slice(0, 8)}…)</option>)}
            </select>
          </div>
          <div className="grid cols-2">
            <div className="field">
              <label>Name (PII)</label>
              <input value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label>Age (SENSITIVE)</label>
              <input type="number" value={age} onChange={(e) => setAge(Number(e.target.value))} />
            </div>
          </div>
          <div className="field">
            <label>Ticket ID (PII, searchable)</label>
            <input value={externalId} onChange={(e) => setExternalId(e.target.value)} />
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <Button variant="primary" disabled={loading || !hallId} onClick={onCreate}>Create</Button>
          </div>
        </Card>

        <Card
          title="Search by ticket ID"
          subtitle="Exact match on HMAC(ticket). Plaintext ticket never stored in DB index."
          right={auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="search.spectator" /> : null}
        >
          <div className="field">
            <label>Ticket ID</label>
            <input value={searchExternalId} onChange={(e) => setSearchExternalId(e.target.value)} />
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <Button variant="primary" disabled={loading} onClick={onSearch}>Search</Button>
          </div>

          <div style={{ marginTop: 12 }} className="tablewrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Hall</th>
                  <th>Name</th>
                  <th>Age</th>
                  <th>Ticket</th>
                </tr>
              </thead>
              <tbody>
                {loading && !searchResults.length ? (
                  <tr><td colSpan={5}><SkeletonRow /></td></tr>
                ) : null}
                {searchResults.map((s) => (
                  <tr key={String(s.id)}>
                    <td className="mono muted">{String(s.id)}</td>
                    <td className="mono muted">{s.hall_id}</td>
                    <td>{s.name ?? "—"}</td>
                    <td><Mono>{s.age === null ? "—" : String(s.age)}</Mono></td>
                    <td>{s.external_id ?? "—"}</td>
                  </tr>
                ))}
                {!loading && !searchResults.length ? (
                  <tr><td colSpan={5} className="muted">No results.</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
