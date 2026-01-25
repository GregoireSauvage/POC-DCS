import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { FilmOut, HallOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createHall, listFilms, listHalls } from "../api/cinema";
import { listPerfSummary } from "../api/perf";
import { PerfSummaryBadge, buildPerfSummary, type PerfSummaryMap } from "../components/PerfSummary";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Halls() {
  const auth = useAuth();
  const token = auth.token!;

  const [films, setFilms] = useState<FilmOut[]>([]);
  const [halls, setHalls] = useState<HallOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [perfSummary, setPerfSummary] = useState<PerfSummaryMap | null>(null);

  const [name, setName] = useState("Hall A");
  const [currentFilmId, setCurrentFilmId] = useState<string>("");

  async function refresh() {
    setError(null);
    setLoading(true);
    try {
      const [f, h] = await Promise.all([listFilms(token), listHalls(token)]);
      setFilms(f);
      setHalls(h);
      if (!currentFilmId && f.length) setCurrentFilmId(f[0].id);
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

  async function onCreate() {
    if (!currentFilmId) return;
    setError(null);
    setLoading(true);
    try {
      await createHall(token, { name, current_film_id: currentFilmId, owner_user_id: auth.userId! });
      await refresh();
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
          title="Halls"
          subtitle="Shows metadata + spectator_count (computed in SQL). IDs may be masked depending on role."
          right={
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Pill>{auth.role}</Pill>
              {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="hall.read" /> : null}
            </div>
          }
        >
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Button onClick={refresh} disabled={loading}>Refresh</Button>
            <span className="badge">
              <span className="muted">Expected</span>
              <strong>developer</strong> masked IDs
            </span>
          </div>

          {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

          <div style={{ marginTop: 12 }} className="tablewrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Current film</th>
                  <th>Owner</th>
                  <th>Spectators</th>
                </tr>
              </thead>
              <tbody>
                {loading && !halls.length ? (
                  <tr><td colSpan={5}><SkeletonRow /></td></tr>
                ) : null}
                {halls.map((h) => (
                  <tr key={h.id}>
                    <td className="mono muted">{h.id}</td>
                    <td>{h.name ?? "—"}</td>
                    <td className="mono muted">{h.current_film_id ?? "—"}</td>
                    <td className="mono muted">{h.owner_user_id ?? "—"}</td>
                    <td><Mono>{String(h.spectator_count ?? 0)}</Mono></td>
                  </tr>
                ))}
                {!loading && !halls.length ? (
                  <tr><td colSpan={5} className="muted">No halls yet.</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>

        <Card
          title="Create hall"
          subtitle="Only agent/admin can create. Owner is the current user in this PoC."
          right={
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Pill kind={auth.role === "admin" ? "ok" : auth.role === "agent" ? "warn" : "danger"}>{auth.role}</Pill>
              {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="hall.create" /> : null}
            </div>
          }
        >
          <div className="field">
            <label>Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label>Current film</label>
            <select value={currentFilmId} onChange={(e) => setCurrentFilmId(e.target.value)}>
              <option value="" disabled>Select film</option>
              {films.map((f) => <option key={f.id} value={f.id}>{f.title} ({f.id.slice(0, 8)}…)</option>)}
            </select>
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <Button variant="primary" disabled={loading || !currentFilmId} onClick={onCreate}>Create</Button>
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
