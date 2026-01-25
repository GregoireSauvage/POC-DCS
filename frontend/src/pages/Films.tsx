import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { FilmOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createFilm, listFilms, updateFilmTime } from "../api/cinema";
import { listPerfSummary } from "../api/perf";
import { PerfSummaryBadge, buildPerfSummary, type PerfSummaryMap } from "../components/PerfSummary";
import { Alert, Button, Card, Mono, Pill, SkeletonRow } from "../components/ui";

export default function Films() {
  const auth = useAuth();
  const token = auth.token!;

  const [items, setItems] = useState<FilmOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [perfSummary, setPerfSummary] = useState<PerfSummaryMap | null>(null);

  const [title, setTitle] = useState("Interstellar");
  const [timeElapsed, setTimeElapsed] = useState<number>(0);

  const [editFilmId, setEditFilmId] = useState<string>("");
  const [editTime, setEditTime] = useState<number>(120);

  async function refresh() {
    setError(null);
    setLoading(true);
    try {
      const data = await listFilms(token);
      setItems(data);
      if (!editFilmId && data.length) setEditFilmId(data[0].id);
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
    setError(null);
    setLoading(true);
    try {
      await createFilm(token, { title, time_elapsed: timeElapsed });
      await refresh();
      await refreshPerf();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  async function onUpdate() {
    if (!editFilmId) return;
    setError(null);
    setLoading(true);
    try {
      await updateFilmTime(token, editFilmId, editTime);
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
          title="Films"
          subtitle="time_elapsed is stored encrypted. PDP decides whether to decrypt or mask it."
          right={
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Pill>{auth.role}</Pill>
              {auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.read" /> : null}
            </div>
          }
        >
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Button onClick={refresh} disabled={loading}>Refresh</Button>
            <span className="badge">
              <span className="muted">Expected</span>
              <strong>admin/agent</strong> decrypt, <strong>developer</strong> masked
            </span>
          </div>

          {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}

          <div style={{ marginTop: 12 }} className="tablewrap">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>time_elapsed</th>
                </tr>
              </thead>
              <tbody>
                {loading && !items.length ? (
                  <tr><td colSpan={3}><SkeletonRow /></td></tr>
                ) : null}
                {items.map((f) => (
                  <tr key={f.id}>
                    <td className="mono muted">{f.id}</td>
                    <td>{f.title}</td>
                    <td><Mono>{String(f.time_elapsed)}</Mono></td>
                  </tr>
                ))}
                {!loading && !items.length ? (
                  <tr><td colSpan={3} className="muted">No films yet.</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="grid" style={{ gap: 14 }}>
          <Card
            title="Create film"
            subtitle="Write is allowed for agent/admin. Developer should get 403."
            right={auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.create" /> : null}
          >
            <div className="field">
              <label>Title</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="field">
              <label>Initial time_elapsed (seconds)</label>
              <input type="number" value={timeElapsed} onChange={(e) => setTimeElapsed(Number(e.target.value))} />
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <Button variant="primary" disabled={loading} onClick={onCreate}>Create</Button>
              <Button variant="ghost" disabled={loading} onClick={() => { setTitle("Interstellar"); setTimeElapsed(0); }}>Reset</Button>
            </div>
          </Card>

          <Card
            title="Update time_elapsed"
            subtitle="Demonstrates frequent writes + read-time enforcement."
            right={auth.role === "admin" ? <PerfSummaryBadge summary={perfSummary} action="film.update_time" /> : null}
          >
            <div className="field">
              <label>Film</label>
              <select value={editFilmId} onChange={(e) => setEditFilmId(e.target.value)}>
                <option value="" disabled>Select film</option>
                {items.map((f) => <option key={f.id} value={f.id}>{f.title} ({f.id.slice(0, 8)}…)</option>)}
              </select>
            </div>
            <div className="field">
              <label>New time_elapsed (seconds)</label>
              <input type="number" value={editTime} onChange={(e) => setEditTime(Number(e.target.value))} />
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <Button variant="primary" disabled={loading || !editFilmId} onClick={onUpdate}>Update</Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
