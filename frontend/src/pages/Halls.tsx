import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { FilmOut, HallOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createHall, listFilms, listHalls } from "../api/cinema";

export default function Halls() {
  const auth = useAuth();
  const token = auth.token!;

  const [films, setFilms] = useState<FilmOut[]>([]);
  const [halls, setHalls] = useState<HallOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  }

  useEffect(() => { refresh(); }, []);

  async function onCreate() {
    if (!currentFilmId) return;
    setError(null);
    setLoading(true);
    try {
      await createHall(token, { name, current_film_id: currentFilmId, owner_user_id: auth.userId! });
      await refresh();
    } catch (e) {
      setError(toMsg(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="row">
        <div className="col">
          <div className="card">
            <h1>Halls</h1>
            <div className="muted">Hall metadata is INTERNAL. Spectator count comes from SQL (no decrypt).</div>
            <div style={{ height: 10 }} />
            <button className="btn" disabled={loading} onClick={refresh}>Refresh</button>
            {error ? <div className="error" style={{ marginTop: 8 }}>{error}</div> : null}

            <table className="table" style={{ marginTop: 10 }}>
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
                {halls.map((h) => (
                  <tr key={h.id}>
                    <td className="muted">{h.id}</td>
                    <td>{h.name ?? "—"}</td>
                    <td className="muted">{h.current_film_id ?? "—"}</td>
                    <td className="muted">{h.owner_user_id ?? "—"}</td>
                    <td>{h.spectator_count ?? 0}</td>
                  </tr>
                ))}
                {!halls.length ? <tr><td colSpan={5} className="muted">No halls yet.</td></tr> : null}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col">
          <div className="card">
            <h1>Create hall</h1>
            <div className="muted">Only agent/admin can create. Owner is set to current user in this PoC.</div>
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
            <button className="btn primary" disabled={loading || !currentFilmId} onClick={onCreate}>Create</button>
            <div style={{ marginTop: 10 }} className="muted">
              Expected: developer can list but sees masked IDs; agent/admin can create.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function toMsg(e: unknown): string {
  if (e instanceof ApiError) return typeof e.body === "string" ? e.body : JSON.stringify(e.body);
  return String(e);
}
