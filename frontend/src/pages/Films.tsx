import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { FilmOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createFilm, listFilms, updateFilmTime } from "../api/cinema";

export default function Films() {
  const auth = useAuth();
  const token = auth.token!;

  const [items, setItems] = useState<FilmOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  }

  useEffect(() => { refresh(); }, []);

  async function onCreate() {
    setError(null);
    setLoading(true);
    try {
      await createFilm(token, { title, time_elapsed: timeElapsed });
      await refresh();
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
            <h1>Films</h1>
            <div className="muted">time_elapsed is stored encrypted. PDP decides decrypt/mask per role.</div>
            <div style={{ height: 10 }} />
            <button className="btn" disabled={loading} onClick={refresh}>Refresh</button>
            {error ? <div className="error" style={{ marginTop: 8 }}>{error}</div> : null}

            <table className="table" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Time elapsed</th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => (
                  <tr key={f.id}>
                    <td className="muted">{f.id}</td>
                    <td>{f.title}</td>
                    <td>{String(f.time_elapsed)}</td>
                  </tr>
                ))}
                {!items.length ? <tr><td colSpan={3} className="muted">No films yet.</td></tr> : null}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col">
          <div className="card">
            <h1>Create film</h1>
            <div className="field">
              <label>Title</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="field">
              <label>Initial time_elapsed (seconds)</label>
              <input type="number" value={timeElapsed} onChange={(e) => setTimeElapsed(Number(e.target.value))} />
            </div>
            <button className="btn primary" disabled={loading} onClick={onCreate}>Create</button>

            <hr />

            <h1>Update time_elapsed</h1>
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
            <button className="btn primary" disabled={loading || !editFilmId} onClick={onUpdate}>Update</button>

            <div style={{ marginTop: 10 }} className="muted">
              Expected: admin sees number; agent sees number; developer sees masked value.
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
