import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import type { HallOut, SpectatorOut } from "../types/dto";
import { ApiError } from "../api/client";
import { createSpectator, listHalls, searchSpectator } from "../api/cinema";

export default function Spectators() {
  const auth = useAuth();
  const token = auth.token!;

  const [halls, setHalls] = useState<HallOut[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  }

  useEffect(() => { refreshHalls(); }, []);

  async function onCreate() {
    if (!hallId) return;
    setError(null);
    setLoading(true);
    try {
      const sp = await createSpectator(token, { hall_id: hallId, name, age, external_id: externalId });
      setSearchResults([sp]);
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
            <h1>Spectators</h1>
            <div className="muted">name + age + external_id are encrypted. Search uses HMAC lookup without plaintext in DB.</div>
            <div style={{ height: 10 }} />
            <button className="btn" disabled={loading} onClick={refreshHalls}>Refresh halls</button>
            {error ? <div className="error" style={{ marginTop: 8 }}>{error}</div> : null}

            <hr />

            <h2>Create spectator</h2>
            <div className="field">
              <label>Hall</label>
              <select value={hallId} onChange={(e) => setHallId(e.target.value)}>
                <option value="" disabled>Select hall</option>
                {halls.map((h) => <option key={h.id} value={h.id}>{h.name ?? "Hall"} ({h.id.slice(0, 8)}…)</option>)}
              </select>
            </div>
            <div className="row">
              <div className="col">
                <div className="field">
                  <label>Name (PII)</label>
                  <input value={name} onChange={(e) => setName(e.target.value)} />
                </div>
              </div>
              <div className="col">
                <div className="field">
                  <label>Age (sensitive)</label>
                  <input type="number" value={age} onChange={(e) => setAge(Number(e.target.value))} />
                </div>
              </div>
            </div>
            <div className="field">
              <label>Ticket ID (PII, searchable via HMAC)</label>
              <input value={externalId} onChange={(e) => setExternalId(e.target.value)} />
            </div>
            <button className="btn primary" disabled={loading || !hallId} onClick={onCreate}>Create</button>

            <div style={{ marginTop: 10 }} className="muted">
              Expected: admin sees all; agent sees age but masked name/ticket; developer sees masked values.
            </div>
          </div>
        </div>

        <div className="col">
          <div className="card">
            <h1>Search by ticket ID</h1>
            <div className="field">
              <label>Ticket ID (exact match)</label>
              <input value={searchExternalId} onChange={(e) => setSearchExternalId(e.target.value)} />
            </div>
            <button className="btn primary" disabled={loading} onClick={onSearch}>Search</button>

            <table className="table" style={{ marginTop: 10 }}>
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
                {searchResults.map((s) => (
                  <tr key={s.id}>
                    <td className="muted">{s.id}</td>
                    <td className="muted">{s.hall_id}</td>
                    <td>{s.name ?? "—"}</td>
                    <td>{s.age === null ? "—" : String(s.age)}</td>
                    <td>{s.external_id ?? "—"}</td>
                  </tr>
                ))}
                {!searchResults.length ? <tr><td colSpan={5} className="muted">No results.</td></tr> : null}
              </tbody>
            </table>
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
