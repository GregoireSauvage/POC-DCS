import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { login } from "../api/auth";
import { ApiError } from "../api/client";
import { useAuth } from "../state/auth";

type Preset = { label: string; username: string; password: string; note: string };

const presets: Preset[] = [
  { label: "Developer", username: "dev", password: "dev", note: "masked view (no decrypt)" },
  { label: "Agent", username: "agent", password: "agent", note: "decrypt sensitive, mask PII" },
  { label: "Admin", username: "admin", password: "admin", note: "full access" }
];

export default function LoginAs() {
  const auth = useAuth();
  const nav = useNavigate();
  const loc = useLocation() as any;
  const from = loc?.state?.from || "/";

  const [username, setUsername] = useState("dev");
  const [password, setPassword] = useState("dev");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function doLogin(u: string, p: string) {
    setError(null);
    setLoading(true);
    try {
      const resp = await login({ username: u, password: p });
      auth.setSession(resp);
      nav(from, { replace: true });
    } catch (e) {
      if (e instanceof ApiError) setError(typeof e.body === "string" ? e.body : JSON.stringify(e.body));
      else setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="card">
        <h1>Login</h1>
        <p className="muted">PoC login. Users are seeded in Postgres: dev/agent/admin.</p>

        <div className="row">
          {presets.map((p) => (
            <div className="col" key={p.label}>
              <div className="card" style={{ borderStyle: "dashed" }}>
                <h2>{p.label}</h2>
                <div className="muted">{p.note}</div>
                <div style={{ height: 10 }} />
                <button className="btn primary" disabled={loading} onClick={() => doLogin(p.username, p.password)}>
                  Login as {p.username}
                </button>
              </div>
            </div>
          ))}
        </div>

        <hr />

        <h2>Manual login</h2>
        <div className="row">
          <div className="col">
            <div className="field">
              <label>Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
          </div>
          <div className="col">
            <div className="field">
              <label>Password</label>
              <input value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          </div>
          <div className="col" style={{ alignSelf: "end" }}>
            <button className="btn primary" disabled={loading} onClick={() => doLogin(username, password)}>
              Login
            </button>
          </div>
        </div>

        {error ? <div className="error" style={{ marginTop: 10 }}>{error}</div> : null}
      </div>
    </div>
  );
}
