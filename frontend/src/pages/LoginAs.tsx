import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { login } from "../api/auth";
import { ApiError } from "../api/client";
import { useAuth } from "../state/auth";
import { Alert, Button, Card, Pill } from "../components/ui";

type Preset = { label: string; username: string; password: string; note: string; kind?: "ok" | "warn" | "danger" };

const presets: Preset[] = [
  { label: "Developer", username: "dev", password: "dev", note: "Read allowed, but sensitive/PII returned masked.", kind: undefined },
  { label: "Agent", username: "agent", password: "agent", note: "Can write some resources. Decrypt sensitive, mask PII.", kind: "warn" },
  { label: "Admin", username: "admin", password: "admin", note: "Full access. Can view audit logs.", kind: "ok" }
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
      <div className="grid" style={{ gap: 18 }}>
        <Card title="Login" subtitle="Seeded users in Postgres: dev/dev, agent/agent, admin/admin." right={<Pill>JWT → PEP → PIP/PDP → KMS</Pill>}>
          <div className="grid cols-2">
            {presets.map((p) => (
              <div key={p.label} className="card dashed">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                  <h2>{p.label}</h2>
                  <Pill kind={p.kind}>{p.username}</Pill>
                </div>
                <p>{p.note}</p>
                <div style={{ height: 12 }} />
                <Button variant="primary" disabled={loading} onClick={() => doLogin(p.username, p.password)}>
                  Login as {p.username}
                </Button>
              </div>
            ))}
          </div>

          <hr />

          <h2>Manual login</h2>
          <div className="grid cols-2">
            <div className="field">
              <label>Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="field">
              <label>Password</label>
              <input value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          </div>
          <div style={{ marginTop: 10 }}>
            <Button variant="primary" disabled={loading} onClick={() => doLogin(username, password)}>
              Login
            </Button>
          </div>

          {error ? <div style={{ marginTop: 12 }}><Alert kind="error">{error}</Alert></div> : null}
        </Card>

        <div className="grid cols-2">
          <div className="card soft">
            <h2>What you’re testing</h2>
            <p>
              The UI does not implement RBAC. It simply displays whatever the backend returns after enforcing DCS decisions
              (decrypt/mask/deny per-field).
            </p>
          </div>
          <div className="card soft">
            <h2>Tip</h2>
            <p>
              Use <span className="kbd">Audit</span> as admin to see how each request was enforced.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
