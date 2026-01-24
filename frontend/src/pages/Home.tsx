import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../state/auth";
import { Card, Pill, Kbd } from "../components/ui";

export default function Home() {
  const auth = useAuth();

  return (
    <div className="container">
      <div className="grid" style={{ gap: 18 }}>
        <Card
          title="Overview"
          subtitle="DCS PoC: per-field decisions (decrypt/mask/deny) driven by metadata and policy."
          right={<Pill>Backend = PEP (data)</Pill>}
        >
          {!auth.token ? (
            <p>
              Not authenticated. Go to <Link to="/login"><Kbd>Login</Kbd></Link>.
            </p>
          ) : (
            <div className="grid cols-2">
              <div className="card soft">
                <h2>Session</h2>
                <p>
                  user <strong>{auth.username}</strong> — role <strong>{auth.role}</strong> — tenant <strong>{auth.tenantId}</strong>
                </p>
                <p className="small">
                  Requests: JWT auth → PIP facts → PDP decision → PEP enforcement → audit log.
                </p>
              </div>

              <div className="card soft">
                <h2>What to try</h2>
                <p className="small">
                  1) <Link to="/films"><Kbd>Films</Kbd></Link> create a film, update <span className="mono">time_elapsed</span><br/>
                  2) <Link to="/halls"><Kbd>Halls</Kbd></Link> create a hall for that film<br/>
                  3) <Link to="/spectators"><Kbd>Spectators</Kbd></Link> add a spectator, then search by ticket id<br/>
                  4) <Link to="/audit"><Kbd>Audit</Kbd></Link> view enforcement logs (admin)
                </p>
              </div>
            </div>
          )}
        </Card>

        <div className="grid cols-2">
          <div className="card soft">
            <h2>Data model</h2>
            <p className="small">
              Film: title + encrypted time_elapsed<br/>
              Hall: name + owner + current_film + spectator_count<br/>
              Spectator: encrypted name/age/ticket + HMAC lookup for ticket search
            </p>
          </div>
          <div className="card soft">
            <h2>Role expectations</h2>
            <p className="small">
              Developer: sees masked data for INTERNAL/PII/SENSITIVE<br/>
              Agent: can write; sees sensitive decrypted; PII masked<br/>
              Admin: decrypts all, can read audit
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
