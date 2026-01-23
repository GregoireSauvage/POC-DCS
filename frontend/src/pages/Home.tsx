import React from "react";
import { useAuth } from "../state/auth";
import { Link } from "react-router-dom";

export default function Home() {
  const auth = useAuth();
  return (
    <div className="container">
      <div className="card">
        <h1>Overview</h1>

        {!auth.token ? (
          <p className="muted">You are not authenticated. Go to <Link to="/login">Login</Link>.</p>
        ) : (
          <>
            <p className="muted">
              Connected as <strong>{auth.username}</strong> (<strong>{auth.role}</strong>) — tenant <strong>{auth.tenantId}</strong>
            </p>
            <div className="row">
              <div className="col">
                <div className="card">
                  <h2>DCS flow</h2>
                  <div className="muted">
                    Backend acts as PEP (data) + internal PIP/PDP. Vault Transit is the KMS. Postgres stores ciphertext + metadata.
                  </div>
                </div>
              </div>
              <div className="col">
                <div className="card">
                  <h2>Try</h2>
                  <ul className="muted">
                    <li><Link to="/films">Create a film</Link>, then update time_elapsed</li>
                    <li><Link to="/halls">Create a hall</Link> using that film</li>
                    <li><Link to="/spectators">Add a spectator</Link> + search by ticket id</li>
                    <li><Link to="/audit">Audit</Link> (admin only)</li>
                  </ul>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
