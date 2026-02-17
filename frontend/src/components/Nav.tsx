import { useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { getApiBase, setApiBase } from "../api/client";
import { useAuth } from "../state/auth";
import { Button, Pill } from "./ui";

const BACKEND_OPTIONS = [
  { value: "/api", label: "Python (/api)" },
  { value: "/api-go", label: "Go (/api-go)" },
];

export default function Nav() {
  const auth = useAuth();
  const nav = useNavigate();
  const [apiBase, setApiBaseState] = useState(() => getApiBase());

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link to="/" className="brand" aria-label="Home">
          <span className="dot" />
          <span>Cinema DCS PoC</span>
        </Link>

        <div className="navlinks">
          <NavLink to="/films" className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>Films</NavLink>
          <NavLink to="/halls" className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>Halls</NavLink>
          <NavLink to="/spectators" className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>Spectators</NavLink>
          <NavLink to="/audit" className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>Audit</NavLink>
          <NavLink to="/perf" className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>Perf</NavLink>
        </div>

        <div className="spacer" />

        <div className="backend-switch">
          <span className="muted">Backend</span>
          <select
            aria-label="Backend"
            value={apiBase}
            onChange={(e) => {
              const next = setApiBase(e.target.value);
              setApiBaseState(next);
              window.location.reload();
            }}
          >
            {BACKEND_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {auth.token ? (
          <>
            <span className="badge">
              <span className="muted">user</span>
              <strong>{auth.username}</strong>
              <Pill kind={auth.role === "admin" ? "ok" : auth.role === "agent" ? "warn" : undefined}>
                {auth.role}
              </Pill>
            </span>
            <Button
              onClick={() => {
                auth.logout();
                nav("/login");
              }}
            >
              Logout
            </Button>
          </>
        ) : (
          <Button variant="primary" onClick={() => nav("/login")}>Login</Button>
        )}
      </div>
    </header>
  );
}
