import React from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../state/auth";

const activeStyle: React.CSSProperties = { textDecoration: "underline" };

export default function Nav() {
  const auth = useAuth();
  const nav = useNavigate();

  return (
    <div className="container">
      <nav>
        <Link to="/" style={{ fontWeight: 700 }}>Cinema DCS PoC</Link>

        <NavLink to="/films" style={({ isActive }) => (isActive ? activeStyle : undefined)}>
          Films
        </NavLink>
        <NavLink to="/halls" style={({ isActive }) => (isActive ? activeStyle : undefined)}>
          Halls
        </NavLink>
        <NavLink to="/spectators" style={({ isActive }) => (isActive ? activeStyle : undefined)}>
          Spectators
        </NavLink>
        <NavLink to="/audit" style={({ isActive }) => (isActive ? activeStyle : undefined)}>
          Audit
        </NavLink>

        <div style={{ marginLeft: "auto" }} />

        {auth.token ? (
          <>
            <span className="badge">
              <span>user:</span> <strong>{auth.username}</strong> <span className="muted">({auth.role})</span>
            </span>
            <button
              className="btn"
              onClick={() => {
                auth.logout();
                nav("/login");
              }}
            >
              Logout
            </button>
          </>
        ) : (
          <button className="btn primary" onClick={() => nav("/login")}>Login</button>
        )}
      </nav>
    </div>
  );
}
