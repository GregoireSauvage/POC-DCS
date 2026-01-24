import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../state/auth";
import { Button, Pill } from "./ui";

export default function Nav() {
  const auth = useAuth();
  const nav = useNavigate();

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
        </div>

        <div className="spacer" />

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
