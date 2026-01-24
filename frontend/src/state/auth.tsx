import React, { createContext, useContext, useMemo, useState } from "react";
import type { LoginResponse, Role } from "../types/dto";

type AuthState = {
  token: string | null;
  role: Role | null;
  tenantId: string | null;
  userId: string | null;
  username: string | null;
};

type AuthContextType = AuthState & {
  setSession: (resp: LoginResponse) => void;
  logout: () => void;
};

const AuthContext = createContext<AuthContextType | null>(null);
const STORAGE_KEY = "cinema_dcs_session_v1";

function loadInitial(): AuthState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { token: null, role: null, tenantId: null, userId: null, username: null };
    const obj = JSON.parse(raw) as AuthState;
    return obj?.token ? obj : { token: null, role: null, tenantId: null, userId: null, username: null };
  } catch {
    return { token: null, role: null, tenantId: null, userId: null, username: null };
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>(() => loadInitial());

  const api = useMemo<AuthContextType>(() => {
    return {
      ...state,
      setSession: (resp) => {
        const next: AuthState = {
          token: resp.access_token,
          role: resp.role,
          tenantId: resp.tenant_id,
          userId: resp.user_id,
          username: resp.username
        };
        setState(next);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      },
      logout: () => {
        const next: AuthState = { token: null, role: null, tenantId: null, userId: null, username: null };
        setState(next);
        localStorage.removeItem(STORAGE_KEY);
      }
    };
  }, [state]);

  return <AuthContext.Provider value={api}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
