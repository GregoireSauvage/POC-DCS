export type Role = "developer" | "agent" | "admin";

export type LoginRequest = { username: string; password: string };
export type LoginResponse = {
  access_token: string;
  token_type: "bearer";
  role: Role;
  tenant_id: string;
  user_id: string;
  username: string;
};

export type FilmOut = { id: string; title: string; time_elapsed: number | string | null };
export type HallOut = { id: string; name: string | null; current_film_id: string | null; owner_user_id: string | null; spectator_count: number | null };
export type SpectatorOut = { id: string; hall_id: string; name: string | null; age: number | string | null; external_id: string | null };

export type AuditOut = {
  ts: string;
  request_id: string;
  tenant_id: string;
  subject_user_id: string | null;
  subject_role: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: "allow" | "deny" | "error";
  fields_decrypted: string[];
  fields_masked: string[];
  fields_denied: string[];
};

export type PerfOut = {
  ts: string;
  request_id: string;
  tenant_id: string;
  subject_user_id: string | null;
  subject_role: string | null;
  action: string;
  resource_type: string;
  dcs_enabled: boolean;
  total_ms: number | null;
  pip_ms: number | null;
  pdp_ms: number | null;
  kms_ms: number | null;
  db_ms: number | null;
};

export type PerfSummaryOut = {
  action: string;
  dcs_enabled: boolean;
  avg_total_ms: number | null;
  count: number;
};
