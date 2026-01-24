import { STORAGE_KEY } from "../state/auth";

export const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, body: unknown) {
    super(`API Error ${status}`);
    this.status = status;
    this.body = body;
  }
}

export async function apiFetch<T>(
  path: string,
  opts: RequestInit & { token?: string | null } = {}
): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers = new Headers(opts.headers || {});
  headers.set("Content-Type", "application/json");
  if (opts.token) headers.set("Authorization", `Bearer ${opts.token}`);

  const res = await fetch(url, { ...opts, headers });
  const text = await res.text();
  const body = text ? safeJson(text) : null;

  if (!res.ok) {
    if (res.status === 401) {
      try {
        localStorage.removeItem(STORAGE_KEY);
        window.dispatchEvent(new Event("auth:logout"));
      } catch {}
    }
    throw new ApiError(res.status, body);
  }
  return body as T;
}

function safeJson(s: string) {
  try { return JSON.parse(s); } catch { return s; }
}
