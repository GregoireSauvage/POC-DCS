import { STORAGE_KEY } from "../state/auth";

export const API_BASE_KEY = "cinema_dcs_api_base_v1";
const DEFAULT_API_BASE = "/api";
const ALLOWED_API_BASES = new Set([DEFAULT_API_BASE, "/api-go"]);

function normalizeApiBase(raw: string | null | undefined): string {
  if (!raw) return DEFAULT_API_BASE;
  return ALLOWED_API_BASES.has(raw) ? raw : DEFAULT_API_BASE;
}

export function getApiBase(): string {
  try {
    const stored = localStorage.getItem(API_BASE_KEY);
    if (stored) return normalizeApiBase(stored);
  } catch {
    // Ignore storage errors in restricted contexts
  }
  const envBase = import.meta.env.VITE_API_BASE_URL as string | undefined;
  return normalizeApiBase(envBase);
}

export function setApiBase(base: string): string {
  const normalized = normalizeApiBase(base);
  try {
    localStorage.setItem(API_BASE_KEY, normalized);
  } catch {
    // Ignore storage errors in restricted contexts
  }
  return normalized;
}

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
  const url = `${getApiBase()}${path}`;
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
      } catch {
        // Ignore storage errors in restricted contexts
      }
    }
    throw new ApiError(res.status, body);
  }
  return body as T;
}

function safeJson(s: string) {
  try { return JSON.parse(s); } catch { return s; }
}
