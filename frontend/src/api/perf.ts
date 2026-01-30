import type { PerfOut, PerfSummaryOut } from "../types/dto";
import { apiFetch } from "./client";

export function listPerf(
  token: string,
  params: { limit?: number; action?: string } = {}
): Promise<PerfOut[]> {
  const qs = new URLSearchParams();
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.action) qs.set("action", params.action);
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<PerfOut[]>(`/perf/${suffix}`, { method: "GET", token });
}

export function listPerfSummary(
  token: string,
  params: { action?: string; cache_level?: number } = {}
): Promise<PerfSummaryOut[]> {
  const qs = new URLSearchParams();
  if (params.action) qs.set("action", params.action);
  if (typeof params.cache_level === "number") qs.set("cache_level", String(params.cache_level));
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<PerfSummaryOut[]>(`/perf/summary${suffix}`, { method: "GET", token });
}
