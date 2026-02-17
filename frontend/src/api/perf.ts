import type { PerfOut, PerfSummaryOut } from "../types/dto";
import { apiFetch, getApiBase } from "./client";

function resolvePerfSource(override?: string): string {
  if (override) return override;
  const base = getApiBase();
  if (base === "/api-go") return "go";
  return "python";
}

export function listPerf(
  token: string,
  params: { limit?: number; action?: string; source?: string } = {}
): Promise<PerfOut[]> {
  const qs = new URLSearchParams();
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.action) qs.set("action", params.action);
  qs.set("source", resolvePerfSource(params.source));
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<PerfOut[]>(`/perf/${suffix}`, { method: "GET", token });
}

export function listPerfSummary(
  token: string,
  params: { action?: string; cache_level?: number; all_cache_levels?: boolean; source?: string } = {}
): Promise<PerfSummaryOut[]> {
  const qs = new URLSearchParams();
  if (params.action) qs.set("action", params.action);
  if (typeof params.cache_level === "number") qs.set("cache_level", String(params.cache_level));
  if (params.all_cache_levels) qs.set("all_cache_levels", "1");
  qs.set("source", resolvePerfSource(params.source));
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return apiFetch<PerfSummaryOut[]>(`/perf/summary${suffix}`, { method: "GET", token });
}
