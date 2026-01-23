import type { AuditOut, FilmOut, HallOut, SpectatorOut } from "../types/dto";
import { apiFetch } from "./client";

export function listFilms(token: string): Promise<FilmOut[]> {
  return apiFetch<FilmOut[]>("/films/", { method: "GET", token });
}

export function createFilm(token: string, payload: { title: string; time_elapsed: number }): Promise<FilmOut> {
  return apiFetch<FilmOut>("/films/", { method: "POST", token, body: JSON.stringify(payload) });
}

export function updateFilmTime(token: string, filmId: string, time_elapsed: number): Promise<FilmOut> {
  const qs = new URLSearchParams({ time_elapsed: String(time_elapsed) }).toString();
  return apiFetch<FilmOut>(`/films/${filmId}/time?${qs}`, { method: "PATCH", token });
}

export function listHalls(token: string): Promise<HallOut[]> {
  return apiFetch<HallOut[]>("/halls/", { method: "GET", token });
}

export function createHall(token: string, payload: { name: string; current_film_id: string; owner_user_id: string }): Promise<HallOut> {
  return apiFetch<HallOut>("/halls/", { method: "POST", token, body: JSON.stringify(payload) });
}

export function createSpectator(token: string, payload: { hall_id: string; name: string; age: number; external_id: string }): Promise<SpectatorOut> {
  return apiFetch<SpectatorOut>("/spectators/", { method: "POST", token, body: JSON.stringify(payload) });
}

export function searchSpectator(token: string, external_id: string): Promise<SpectatorOut[]> {
  const qs = new URLSearchParams({ external_id }).toString();
  return apiFetch<SpectatorOut[]>(`/spectators/search?${qs}`, { method: "GET", token });
}

export function listAudit(token: string): Promise<AuditOut[]> {
  return apiFetch<AuditOut[]>("/audit/", { method: "GET", token });
}
