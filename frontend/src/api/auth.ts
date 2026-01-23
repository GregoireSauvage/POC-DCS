import type { LoginRequest, LoginResponse } from "../types/dto";
import { apiFetch } from "./client";

export function login(req: LoginRequest): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(req),
  });
}
