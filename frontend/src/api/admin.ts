import type { AdminSettingsOut, AdminSettingsUpdate } from "../types/dto";
import { apiFetch } from "./client";

export function getAdminSettings(token: string): Promise<AdminSettingsOut> {
  return apiFetch<AdminSettingsOut>("/admin/settings", { method: "GET", token });
}

export function updateAdminSettings(
  token: string,
  payload: AdminSettingsUpdate
): Promise<AdminSettingsOut> {
  return apiFetch<AdminSettingsOut>("/admin/settings", {
    method: "PATCH",
    token,
    body: JSON.stringify(payload),
  });
}
