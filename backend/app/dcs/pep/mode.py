from app.core.config import settings


def dcs_enabled() -> bool:
    return settings.DCS_MODE.lower() not in ("off", "false", "0", "no")


def allow_without_dcs(action: str, role: str) -> bool:
    if action in ("film.read", "hall.read", "spectator.read", "search.spectator"):
        return True
    if action in ("film.create", "hall.create", "spectator.create", "film.update_time"):
        return role in ("agent", "admin")
    if action == "bootstrap":
        return role == "admin"
    if action == "audit.read":
        return role == "admin"
    return False
