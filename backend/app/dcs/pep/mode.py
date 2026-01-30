from app.core.config import settings
from app.core.dcs_config import get_dcs_config


def dcs_enabled() -> bool:
    return settings.DCS_MODE.lower() not in ("off", "false", "0", "no")


def allow_without_dcs(action: str, role: str) -> bool:
    cfg = get_dcs_config()
    pdp_cfg = cfg.get("pdp", {})
    if action in pdp_cfg.get("read_actions", []):
        return True
    if action in pdp_cfg.get("write_actions", []):
        return role in ("agent", "admin")
    if action in pdp_cfg.get("bootstrap_actions", []):
        return role == "admin"
    if action in pdp_cfg.get("audit_actions", []):
        return role == "admin"
    return False
