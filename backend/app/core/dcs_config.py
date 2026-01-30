from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import settings


_DEFAULT_CONFIG: dict[str, Any] = {
    "pip": {
        "channel": "web",
        "purpose": "cinema_ops",
        "device_trust": 0.8,
        "client_ip_header": "x-real-ip",
    },
    "pdp": {
        "default_classification": "INTERNAL",
        "read_actions": ["film.read", "hall.read", "spectator.read", "search.spectator"],
        "write_actions": ["film.create", "hall.create", "spectator.create", "film.update_time"],
        "bootstrap_actions": ["bootstrap"],
        "audit_actions": ["audit.read"],
        "role_classification_actions": {
            "admin": {
                "PUBLIC": "allow",
                "INTERNAL": "allow",
                "SENSITIVE": "decrypt",
                "PII": "decrypt",
            },
            "agent": {
                "PUBLIC": "allow",
                "INTERNAL": "allow",
                "SENSITIVE": "decrypt",
                "PII": "mask_after_decrypt",
            },
            "developer": {
                "PUBLIC": "allow",
                "INTERNAL": "mask_after_decrypt",
                "SENSITIVE": "mask_after_decrypt",
                "PII": "mask_after_decrypt",
            },
        },
        "spectator_agent_hardening_fields": ["name", "external_id"],
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)  # type: ignore[arg-type]
        else:
            out[key] = val
    return out


def _config_path() -> Path:
    if getattr(settings, "DCS_CONFIG_PATH", ""):
        return Path(settings.DCS_CONFIG_PATH)
    return Path(__file__).resolve().parent.parent / "config" / "dcs_config.json"


@lru_cache(maxsize=1)
def get_dcs_config() -> dict[str, Any]:
    path = _config_path()
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict):
            return _deep_merge(_DEFAULT_CONFIG, data)
    except Exception:
        pass
    return _DEFAULT_CONFIG
