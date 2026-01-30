from __future__ import annotations

import logging
from threading import Lock

from app.core.config import settings

_log = logging.getLogger("runtime_settings")
_lock = Lock()
_overrides: dict[str, object | None] = {"dcs_mode": None, "cache_level": None}


def get_dcs_mode() -> str:
    with _lock:
        val = _overrides.get("dcs_mode")
    return str(val) if val is not None else settings.DCS_MODE


def get_cache_level() -> int:
    with _lock:
        val = _overrides.get("cache_level")
    if val is None:
        return settings.CACHE_LEVEL
    try:
        return int(val)
    except Exception:
        return settings.CACHE_LEVEL


def set_runtime_settings(*, dcs_mode: str | None, cache_level: int | None) -> None:
    changed = False
    with _lock:
        if dcs_mode is not None:
            _overrides["dcs_mode"] = str(dcs_mode).lower()
            changed = True
        if cache_level is not None:
            _overrides["cache_level"] = max(0, int(cache_level))
            changed = True
    if changed:
        _log.info("runtime settings updated: dcs_mode=%s cache_level=%s", get_dcs_mode(), get_cache_level())
        try:
            from app.cache.cache import clear_all_caches
            clear_all_caches()
        except Exception:
            pass


def get_runtime_settings() -> dict[str, object]:
    return {"dcs_mode": get_dcs_mode(), "cache_level": get_cache_level()}
