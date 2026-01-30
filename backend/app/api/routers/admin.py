from fastapi import APIRouter, Depends, HTTPException

from app.core.security.auth import Principal, require_role
from app.core.runtime_settings import get_runtime_settings, set_runtime_settings
from app.schemas.admin import AdminSettingsOut, AdminSettingsUpdate

router = APIRouter()


@router.get("/settings", response_model=AdminSettingsOut)
def get_settings(p: Principal = Depends(require_role("admin"))):
    data = get_runtime_settings()
    return {"dcs_mode": data["dcs_mode"], "cache_level": data["cache_level"]}


@router.patch("/settings", response_model=AdminSettingsOut)
def update_settings(payload: AdminSettingsUpdate, p: Principal = Depends(require_role("admin"))):
    if payload.dcs_mode is not None and payload.dcs_mode.lower() not in ("on", "off"):
        raise HTTPException(status_code=400, detail="dcs_mode must be 'on' or 'off'")
    if payload.cache_level is not None and payload.cache_level < 0:
        raise HTTPException(status_code=400, detail="cache_level must be >= 0")

    set_runtime_settings(
        dcs_mode=payload.dcs_mode,
        cache_level=payload.cache_level,
    )
    data = get_runtime_settings()
    return {"dcs_mode": data["dcs_mode"], "cache_level": data["cache_level"]}
