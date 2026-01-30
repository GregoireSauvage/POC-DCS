from pydantic import BaseModel, Field


class AdminSettingsOut(BaseModel):
    dcs_mode: str
    cache_level: int


class AdminSettingsUpdate(BaseModel):
    dcs_mode: str | None = Field(default=None)
    cache_level: int | None = Field(default=None, ge=0, le=3)
