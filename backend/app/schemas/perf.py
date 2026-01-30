from pydantic import BaseModel
from uuid import UUID
from datetime import datetime


class PerfOut(BaseModel):
    ts: datetime
    request_id: str
    tenant_id: str
    subject_user_id: UUID | None
    subject_role: str | None
    action: str
    resource_type: str
    dcs_enabled: bool
    cache_level: int
    total_ms: float | None
    pip_ms: float | None
    pdp_ms: float | None
    kms_ms: float | None
    db_ms: float | None


class PerfSummaryOut(BaseModel):
    action: str
    dcs_enabled: bool
    cache_level: int
    avg_total_ms: float | None
    count: int
