from sqlalchemy.orm import Session
from uuid import UUID
from app.db.models.perf_log import PerfLog
from app.core.runtime_settings import get_cache_level
from app.observability.perf import PerfContext


def write_perf(
    *,
    db: Session,
    request_id: str,
    tenant_id: str,
    subject_user_id: UUID | None,
    subject_role: str | None,
    action: str,
    resource_type: str,
    dcs_enabled: bool,
    perf: PerfContext | None,
):
    metrics = perf.metrics if perf is not None else {}
    total_ms = perf.elapsed_ms() if perf is not None else None

    row = PerfLog(
        request_id=request_id,
        tenant_id=tenant_id,
        subject_user_id=subject_user_id,
        subject_role=subject_role,
        action=action,
        resource_type=resource_type,
        dcs_enabled=dcs_enabled,
        cache_level=get_cache_level(),
        total_ms=total_ms,
        pip_ms=metrics.get("pip_ms"),
        pdp_ms=metrics.get("pdp_ms"),
        kms_ms=metrics.get("kms_ms"),
        db_ms=metrics.get("db_ms"),
    )
    db.add(row)
    db.commit()
