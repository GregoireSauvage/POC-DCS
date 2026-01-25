from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.security.auth import Principal, require_role
from app.db.session import get_db
from app.db.models.perf_log import PerfLog
from app.schemas.perf import PerfOut, PerfSummaryOut

router = APIRouter()


@router.get("/", response_model=list[PerfOut])
def list_perf(
    limit: int = Query(200, ge=1, le=1000),
    action: str | None = Query(None),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_role("admin")),
):
    q = db.query(PerfLog).order_by(PerfLog.ts.desc())
    if action:
        q = q.filter(PerfLog.action == action)
    rows = q.limit(limit).all()
    return [
        {
            "ts": r.ts,
            "request_id": r.request_id,
            "tenant_id": r.tenant_id,
            "subject_user_id": r.subject_user_id,
            "subject_role": r.subject_role,
            "action": r.action,
            "resource_type": r.resource_type,
            "dcs_enabled": r.dcs_enabled,
            "total_ms": r.total_ms,
            "pip_ms": r.pip_ms,
            "pdp_ms": r.pdp_ms,
            "kms_ms": r.kms_ms,
            "db_ms": r.db_ms,
        }
        for r in rows
    ]


@router.get("/summary", response_model=list[PerfSummaryOut])
def perf_summary(
    action: str | None = Query(None),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_role("admin")),
):
    q = (
        db.query(
            PerfLog.action,
            PerfLog.dcs_enabled,
            func.avg(PerfLog.total_ms).label("avg_total_ms"),
            func.count(PerfLog.id).label("count"),
        )
        .group_by(PerfLog.action, PerfLog.dcs_enabled)
        .order_by(PerfLog.action.asc())
    )
    if action:
        q = q.filter(PerfLog.action == action)
    rows = q.all()
    return [
        {
            "action": r.action,
            "dcs_enabled": r.dcs_enabled,
            "avg_total_ms": float(r.avg_total_ms) if r.avg_total_ms is not None else None,
            "count": int(r.count),
        }
        for r in rows
    ]
