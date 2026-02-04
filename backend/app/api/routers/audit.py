from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.security.auth import Principal, get_current_principal
from app.db.models.audit_log import AuditLog
from app.db.session import get_db
from app.dcs.pdp.engine import evaluate
from app.dcs.pep.mode import dcs_enabled
from app.dcs.pip.provider import build_policy_input
from app.schemas.audit import AuditOut
from app.services.perf_service import write_perf

router = APIRouter()


@router.get("/", response_model=list[AuditOut])
def list_audit(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    p: Annotated[Principal, Depends(get_current_principal)],
):
    pi = build_policy_input(
        db=db,
        request=request,
        principal=p,
        action="audit.read",
        resource_type="audit",
        resource_id="audit",
        owner_id=None,
        crypto_meta={},
    )
    dec = evaluate(pi)
    if not dec.allow:
        write_perf(
            db=db,
            request_id=request.state.request_id,
            tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id),
            subject_role=p.role,
            action="audit.read",
            resource_type="audit",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(200).all()
    out = [
        {
            "ts": r.ts,
            "request_id": r.request_id,
            "tenant_id": r.tenant_id,
            "subject_user_id": r.subject_user_id,
            "subject_role": r.subject_role,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "outcome": r.outcome,
            "fields_decrypted": r.fields_decrypted,
            "fields_masked": r.fields_masked,
            "fields_denied": r.fields_denied,
        }
        for r in rows
    ]
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="audit.read",
        resource_type="audit",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return out
