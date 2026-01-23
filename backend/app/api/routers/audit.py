from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security.auth import Principal, get_current_principal
from app.db.models.audit_log import AuditLog
from app.schemas.audit import AuditOut
from app.dcs.pip.provider import build_policy_input
from app.dcs.pdp.engine import evaluate

router = APIRouter()

@router.get("/", response_model=list[AuditOut])
def list_audit(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="audit.read", resource_type="audit",
        resource_id="audit", owner_id=None,
        crypto_meta={},
    )
    dec = evaluate(pi)
    if not dec.allow:
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(200).all()
    return [
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
