from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID

from app.db.session import get_db
from app.core.security.auth import Principal, get_current_principal
from app.db.models.hall import Hall
from app.db.models.spectator import Spectator
from app.schemas.hall import HallOut, HallCreate
from app.dcs.pip.provider import build_policy_input
from app.dcs.pdp.engine import evaluate, decision_hash
from app.dcs.pep.data_pep import mask_uuid
from app.dcs.pep.mode import dcs_enabled
from app.services.audit_service import write_audit
from app.services.perf_service import write_perf
from app.services.cinema_service import create_hall

router = APIRouter()

@router.get("/", response_model=list[HallOut])
def list_halls(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    halls = db.query(Hall).filter(Hall.tenant_id == p.tenant_id).all()
    out = []
    for h in halls:
        spectator_count = db.query(Spectator).filter(Spectator.tenant_id == p.tenant_id, Spectator.hall_id == h.id).count()

        pi = build_policy_input(
            db=db, request=request, principal=p,
            action="hall.read", resource_type="hall",
            resource_id=str(h.id), owner_id=str(h.owner_user_id),
            crypto_meta={},
        )
        dec = evaluate(pi)
        dh = decision_hash(dec)
        if not dec.allow:
            write_audit(
                db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
                subject_user_id=UUID(p.user_id), subject_role=p.role,
                action="hall.read", resource_type="hall", resource_id=h.id,
                outcome="deny", decision_hash=dh,
                fields_decrypted=[], fields_masked=[], fields_denied=[],
                details={"reason": dec.reason},
            )
            continue

        payload = {
            "id": h.id,
            "name": h.name,
            "current_film_id": h.current_film_id,
            "owner_user_id": h.owner_user_id,
            "spectator_count": spectator_count,
        }

        masked, denied = [], []
        fa = dec.field_actions
        if fa.get("owner_user_id") == "mask_after_decrypt":
            payload["owner_user_id"] = mask_uuid(str(payload["owner_user_id"]))
            masked.append("owner_user_id")
        if fa.get("current_film_id") == "mask_after_decrypt":
            payload["current_film_id"] = mask_uuid(str(payload["current_film_id"]))
            masked.append("current_film_id")
        if fa.get("name") == "deny":
            payload["name"] = None
            denied.append("name")

        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="hall.read", resource_type="hall", resource_id=h.id,
            outcome="allow", decision_hash=dh,
            fields_decrypted=[], fields_masked=masked, fields_denied=denied,
            details={},
        )
        out.append(payload)
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="hall.read",
        resource_type="hall",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return out

@router.post("/", response_model=HallOut)
def create_one(request: Request, payload: HallCreate, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="hall.create", resource_type="hall",
        resource_id="new", owner_id=str(payload.owner_user_id),
        crypto_meta={},
    )
    dec = evaluate(pi)
    dh = decision_hash(dec)
    if not dec.allow:
        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="hall.create", resource_type="hall", resource_id=None,
            outcome="deny", decision_hash=dh,
            fields_decrypted=[], fields_masked=[], fields_denied=[],
            details={"reason": dec.reason},
        )
        write_perf(
            db=db,
            request_id=request.state.request_id,
            tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id),
            subject_role=p.role,
            action="hall.create",
            resource_type="hall",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    hall = create_hall(
        db,
        tenant_id=p.tenant_id,
        name=payload.name,
        owner_user_id=payload.owner_user_id,
        current_film_id=payload.current_film_id,
    )
    write_audit(
        db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id), subject_role=p.role,
        action="hall.create", resource_type="hall", resource_id=hall.id,
        outcome="allow", decision_hash=dh,
        fields_decrypted=[], fields_masked=[], fields_denied=[],
        details={"name": payload.name},
    )
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="hall.create",
        resource_type="hall",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return {"id": hall.id, "name": hall.name, "current_film_id": hall.current_film_id, "owner_user_id": hall.owner_user_id, "spectator_count": 0}
