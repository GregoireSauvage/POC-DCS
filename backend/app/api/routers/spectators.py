from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sqlalchemy.orm import Session
from uuid import UUID

from app.db.session import get_db
from app.core.security.auth import Principal, get_current_principal
from app.db.models.spectator import Spectator
from app.db.models.hall import Hall
from app.schemas.spectator import SpectatorCreate, SpectatorOut
from app.dcs.pip.provider import build_policy_input
from app.dcs.pdp.engine import evaluate, decision_hash
from app.dcs.pep.data_pep import apply_decision, mask_uuid
from app.dcs.pep.mode import dcs_enabled
from app.services.audit_service import write_audit
from app.services.perf_service import write_perf
from app.services.cinema_service import add_spectator
from app.dcs.kms.vault_transit import VaultClient
from app.dcs.crypto.lookup import normalize_external_id, hmac_lookup

router = APIRouter()
vault = VaultClient()

@router.post("/", response_model=SpectatorOut)
def create_one(request: Request, payload: SpectatorCreate, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    hall = db.query(Hall).filter(Hall.tenant_id == p.tenant_id, Hall.id == payload.hall_id).one_or_none()
    if hall is None:
        raise HTTPException(status_code=404, detail="Hall not found")

    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="spectator.create", resource_type="spectator",
        resource_id="new", owner_id=str(hall.owner_user_id),
        crypto_meta={
            "name": {"ciphertext_field": "name_ct"},
            "age": {"ciphertext_field": "age_ct"},
            "external_id": {"ciphertext_field": "external_id_ct"},
        },
    )
    dec = evaluate(pi)
    dh = decision_hash(dec)
    if not dec.allow:
        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="spectator.create", resource_type="spectator", resource_id=None,
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
            action="spectator.create",
            resource_type="spectator",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    sp = add_spectator(
        db,
        tenant_id=p.tenant_id,
        hall_id=payload.hall_id,
        name=payload.name,
        age=payload.age,
        external_id=payload.external_id,
    )

    # respond under read policy
    pi_r = build_policy_input(
        db=db, request=request, principal=p,
        action="spectator.read", resource_type="spectator",
        resource_id=str(sp.id), owner_id=str(hall.owner_user_id),
        crypto_meta={
            "name": {"ciphertext_field": "name_ct"},
            "age": {"ciphertext_field": "age_ct"},
            "external_id": {"ciphertext_field": "external_id_ct"},
        },
    )
    dec_r = evaluate(pi_r)
    row = {"id": sp.id, "hall_id": sp.hall_id, "name_ct": sp.name_ct, "age_ct": sp.age_ct, "external_id_ct": sp.external_id_ct}
    applied = apply_decision(decision=dec_r, ciphertext_row=row, field_to_ciphertext={"name":"name_ct","age":"age_ct","external_id":"external_id_ct"})

    spectator_id = str(sp.id) if (p.role == "admin" or not dcs_enabled()) else mask_uuid(str(sp.id))

    write_audit(
        db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id), subject_role=p.role,
        action="spectator.create", resource_type="spectator", resource_id=sp.id,
        outcome="allow", decision_hash=dh,
        fields_decrypted=[], fields_masked=[], fields_denied=[],
        details={"hall_id": str(payload.hall_id)},
    )

    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="spectator.create",
        resource_type="spectator",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )

    return {
        "id": spectator_id,
        "hall_id": sp.hall_id,
        "name": applied.payload.get("name"),
        "age": applied.payload.get("age"),
        "external_id": applied.payload.get("external_id"),
    }

@router.get("/search", response_model=list[SpectatorOut])
def search_by_external_id(
    request: Request,
    external_id: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_current_principal),
):
    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="search.spectator", resource_type="spectator",
        resource_id="search", owner_id=None,
        crypto_meta={
            "name": {"ciphertext_field": "name_ct"},
            "age": {"ciphertext_field": "age_ct"},
            "external_id": {"ciphertext_field": "external_id_ct"},
        },
    )
    dec = evaluate(pi)
    dh = decision_hash(dec)
    if not dec.allow:
        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="search.spectator", resource_type="spectator", resource_id=None,
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
            action="search.spectator",
            resource_type="spectator",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    pepper = vault.get_pepper()
    lookup = hmac_lookup(pepper, normalize_external_id(external_id))
    matches = db.query(Spectator).filter(Spectator.tenant_id == p.tenant_id, Spectator.external_id_lookup == lookup).all()

    out = []
    for sp in matches:
        pi_r = build_policy_input(
            db=db, request=request, principal=p,
            action="spectator.read", resource_type="spectator",
            resource_id=str(sp.id), owner_id=None,
            crypto_meta={
                "name": {"ciphertext_field": "name_ct"},
                "age": {"ciphertext_field": "age_ct"},
                "external_id": {"ciphertext_field": "external_id_ct"},
            },
        )
        dec_r = evaluate(pi_r)
        row = {"id": sp.id, "hall_id": sp.hall_id, "name_ct": sp.name_ct, "age_ct": sp.age_ct, "external_id_ct": sp.external_id_ct}
        applied = apply_decision(decision=dec_r, ciphertext_row=row, field_to_ciphertext={"name":"name_ct","age":"age_ct","external_id":"external_id_ct"})
        spectator_id = str(sp.id) if (p.role == "admin" or not dcs_enabled()) else mask_uuid(str(sp.id))
        out.append({
            "id": spectator_id,
            "hall_id": sp.hall_id,
            "name": applied.payload.get("name"),
            "age": applied.payload.get("age"),
            "external_id": applied.payload.get("external_id"),
        })

    write_audit(
        db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id), subject_role=p.role,
        action="search.spectator", resource_type="spectator", resource_id=None,
        outcome="allow", decision_hash=dh,
        fields_decrypted=[], fields_masked=[], fields_denied=[],
        details={"matches": len(out)},
    )
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="search.spectator",
        resource_type="spectator",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return out
