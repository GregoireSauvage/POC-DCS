from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sqlalchemy.orm import Session
from uuid import UUID

from app.db.session import get_db
from app.core.security.auth import Principal, get_current_principal
from app.db.models.film import Film
from app.schemas.film import FilmCreate, FilmOut
from app.dcs.pip.provider import build_policy_input
from app.dcs.pdp.engine import evaluate, decision_hash
from app.dcs.pep.data_pep import apply_decision
from app.dcs.pep.mode import dcs_enabled
from app.services.audit_service import write_audit
from app.services.perf_service import write_perf
from app.services.cinema_service import create_film, update_film_time

router = APIRouter()

@router.get("/", response_model=list[FilmOut])
def list_films(request: Request, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    films = db.query(Film).filter(Film.tenant_id == p.tenant_id).all()
    out = []
    for film in films:
        pi = build_policy_input(
            db=db,
            request=request,
            principal=p,
            action="film.read",
            resource_type="film",
            resource_id=str(film.id),
            owner_id=None,
            crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}},
        )
        dec = evaluate(pi)
        dh = decision_hash(dec)

        row = {"title": film.title, "time_elapsed_ct": film.time_elapsed_ct}
        applied = apply_decision(decision=dec, ciphertext_row=row, field_to_ciphertext={"time_elapsed": "time_elapsed_ct"})
        payload = {"id": film.id, "title": film.title, "time_elapsed": applied.payload.get("time_elapsed")}

        write_audit(
            db=db,
            request_id=request.state.request_id,
            tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id),
            subject_role=p.role,
            action="film.read",
            resource_type="film",
            resource_id=film.id,
            outcome="allow" if dec.allow else "deny",
            decision_hash=dh,
            fields_decrypted=applied.decrypted,
            fields_masked=applied.masked,
            fields_denied=applied.denied,
            details={},
        )
        out.append(payload)
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="film.read",
        resource_type="film",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return out

@router.post("/", response_model=FilmOut)
def create_one(request: Request, payload: FilmCreate, db: Session = Depends(get_db), p: Principal = Depends(get_current_principal)):
    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="film.create", resource_type="film",
        resource_id="new", owner_id=None,
        crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}},
    )
    dec = evaluate(pi)
    dh = decision_hash(dec)
    if not dec.allow:
        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="film.create", resource_type="film", resource_id=None,
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
            action="film.create",
            resource_type="film",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    film = create_film(db, tenant_id=p.tenant_id, title=payload.title, time_elapsed=payload.time_elapsed)
    write_audit(
        db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id), subject_role=p.role,
        action="film.create", resource_type="film", resource_id=film.id,
        outcome="allow", decision_hash=dh,
        fields_decrypted=[], fields_masked=[], fields_denied=[],
        details={"title": payload.title},
    )

    # Respond under read policy
    pi_r = build_policy_input(
        db=db, request=request, principal=p,
        action="film.read", resource_type="film",
        resource_id=str(film.id), owner_id=None,
        crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}},
    )
    dec_r = evaluate(pi_r)
    row = {"title": film.title, "time_elapsed_ct": film.time_elapsed_ct}
    applied = apply_decision(decision=dec_r, ciphertext_row=row, field_to_ciphertext={"time_elapsed":"time_elapsed_ct"})
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="film.create",
        resource_type="film",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return {"id": film.id, "title": film.title, "time_elapsed": applied.payload.get("time_elapsed")}

@router.patch("/{film_id}/time", response_model=FilmOut)
def update_time(
    request: Request,
    film_id: UUID,
    time_elapsed: int = Query(..., ge=0),
    db: Session = Depends(get_db),
    p: Principal = Depends(get_current_principal),
):
    pi = build_policy_input(
        db=db, request=request, principal=p,
        action="film.update_time", resource_type="film",
        resource_id=str(film_id), owner_id=None,
        crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}},
    )
    dec = evaluate(pi)
    dh = decision_hash(dec)
    if not dec.allow:
        write_audit(
            db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
            subject_user_id=UUID(p.user_id), subject_role=p.role,
            action="film.update_time", resource_type="film", resource_id=film_id,
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
            action="film.update_time",
            resource_type="film",
            dcs_enabled=dcs_enabled(),
            perf=getattr(request.state, "perf", None),
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    film = update_film_time(db, tenant_id=p.tenant_id, film_id=film_id, time_elapsed=time_elapsed)

    # Respond under read policy
    pi_r = build_policy_input(
        db=db, request=request, principal=p,
        action="film.read", resource_type="film",
        resource_id=str(film.id), owner_id=None,
        crypto_meta={"time_elapsed": {"ciphertext_field": "time_elapsed_ct"}},
    )
    dec_r = evaluate(pi_r)
    row = {"title": film.title, "time_elapsed_ct": film.time_elapsed_ct}
    applied = apply_decision(decision=dec_r, ciphertext_row=row, field_to_ciphertext={"time_elapsed":"time_elapsed_ct"})

    write_audit(
        db=db, request_id=request.state.request_id, tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id), subject_role=p.role,
        action="film.update_time", resource_type="film", resource_id=film_id,
        outcome="allow", decision_hash=dh,
        fields_decrypted=[], fields_masked=[], fields_denied=[],
        details={"new_time_elapsed": time_elapsed},
    )
    write_perf(
        db=db,
        request_id=request.state.request_id,
        tenant_id=p.tenant_id,
        subject_user_id=UUID(p.user_id),
        subject_role=p.role,
        action="film.update_time",
        resource_type="film",
        dcs_enabled=dcs_enabled(),
        perf=getattr(request.state, "perf", None),
    )
    return {"id": film.id, "title": film.title, "time_elapsed": applied.payload.get("time_elapsed")}
