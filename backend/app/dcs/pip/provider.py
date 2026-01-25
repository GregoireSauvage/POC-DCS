from sqlalchemy.orm import Session
from fastapi import Request
from app.core.config import settings
from app.core.security.auth import Principal
from app.dcs.pep.mode import dcs_enabled
from app.dcs.pip.types import Subject, Context, Resource, PolicyInput
from app.dcs.pip.classification import get_classification_map
from app.observability.perf import perf_span

def build_policy_input(
    *,
    db: Session,
    request: Request,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: str,
    owner_id: str | None,
    labels: list[str] | None = None,
    crypto_meta: dict[str, dict] | None = None,
) -> PolicyInput:
    with perf_span("pip_ms"):
        labels = labels or []
        crypto_meta = crypto_meta or {}

        subject = Subject(
            user_id=principal.user_id,
            tenant_id=principal.tenant_id,
            role=principal.role,
            username=principal.username,
        )

        ctx = Context(
            env=settings.ENV,
            channel="web",
            purpose="cinema_ops",
            client_ip=request.headers.get("x-real-ip") or (request.client.host if request.client else None),
            device_trust=0.8,  # PoC constant
            request_id=getattr(request.state, "request_id", "no-request-id"),
        )

        if not dcs_enabled():
            res = Resource(
                type=resource_type,
                id=resource_id,
                owner_id=owner_id,
                tenant_id=principal.tenant_id,
                labels=labels,
                fields={},
            )
            return PolicyInput(subject=subject, action=action, resource=res, context=ctx)

        cls_map = get_classification_map(db, resource_type)

        fields: dict[str, dict] = {}
        for field_name, classification in cls_map.items():
            fields[field_name] = {"classification": classification}
            if field_name in crypto_meta:
                fields[field_name]["crypto"] = crypto_meta[field_name]

        res = Resource(
            type=resource_type,
            id=resource_id,
            owner_id=owner_id,
            tenant_id=principal.tenant_id,
            labels=labels,
            fields=fields,
        )

        return PolicyInput(subject=subject, action=action, resource=res, context=ctx)
