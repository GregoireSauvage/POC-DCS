from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models.audit_log import AuditLog


def write_audit(
    *,
    db: Session,
    request_id: str,
    tenant_id: str,
    subject_user_id: UUID | None,
    subject_role: str | None,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    outcome: str,
    decision_hash: str | None,
    fields_decrypted: list[str],
    fields_masked: list[str],
    fields_denied: list[str],
    details: dict | None,
):
    row = AuditLog(
        request_id=request_id,
        tenant_id=tenant_id,
        subject_user_id=subject_user_id,
        subject_role=subject_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        decision_hash=decision_hash,
        fields_decrypted=fields_decrypted,
        fields_masked=fields_masked,
        fields_denied=fields_denied,
        details=details or {},
    )
    db.add(row)
    db.commit()
