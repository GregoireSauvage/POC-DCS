from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AuditOut(BaseModel):
    ts: datetime
    request_id: str
    tenant_id: str
    subject_user_id: UUID | None
    subject_role: str | None
    action: str
    resource_type: str
    resource_id: UUID | None
    outcome: str
    fields_decrypted: list[str]
    fields_masked: list[str]
    fields_denied: list[str]
