import uuid

from sqlalchemy import BigInteger, CheckConstraint, DateTime, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("outcome IN ('allow','deny','error')", name="audit_outcome_check"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    request_id: Mapped[str] = mapped_column(String, nullable=False)

    tenant_id: Mapped[str] = mapped_column(String, nullable=False)
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    subject_role: Mapped[str | None] = mapped_column(String, nullable=True)

    action: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    outcome: Mapped[str] = mapped_column(String, nullable=False)
    decision_hash: Mapped[str | None] = mapped_column(String, nullable=True)

    fields_decrypted: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    fields_masked: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    fields_denied: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)

    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
