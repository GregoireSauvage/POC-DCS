import uuid

from sqlalchemy import DateTime, ForeignKeyConstraint, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class Spectator(Base):
    __tablename__ = "spectators"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "hall_id"], ["halls.tenant_id", "halls.id"]),
        Index("idx_spectators_hall", "tenant_id", "hall_id"),
        UniqueConstraint("tenant_id", "external_id_lookup", name="uq_spectators_lookup"),
    )

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)

    hall_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    name_ct: Mapped[str] = mapped_column(String, nullable=False)
    age_ct: Mapped[str] = mapped_column(String, nullable=False)
    external_id_ct: Mapped[str] = mapped_column(String, nullable=False)

    external_id_lookup: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
