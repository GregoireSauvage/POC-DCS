import uuid

from sqlalchemy import DateTime, ForeignKeyConstraint, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class Hall(Base):
    __tablename__ = "halls"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "owner_user_id"], ["users.tenant_id", "users.id"]),
        ForeignKeyConstraint(["tenant_id", "current_film_id"], ["films.tenant_id", "films.id"]),
        Index("idx_halls_owner", "tenant_id", "owner_user_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    current_film_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
