import uuid

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class Film(Base):
    __tablename__ = "films"

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    time_elapsed_ct: Mapped[str] = mapped_column(String, nullable=False)
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
