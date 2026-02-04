import uuid

from sqlalchemy import CheckConstraint, DateTime, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('developer','agent','admin')", name="users_role_check"),
        UniqueConstraint("tenant_id", "username", name="users_tenant_username_uq"),
    )

    tenant_id: Mapped[str] = mapped_column(String, primary_key=True)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    username: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    labels: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
