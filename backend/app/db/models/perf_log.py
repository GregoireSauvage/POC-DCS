import uuid

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class PerfLog(Base):
    __tablename__ = "perf_logs"

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
    dcs_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    cache_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    total_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    pip_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    pdp_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    kms_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    db_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
