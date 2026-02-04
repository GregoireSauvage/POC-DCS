from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base


class FieldClassification(Base):
    __tablename__ = "field_classification"
    __table_args__ = (
        CheckConstraint(
            "classification IN ('PUBLIC','INTERNAL','PII','SENSITIVE')",
            name="field_classification_check",
        ),
    )

    resource_type: Mapped[str] = mapped_column(String, primary_key=True)
    field_name: Mapped[str] = mapped_column(String, primary_key=True)
    classification: Mapped[str] = mapped_column(String, nullable=False)
