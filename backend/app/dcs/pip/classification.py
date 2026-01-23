from sqlalchemy.orm import Session
from app.db.models.field_classification import FieldClassification

def get_classification_map(db: Session, resource_type: str) -> dict[str, str]:
    rows = db.query(FieldClassification).filter(FieldClassification.resource_type == resource_type).all()
    return {r.field_name: r.classification for r in rows}
