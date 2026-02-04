from sqlalchemy.orm import Session

from app.cache.cache import cache_level_enabled, classification_cache
from app.db.models.field_classification import FieldClassification


def get_classification_map(db: Session, resource_type: str) -> dict[str, str]:
    if cache_level_enabled(1):
        cached = classification_cache.get(resource_type)
        if cached is not None:
            return cached
    rows = (
        db.query(FieldClassification)
        .filter(FieldClassification.resource_type == resource_type)
        .all()
    )
    result = {r.field_name: r.classification for r in rows}
    if cache_level_enabled(1):
        classification_cache.set(resource_type, result)
    return result
