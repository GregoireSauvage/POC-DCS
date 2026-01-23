from sqlalchemy.orm import Session
from uuid import UUID
import uuid as _uuid

from app.db.models.film import Film
from app.db.models.hall import Hall
from app.db.models.spectator import Spectator
from app.dcs.kms.vault_transit import VaultClient
from app.dcs.crypto.lookup import normalize_external_id, hmac_lookup

vault = VaultClient()

def create_film(db: Session, *, tenant_id: str, title: str, time_elapsed: int) -> Film:
    film = Film(
        tenant_id=tenant_id,
        id=_uuid.uuid4(),
        title=title,
        time_elapsed_ct=vault.encrypt(str(time_elapsed)),
        labels=[],
    )
    db.add(film)
    db.commit()
    db.refresh(film)
    return film

def create_hall(db: Session, *, tenant_id: str, name: str, owner_user_id: UUID, current_film_id: UUID) -> Hall:
    hall = Hall(
        tenant_id=tenant_id,
        id=_uuid.uuid4(),
        name=name,
        owner_user_id=owner_user_id,
        current_film_id=current_film_id,
        labels=[],
    )
    db.add(hall)
    db.commit()
    db.refresh(hall)
    return hall

def add_spectator(db: Session, *, tenant_id: str, hall_id: UUID, name: str, age: int, external_id: str) -> Spectator:
    pepper = vault.get_pepper()
    lookup = hmac_lookup(pepper, normalize_external_id(external_id))
    sp = Spectator(
        tenant_id=tenant_id,
        id=_uuid.uuid4(),
        hall_id=hall_id,
        name_ct=vault.encrypt(name),
        age_ct=vault.encrypt(str(age)),
        external_id_ct=vault.encrypt(external_id),
        external_id_lookup=lookup,
        labels=[],
    )
    db.add(sp)
    db.commit()
    db.refresh(sp)
    return sp

def update_film_time(db: Session, *, tenant_id: str, film_id: UUID, time_elapsed: int) -> Film:
    film = db.query(Film).filter(Film.tenant_id == tenant_id, Film.id == film_id).one()
    film.time_elapsed_ct = vault.encrypt(str(time_elapsed))
    db.add(film)
    db.commit()
    db.refresh(film)
    return film
