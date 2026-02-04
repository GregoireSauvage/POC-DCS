from uuid import UUID

from pydantic import BaseModel


class HallCreate(BaseModel):
    name: str
    current_film_id: UUID
    owner_user_id: UUID


class HallOut(BaseModel):
    id: UUID
    name: str | None
    current_film_id: UUID | str | None
    owner_user_id: UUID | str | None
    spectator_count: int | None
