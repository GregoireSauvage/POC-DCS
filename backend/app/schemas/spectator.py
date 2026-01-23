from pydantic import BaseModel
from uuid import UUID

class SpectatorCreate(BaseModel):
    hall_id: UUID
    name: str
    age: int
    external_id: str  # ticket id

class SpectatorOut(BaseModel):
    id: UUID | str
    hall_id: UUID
    name: str | None
    age: int | str | None
    external_id: str | None
