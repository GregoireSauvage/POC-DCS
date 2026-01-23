from pydantic import BaseModel
from uuid import UUID

class FilmCreate(BaseModel):
    title: str
    time_elapsed: int = 0

class FilmOut(BaseModel):
    id: UUID
    title: str
    time_elapsed: int | str | None  # can be masked
