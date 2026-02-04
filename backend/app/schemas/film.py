from uuid import UUID

from pydantic import BaseModel


class FilmCreate(BaseModel):
    title: str
    time_elapsed: int = 0


class FilmOut(BaseModel):
    id: UUID
    title: str
    time_elapsed: int | str | None  # can be masked
