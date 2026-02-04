from dataclasses import dataclass
from typing import Literal

FieldAction = Literal["allow", "decrypt", "mask_after_decrypt", "deny"]


@dataclass(frozen=True)
class Decision:
    allow: bool
    field_actions: dict[str, FieldAction]
    reason: str = ""
