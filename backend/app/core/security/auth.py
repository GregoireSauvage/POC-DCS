from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security.jwt import verify_token
from app.db.models.user import User
from app.db.session import get_db

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str
    username: str
    role: str
    scopes: list[str]


def get_current_principal(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")
    try:
        payload = verify_token(creds.credentials)
    except Exception as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err
    try:
        tenant_id = payload["tenant_id"]
        user_id = UUID(payload["sub"])
    except Exception as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err

    user = db.query(User).filter(User.tenant_id == tenant_id, User.id == user_id).one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Token user not found")
    return Principal(
        tenant_id=user.tenant_id,
        user_id=str(user.id),
        username=user.username,
        role=user.role,
        scopes=payload.get("scopes", []),
    )


def require_role(*roles: str):
    def _dep(p: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return p

    return _dep
