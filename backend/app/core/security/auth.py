from dataclasses import dataclass
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.security.jwt import verify_token

bearer = HTTPBearer(auto_error=False)

@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str
    username: str
    role: str
    scopes: list[str]

def get_current_principal(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> Principal:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")
    try:
        payload = verify_token(creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    return Principal(
        tenant_id=payload["tenant_id"],
        user_id=payload["sub"],
        username=payload.get("username", ""),
        role=payload.get("role", "developer"),
        scopes=payload.get("scopes", []),
    )

def require_role(*roles: str):
    def _dep(p: Principal = Depends(get_current_principal)) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return p
    return _dep
