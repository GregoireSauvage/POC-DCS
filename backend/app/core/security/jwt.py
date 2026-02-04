from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings

ALGO = "HS256"


def issue_token(
    *, tenant_id: str, user_id: str, username: str, role: str, scopes: list[str]
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.JWT_TTL_MINUTES)).timestamp()),
        "sub": user_id,
        "tenant_id": tenant_id,
        "username": username,
        "role": role,
        "scopes": scopes,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGO)


def verify_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[ALGO],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
        options={"verify_at_hash": False},
    )
