from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security.jwt import issue_token
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.auth import LoginRequest, LoginResponse

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]):
    # PoC: tenant is fixed to 't1'
    user = (
        db.query(User)
        .filter(User.username == payload.username, User.tenant_id == "t1")
        .one_or_none()
    )
    if user is None or user.password_hash != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    scopes = ["*"] if user.role == "admin" else ["cinema"]
    token = issue_token(
        tenant_id=user.tenant_id,
        user_id=str(user.id),
        username=user.username,
        role=user.role,
        scopes=scopes,
    )
    return LoginResponse(
        access_token=token,
        role=user.role,
        tenant_id=user.tenant_id,
        user_id=str(user.id),
        username=user.username,
    )
