from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Organization, User
from ..security import (
    bearer_token, current_user, dummy_verify, hash_password, issue_token, login_limiter, revoke_token, verify_password,
)
from ..services.common import audit, iso

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", v):
            raise ValueError("Username may contain letters, digits, '.', '_' and '-' only")
        return v.lower()

    @field_validator("password")
    @classmethod
    def _p(cls, v: str) -> str:
        if v.lower() == v or v.upper() == v or not re.search(r"\d", v):
            raise ValueError("Password needs upper- and lower-case letters and a digit")
        return v


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


def user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role, "org_id": u.org_id}


def default_org(db: Session) -> Organization:
    s = get_settings()
    org = db.scalar(select(Organization).order_by(Organization.id).limit(1))
    if org is None:
        org = Organization(name=s.default_organization, slug="default")
        db.add(org)
        db.flush()
    return org


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if not get_settings().allow_self_registration:
        raise HTTPException(403, "Self-registration is disabled; ask an administrator for an account")
    ip = request.client.host if request.client else "unknown"
    if not login_limiter.check(f"register:{ip}", get_settings().login_rate_limit_per_minute):
        raise HTTPException(429, "Too many attempts; wait a minute and try again")
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "Username already taken")
    org = default_org(db)
    u = User(org_id=org.id, username=body.username, display_name=body.display_name,
             password_hash=hash_password(body.password), role="learner")
    db.add(u)
    db.flush()
    audit(db, user_id=u.id, org_id=org.id, action="user.register", target_type="user", target_id=u.id)
    token, exp = issue_token(db, u)
    db.commit()
    return {"token": token, "expires_at": iso(exp), "user": user_out(u)}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    limit = get_settings().login_rate_limit_per_minute
    if not (login_limiter.check(f"login-ip:{ip}", limit * 3) and login_limiter.check(f"login-user:{body.username.lower()}", limit)):
        raise HTTPException(429, "Too many login attempts; wait a minute and try again")
    u = db.scalar(select(User).where(User.username == body.username.lower()))
    if u is None:
        dummy_verify(body.password)
        raise HTTPException(401, "Invalid username or password")
    if not verify_password(body.password, u.password_hash) or not u.is_active:
        audit(db, user_id=u.id, org_id=u.org_id, action="auth.login_failed", target_type="user", target_id=u.id)
        db.commit()
        raise HTTPException(401, "Invalid username or password")
    token, exp = issue_token(db, u)
    audit(db, user_id=u.id, org_id=u.org_id, action="auth.login", target_type="user", target_id=u.id)
    db.commit()
    return {"token": token, "expires_at": iso(exp), "user": user_out(u)}


@router.post("/logout")
def logout(token: str = Depends(bearer_token), user: User = Depends(current_user), db: Session = Depends(get_db)):
    revoke_token(db, token)
    audit(db, user_id=user.id, org_id=user.org_id, action="auth.logout")
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return user_out(user)
