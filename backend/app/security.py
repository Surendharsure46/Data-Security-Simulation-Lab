"""Authentication: password hashing, opaque bearer tokens, rate limiting, role checks.

* Passwords: PBKDF2-HMAC-SHA256 (stdlib), per-user random salt, configurable iterations.
* Tokens: 256-bit random values returned once to the client; only their SHA-256
  hash is stored. Tokens are sent in the ``Authorization: Bearer`` header (never in
  cookies), so cross-site request forgery does not apply to the API.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuthToken, User
from .services.common import as_utc


def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or get_settings().password_hash_iterations
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# A fixed dummy hash so failed lookups take comparable time to real verifications.
_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-for-timing")
    verify_password(password, _DUMMY_HASH)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(db: Session, user: User) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=get_settings().token_ttl_hours)
    db.add(AuthToken(user_id=user.id, token_hash=_token_hash(token), expires_at=expires))
    return token, expires


def revoke_token(db: Session, token: str) -> None:
    t = db.scalar(select(AuthToken).where(AuthToken.token_hash == _token_hash(token)))
    if t:
        t.revoked = True


class RateLimiter:
    """In-memory sliding-window limiter (single-process deployments)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


login_limiter = RateLimiter()

_UNAUTH = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required",
                        headers={"WWW-Authenticate": "Bearer"})


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _UNAUTH
    return authorization.split(" ", 1)[1].strip()


def current_user(token: str = Depends(bearer_token), db: Session = Depends(get_db)) -> User:
    t = db.scalar(select(AuthToken).where(AuthToken.token_hash == _token_hash(token)))
    if t is None or t.revoked or as_utc(t.expires_at) < datetime.now(timezone.utc):
        raise _UNAUTH
    user = db.get(User, t.user_id)
    if user is None or not user.is_active:
        raise _UNAUTH
    return user


def require_role(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation")
        return user

    return dep
