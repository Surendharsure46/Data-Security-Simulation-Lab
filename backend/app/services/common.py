"""Shared helpers: time handling, audit records, errors."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditRecord


class DomainError(Exception):
    """Business-rule violation; mapped to HTTP 400/409 by the API layer."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; every stored timestamp is UTC by convention."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    d = as_utc(dt)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def audit(db: Session, *, user_id: int | None, org_id: int | None, action: str,
          target_type: str | None = None, target_id: Any = None, detail: dict[str, Any] | None = None) -> None:
    db.add(AuditRecord(
        user_id=user_id, org_id=org_id, action=action, target_type=target_type,
        target_id=None if target_id is None else str(target_id), detail=detail or {},
    ))
