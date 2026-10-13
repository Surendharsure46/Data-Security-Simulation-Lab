"""Hands-on labs. Each lab keeps per-user state in ``LabState`` and records exercise
results in ``LabExerciseResult`` with explicit provenance (REAL_LAB or SIMULATED)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import LabExerciseResult, LabState, User


def lab_dir(user: User, lab: str) -> Path:
    """Per-user lab directory built only from server-side identifiers.

    The suffix (hash of username and creation time) prevents a recreated database that
    reuses numeric ids from handing one user another user's leftover lab files.
    """
    import hashlib

    tag = hashlib.sha256(f"{user.username}|{user.created_at.isoformat()}".encode()).hexdigest()[:12]
    d = Path(get_settings().lab_data_dir) / f"user-{int(user.id)}-{tag}" / lab
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_state(db: Session, user: User, lab: str, default: dict[str, Any]) -> LabState:
    """Get-or-create, safe against two concurrent first requests (unique user_id + lab)."""
    st = db.scalar(select(LabState).where(LabState.user_id == user.id, LabState.lab == lab))
    if st is None:
        try:
            with db.begin_nested():
                st = LabState(user_id=user.id, lab=lab, state=default)
                db.add(st)
        except IntegrityError:
            st = db.scalar(select(LabState).where(LabState.user_id == user.id, LabState.lab == lab))
    return st


def set_state(st: LabState, **changes: Any) -> None:
    st.state = {**(st.state or {}), **changes}


def record_result(db: Session, user: User, lab: str, exercise: str, passed: bool, provenance: str, detail: dict[str, Any]) -> None:
    db.add(LabExerciseResult(user_id=user.id, lab=lab, exercise=exercise, passed=passed, provenance=provenance, detail=detail))


def passed_exercises(db: Session, user: User, lab: str) -> set[str]:
    return {r.exercise for r in db.scalars(select(LabExerciseResult).where(
        LabExerciseResult.user_id == user.id, LabExerciseResult.lab == lab, LabExerciseResult.passed.is_(True)))}
