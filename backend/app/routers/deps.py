"""Shared API dependencies and serializers.

Serializers deliberately omit internal fields (``step_key``) that would reveal which
timeline step - and therefore which ground-truth role - an event or alert belongs to.
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Alert, ScenarioSession, SecurityEvent, User
from ..security import current_user
from ..services.common import iso

STAFF_ROLES = ("instructor", "admin")


def load_session(db: Session, session_id: int, user: User, *, write: bool) -> ScenarioSession:
    s = db.get(ScenarioSession, session_id)
    # 404 (not 403) for sessions the caller may not see, so IDs cannot be enumerated.
    if s is None or s.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="Session not found")
    is_owner = s.user_id == user.id
    if not is_owner and user.role not in STAFF_ROLES:
        raise HTTPException(status_code=404, detail="Session not found")
    if write:
        if not is_owner:
            raise HTTPException(status_code=403, detail="Only the session owner can change a session")
        if s.status != "ACTIVE":
            raise HTTPException(status_code=409, detail=f"Session is {s.status}; resume it (or reset after submission) to make changes")
    return s


def read_session(session_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)) -> ScenarioSession:
    return load_session(db, session_id, user, write=False)


def write_session(session_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)) -> ScenarioSession:
    return load_session(db, session_id, user, write=True)


def event_out(e: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": e.event_id, "timestamp": iso(e.timestamp), "organization_id": e.organization_id,
        "scenario_id": e.scenario_id, "scenario_session_id": e.session_id, "run_number": e.run_number,
        "actor_id": e.actor_id, "resource_id": e.resource_id, "action": e.action, "result": e.result,
        "data_classification": e.data_classification, "source_type": e.source_type, "source_system": e.source_system,
        "provenance": e.provenance, "policy_id": e.policy_id, "policy_version": e.policy_version,
        "destination": e.destination, "transaction_id": e.transaction_id, "related_event_ids": e.related_event_ids or [],
        "evidence_refs": e.evidence_refs or [], "summary": e.summary, "extension": e.extension or {},
    }


def alert_out(a: Alert) -> dict[str, Any]:
    return {
        "alert_id": a.alert_id, "run_number": a.run_number, "title": a.title, "severity": a.severity, "status": a.status,
        "disposition": a.disposition, "disposition_note": a.disposition_note, "policy_id": a.policy_id,
        "policy_version": a.policy_version, "triggering_event_id": a.triggering_event_id, "event_ids": a.event_ids or [],
        "actor_id": a.actor_id, "resource_id": a.resource_id, "explanation": a.explanation, "timestamp": iso(a.timestamp),
        "provenance": "SIMULATED",
    }
