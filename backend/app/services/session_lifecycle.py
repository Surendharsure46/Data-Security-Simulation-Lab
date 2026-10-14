"""Scenario-session creation and submission shared by the scenario API and the mission workflow."""
from __future__ import annotations

import secrets
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AssessmentAttempt, MissionAttempt, ScenarioSession, User
from . import assessment, reports
from .common import DomainError, audit
from .scenario_defs import get_definition
from .simulation import provision_environment, record_action


def start_time(d) -> datetime:
    return datetime.fromisoformat(d.sim_start.replace("Z", "+00:00"))


def start_scenario_session(db: Session, user: User, scenario_id: str, mode: str, variant: str | None = None, *,
                           exclude_variant: str | None = None) -> ScenarioSession:
    """Provision a new session. Independent assessments always get an unpredictable variant unless the
    caller asks for one *different* from a previous attempt (``exclude_variant``)."""
    d = get_definition(scenario_id)
    if d is None:
        raise DomainError("Scenario not found", 404)
    keys = [v.key for v in d.variants]
    if exclude_variant is not None:
        choices = [k for k in keys if k != exclude_variant] or keys
        variant = secrets.choice(choices)
    elif mode == "ASSESSMENT" or variant is None:
        variant = secrets.choice(keys)
    elif variant not in keys:
        raise DomainError(f"Unknown variant; available: {keys}", 422)
    s = ScenarioSession(user_id=user.id, org_id=user.org_id, scenario_id=d.id, scenario_version=d.version, variant=variant,
                        mode=mode, status="ACTIVE", sim_clock=start_time(d), flags={}, hints_used={})
    db.add(s)
    db.flush()
    provision_environment(db, s)
    record_action(db, s, "SESSION_START", {"mode": mode})
    audit(db, user_id=user.id, org_id=user.org_id, action="session.start", target_type="session", target_id=s.id,
          detail={"scenario": d.id, "mode": mode})
    return s


def submit_scenario_session(db: Session, s: ScenarioSession, user: User) -> AssessmentAttempt:
    """Grade the session on the server, store the attempt with a report snapshot and lock the session."""
    snapshot = reports.to_markdown(reports.build(db, s, "case-report"))
    attempt = assessment.submit(db, s, user.id, snapshot)
    s.status = "SUBMITTED"
    record_action(db, s, "SUBMIT", {}, {"attempt_id": attempt.id, "score": attempt.total_score})
    audit(db, user_id=user.id, org_id=user.org_id, action="assessment.submit", target_type="session", target_id=s.id,
          detail={"score": attempt.total_score, "passed": attempt.passed})
    return attempt


def mission_attempt_for_session(db: Session, session_id: int) -> MissionAttempt | None:
    return db.scalar(select(MissionAttempt).where(MissionAttempt.session_id == session_id)
                     .order_by(MissionAttempt.id.desc()).limit(1))
