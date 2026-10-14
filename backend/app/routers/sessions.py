"""Scenario catalogue, session lifecycle, timeline execution, assessment and reports."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    AccessGrant, Alert, AssessmentAttempt, CaseNote, ChangeRecord, ClassificationAssignment, ClassificationFinding,
    ClassificationLabel, ClassificationRule, DataAsset, Destination, DiscoveryScan, EvidenceReference, InvestigationCase,
    Policy, PolicyEvaluation, PolicyTestRun, PolicyVersion, RemediationAction, ScenarioAction, ScenarioSession,
    SecurityEvent, SimGroup, SimIdentity, User,
)
from ..security import current_user
from ..services import assessment, reports
from ..services.common import audit, iso
from ..services.scenario_defs import all_definitions, get_definition, public_view
from ..services.session_lifecycle import (
    mission_attempt_for_session, start_scenario_session, start_time, submit_scenario_session,
)
from ..services.simulation import advance_clock, execute_activity, provision_environment, record_action, run_timeline
from .deps import STAFF_ROLES, alert_out, event_out, load_session, read_session, write_session

router = APIRouter(prefix="/api", tags=["scenarios"])


@router.get("/scenarios")
def list_scenarios(user: User = Depends(current_user)):
    return [public_view(d) for d in all_definitions().values()]


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str, user: User = Depends(current_user)):
    d = get_definition(scenario_id)
    if d is None:
        raise HTTPException(404, "Scenario not found")
    return public_view(d)


class StartIn(BaseModel):
    scenario_id: str
    mode: Literal["GUIDED", "ASSESSMENT"] = "GUIDED"
    variant: str | None = Field(default=None, max_length=10)


def session_summary(db: Session, s: ScenarioSession, *, detail: bool = False) -> dict[str, Any]:
    d = get_definition(s.scenario_id)
    out: dict[str, Any] = {
        "id": s.id, "scenario_id": s.scenario_id, "scenario_title": d.title if d else s.scenario_id,
        "scenario_version": s.scenario_version, "mode": s.mode, "status": s.status, "attempt_number": s.attempt_number,
        "sim_clock": iso(s.sim_clock), "run_count": s.run_count, "created_at": iso(s.created_at), "updated_at": iso(s.updated_at),
        "user_id": s.user_id, "execution_mode": "SIMULATED",
    }
    m = mission_attempt_for_session(db, s.id)
    out["mission"] = {"attempt_id": m.id, "mission_id": m.mission_id, "status": m.status} if m else None
    if detail:
        progress = assessment.task_progress(db, s)
        out["progress"] = progress
        out["progress_percent"] = round(100 * sum(t["done"] for t in progress) / max(1, len(progress)))
        out["scenario"] = public_view(d) if d else None
        out["runs"] = (s.flags or {}).get("runs", [])
        out["counts"] = {
            "events": db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.session_id == s.id)) or 0,
            "alerts": db.scalar(select(func.count(Alert.id)).where(Alert.session_id == s.id)) or 0,
            "open_alerts": db.scalar(select(func.count(Alert.id)).where(Alert.session_id == s.id, Alert.disposition.is_(None))) or 0,
            "cases": db.scalar(select(func.count(InvestigationCase.id)).where(InvestigationCase.session_id == s.id)) or 0,
            "policies": db.scalar(select(func.count(Policy.id)).where(Policy.session_id == s.id)) or 0,
            "unlabeled_assets": db.scalar(select(func.count(DataAsset.id)).where(DataAsset.session_id == s.id, DataAsset.label_key.is_(None))) or 0,
            "remediations": db.scalar(select(func.count(RemediationAction.id)).where(RemediationAction.session_id == s.id)) or 0,
        }
        out["hints_enabled"] = s.mode == "GUIDED"
        out["hints_used"] = s.hints_used or {}
        latest = db.scalar(select(AssessmentAttempt).where(AssessmentAttempt.session_id == s.id).order_by(AssessmentAttempt.id.desc()).limit(1))
        out["latest_attempt"] = attempt_out(latest) if latest else None
    return out


@router.post("/sessions", status_code=201)
def start_session(body: StartIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = start_scenario_session(db, user, body.scenario_id, body.mode, body.variant)
    db.commit()
    return session_summary(db, s, detail=True)


@router.get("/sessions")
def list_sessions(all_users: bool = False, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(ScenarioSession).where(ScenarioSession.org_id == user.org_id)
    if not (all_users and user.role in STAFF_ROLES):
        q = q.where(ScenarioSession.user_id == user.id)
    return [session_summary(db, s) for s in db.scalars(q.order_by(ScenarioSession.updated_at.desc()))]


@router.get("/sessions/{session_id}")
def get_session(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return session_summary(db, s, detail=True)


def _owner_or_404(db: Session, session_id: int, user: User) -> ScenarioSession:
    s = load_session(db, session_id, user, write=False)
    if s.user_id != user.id:
        raise HTTPException(403, "Only the session owner can change a session")
    return s


@router.post("/sessions/{session_id}/pause")
def pause(session_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _owner_or_404(db, session_id, user)
    if s.status != "ACTIVE":
        raise HTTPException(409, f"Cannot pause a {s.status} session")
    s.status = "PAUSED"
    record_action(db, s, "SESSION_PAUSE", {})
    db.commit()
    return session_summary(db, s)


@router.post("/sessions/{session_id}/resume")
def resume(session_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _owner_or_404(db, session_id, user)
    if s.status != "PAUSED":
        raise HTTPException(409, f"Cannot resume a {s.status} session")
    s.status = "ACTIVE"
    record_action(db, s, "SESSION_RESUME", {})
    db.commit()
    return session_summary(db, s)


class ResetIn(BaseModel):
    new_variant: bool = True
    confirm: bool = False


def _wipe(db: Session, sid: int) -> None:
    case_ids = select(InvestigationCase.id).where(InvestigationCase.session_id == sid)
    db.execute(delete(CaseNote).where(CaseNote.case_id.in_(case_ids)))
    db.execute(delete(EvidenceReference).where(EvidenceReference.case_id.in_(case_ids)))
    db.execute(delete(RemediationAction).where(RemediationAction.session_id == sid))
    db.execute(delete(InvestigationCase).where(InvestigationCase.session_id == sid))
    db.execute(delete(ChangeRecord).where(ChangeRecord.session_id == sid))
    pol_ids = select(Policy.id).where(Policy.session_id == sid)
    db.execute(delete(PolicyVersion).where(PolicyVersion.policy_id.in_(pol_ids)))
    for model in (PolicyTestRun, Policy, PolicyEvaluation, Alert, SecurityEvent, ClassificationFinding, DiscoveryScan,
                  ClassificationAssignment, ClassificationRule, ClassificationLabel, AccessGrant, Destination, DataAsset,
                  SimGroup, SimIdentity, ScenarioAction):
        db.execute(delete(model).where(model.session_id == sid))


@router.post("/sessions/{session_id}/reset")
def reset(session_id: int, body: ResetIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Discard all simulated state and start a new attempt. Submitted assessment attempts are kept."""
    s = _owner_or_404(db, session_id, user)
    if not body.confirm:
        raise HTTPException(409, "Reset discards all work in this session (submitted attempts are kept). Resubmit with confirm=true.")
    if mission_attempt_for_session(db, s.id) is not None:
        raise HTTPException(409, "This session belongs to a mission. Use 'Retry with practice or new variant' in the mission view.")
    d = get_definition(s.scenario_id)
    from .curriculum import remember_completed_tasks
    remember_completed_tasks(db, user)
    _wipe(db, s.id)
    db.flush()
    if body.new_variant and len(d.variants) > 1:
        keys = [v.key for v in d.variants]
        s.variant = keys[(keys.index(s.variant) + 1) % len(keys)] if s.variant in keys else keys[0]
    s.attempt_number += 1
    s.status = "ACTIVE"
    s.run_count = 0
    s.event_seq = 0
    s.flags = {}
    s.hints_used = {}
    s.sim_clock = start_time(d)
    s.scenario_version = d.version
    provision_environment(db, s)
    record_action(db, s, "SESSION_RESET", {"attempt": s.attempt_number})
    audit(db, user_id=user.id, org_id=user.org_id, action="session.reset", target_type="session", target_id=s.id)
    db.commit()
    return session_summary(db, s, detail=True)


@router.post("/sessions/{session_id}/hints/{task_key}")
def reveal_hint(task_key: str, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    if s.mode != "GUIDED":
        raise HTTPException(403, "Hints are disabled in independent assessment mode")
    d = get_definition(s.scenario_id)
    hints = d.hints.get(task_key)
    if hints is None:
        raise HTTPException(404, "No hints for this task")
    used = dict(s.hints_used or {})
    revealed = list(used.get(task_key, []))
    if len(revealed) < len(hints):
        revealed.append(len(revealed))
        used[task_key] = revealed
        s.hints_used = used
        record_action(db, s, "HINT", {"task": task_key, "index": revealed[-1]})
        db.commit()
    return {"task": task_key, "hints": [hints[i] for i in revealed], "remaining": len(hints) - len(revealed)}


@router.get("/sessions/{session_id}/hints")
def revealed_hints(s: ScenarioSession = Depends(read_session)):
    d = get_definition(s.scenario_id)
    return {k: [d.hints[k][i] for i in v] for k, v in (s.hints_used or {}).items() if k in d.hints}


class RunIn(BaseModel):
    mode: Literal["standard", "validation"] = "standard"


@router.post("/sessions/{session_id}/timeline/run")
def run(body: RunIn, s: ScenarioSession = Depends(write_session), user: User = Depends(current_user), db: Session = Depends(get_db)):
    result = run_timeline(db, s, body.mode)
    audit(db, user_id=user.id, org_id=user.org_id, action="session.run_timeline", target_type="session", target_id=s.id, detail=result)
    db.commit()
    return result


class ActivityIn(BaseModel):
    actor: str = Field(max_length=60)
    action: Literal["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT", "SIGN_IN"]
    resource: str | None = Field(default=None, max_length=60)
    destination: str | None = Field(default=None, max_length=60)
    record_count: int | None = Field(default=None, ge=0, le=10_000_000)
    business_justification: str | None = Field(default=None, max_length=300)
    ticket_id: str | None = Field(default=None, max_length=40)


@router.post("/sessions/{session_id}/activities")
def simulate_activity(body: ActivityIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    """Controlled synthetic event generator: run one activity through all live controls."""
    ts = advance_clock(s)
    spec = {"actor": body.actor, "action": body.action, "resource": body.resource, "destination": body.destination,
            "record_count": body.record_count,
            "context": {"business_justification": body.business_justification, "ticket_id": body.ticket_id, "device_managed": True}}
    res = execute_activity(db, s, spec, timestamp=ts, run_number=0, learner_initiated=True)
    record_action(db, s, "ACTIVITY", {k: v for k, v in spec.items() if v is not None}, {"outcome": res["outcome"]})
    db.commit()
    return {"outcome": res["outcome"], "reason": res["reason"], "transaction_id": res["transaction_id"],
            "decision": res.get("decision"), "policy_trace": res.get("entries", []),
            "events": [event_out(e) for e in res["events"]], "alerts": [alert_out(a) for a in res["alerts"]]}


@router.get("/sessions/{session_id}/actions")
def action_log(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"seq": a.seq, "action_type": a.action_type, "params": a.params, "result": a.result, "provenance": a.provenance,
             "sim_time": iso(a.sim_time), "created_at": iso(a.created_at)}
            for a in db.scalars(select(ScenarioAction).where(ScenarioAction.session_id == s.id).order_by(ScenarioAction.seq))]


# --------------------------------------------------------------------------- assessment


def attempt_out(a: AssessmentAttempt) -> dict[str, Any]:
    return {"id": a.id, "session_id": a.session_id, "scenario_id": a.scenario_id, "attempt_number": a.attempt_number,
            "mode": a.mode, "rubric_version": a.rubric_version, "total_score": a.total_score, "passed": a.passed,
            "category_scores": a.category_scores, "criteria": a.criteria, "critical_failures": a.critical_failures,
            "missing_tasks": a.missing_tasks, "recommendations": a.recommendations, "inputs_digest": a.inputs_digest,
            "submitted_at": iso(a.submitted_at),
            "label": "Guided practice result" if a.mode == "GUIDED" else "Independent assessment result",
            "disclaimer": "Platform assessment outcome for the tasks in this scenario only. Not a professional certification."}


class SubmitIn(BaseModel):
    confirm: bool = False


@router.post("/sessions/{session_id}/submit")
def submit(body: SubmitIn, s: ScenarioSession = Depends(write_session), user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not body.confirm:
        raise HTTPException(409, "Submission locks the session for grading. Resubmit with confirm=true.")
    if mission_attempt_for_session(db, s.id) is not None:
        raise HTTPException(409, "This session belongs to a mission. Submit your evidence and explanation from the mission view.")
    attempt = submit_scenario_session(db, s, user)
    db.commit()
    return attempt_out(attempt)


@router.get("/sessions/{session_id}/attempts")
def attempts(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [attempt_out(a) for a in db.scalars(select(AssessmentAttempt).where(AssessmentAttempt.session_id == s.id).order_by(AssessmentAttempt.id))]


@router.get("/attempts")
def my_attempts(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [attempt_out(a) for a in db.scalars(select(AssessmentAttempt).where(AssessmentAttempt.user_id == user.id).order_by(AssessmentAttempt.id.desc()))]


# --------------------------------------------------------------------------- reports


@router.get("/sessions/{session_id}/reports")
def report_types(s: ScenarioSession = Depends(read_session)):
    return [{"type": k, "title": v, "formats": ["md", "html", "json"] + (["csv"] if k in reports.TABULAR else [])}
            for k, v in reports.REPORT_TYPES.items()]


@router.get("/sessions/{session_id}/reports/{report_type}")
def report(report_type: str, format: Literal["md", "html", "json", "csv"] = Query("md"), download: bool = False,
           s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    rep = reports.build(db, s, report_type)
    fname = f"threatready-{report_type}-session{s.id}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{fname}"'} if download else {}
    if format == "json":
        return JSONResponse(rep, headers=headers)
    if format == "csv":
        return PlainTextResponse(reports.to_csv(rep), media_type="text/csv; charset=utf-8", headers=headers)
    if format == "html":
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        return Response(reports.to_html(rep), media_type="text/html; charset=utf-8", headers=headers)
    return PlainTextResponse(reports.to_markdown(rep), media_type="text/markdown; charset=utf-8", headers=headers)


@router.get("/attempts/{attempt_id}/report")
def attempt_report(attempt_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(AssessmentAttempt, attempt_id)
    if a is None:
        raise HTTPException(404, "Attempt not found")
    load_session(db, a.session_id, user, write=False)
    return PlainTextResponse(a.report_snapshot, media_type="text/markdown; charset=utf-8")
