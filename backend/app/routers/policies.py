"""DLP Policy Studio and Data Security Engineering endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ChangeRecord, PolicyEvaluation, PolicyTestRun, ScenarioSession, User
from ..security import current_user
from ..services import policies as svc
from ..services.common import iso
from ..services.policy_engine import FIELDS, PolicyDefinition
from ..services.simulation import definition_for
from .deps import read_session, write_session

router = APIRouter(prefix="/api/sessions/{session_id}/policies", tags=["policies"])


@router.get("/language")
def language(s: ScenarioSession = Depends(read_session)):
    return {
        "fields": FIELDS,
        "operators": ["eq", "neq", "in", "not_in", "contains_any", "contains_all", "contains_none", "gt", "gte", "lt", "lte",
                      "exists", "not_exists", "label_at_least", "label_below"],
        "outcomes": ["ALLOW", "MONITOR", "WARN", "BLOCK"],
        "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "actions": ["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"],
        "precedence": [
            "Disabled policies are skipped.",
            "A policy matches when its action scope and condition group are true; missing fields make a condition false.",
            "The first matching exception replaces the outcome with ALLOW or MONITOR and suppresses the alert unless keep_alert is set.",
            "The final DLP decision is the most restrictive outcome: BLOCK > WARN > MONITOR > ALLOW; ties break on priority then key.",
            "Detection policies only MONITOR and raise alerts; they never enforce.",
            "If nothing matches the activity is allowed.",
        ],
        "schema": PolicyDefinition.model_json_schema(),
    }


@router.get("")
def list_policies(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    from ..models import Policy
    return [svc.serialize_policy(p) for p in db.scalars(select(Policy).where(Policy.session_id == s.id).order_by(Policy.key))]


class PolicyIn(BaseModel):
    key: str = Field(max_length=44)
    definition: dict[str, Any]
    change_note: str = Field(default="", max_length=500)


@router.post("", status_code=201)
def create(body: PolicyIn, user: User = Depends(current_user), s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    p = svc.create_policy(db, s, user.username, body.key, body.definition, body.change_note)
    db.commit()
    return svc.serialize_policy(p)


@router.get("/{key}")
def get(key: str, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    p = svc.get_policy(db, s, key)
    out = svc.serialize_policy(p)
    out["version_definitions"] = {v.version: v.definition for v in p.versions}
    return out


class UpdateIn(BaseModel):
    definition: dict[str, Any]
    change_note: str = Field(min_length=3, max_length=500)


@router.put("/{key}")
def update(key: str, body: UpdateIn, user: User = Depends(current_user), s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    v = svc.update_policy(db, s, user.username, key, body.definition, body.change_note)
    db.commit()
    return {"key": key, "version": v.version, "policy": svc.serialize_policy(svc.get_policy(db, s, key))}


class StatusIn(BaseModel):
    status: str


@router.post("/{key}/status")
def status(key: str, body: StatusIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    p = svc.set_status(db, s, key, body.status)
    db.commit()
    return svc.serialize_policy(p)


class RollbackIn(BaseModel):
    to_version: int = Field(ge=1)


@router.post("/{key}/rollback")
def rollback(key: str, body: RollbackIn, user: User = Depends(current_user), s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    v = svc.rollback(db, s, user.username, key, body.to_version)
    db.commit()
    return {"key": key, "version": v.version}


@router.get("/{key}/diff")
def diff(key: str, a: int, b: int, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return {"key": key, "from_version": a, "to_version": b, "changes": svc.diff(db, s, key, a, b)}


class TestIn(BaseModel):
    actor: str = Field(max_length=60)
    action: str = Field(max_length=20)
    resource: str = Field(max_length=60)
    destination: str | None = Field(default=None, max_length=60)
    record_count: int | None = Field(default=None, ge=0, le=10_000_000)
    hour: int = Field(default=12, ge=0, le=23)
    context: dict[str, Any] = Field(default_factory=dict)
    draft: dict[str, Any] | None = None  # {"key": ..., "definition": {...}} to preview an unsaved edit


@router.post("/test")
def test(body: TestIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    ctx = {k: v for k, v in body.context.items() if k in ("business_justification", "ticket_id", "device_managed")}
    res = svc.dry_run(db, s, {"actor": body.actor, "action": body.action, "resource": body.resource, "destination": body.destination,
                              "record_count": body.record_count, "hour": body.hour, "context": ctx}, candidate=body.draft)
    db.commit()
    return res


@router.post("/{key}/test-cases/run")
def run_embedded_cases(key: str, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    """Run the test cases embedded in a policy definition against the current policy set."""
    p = svc.get_policy(db, s, key)
    cur = next(v for v in p.versions if v.version == p.current_version)
    cases = PolicyDefinition.model_validate(cur.definition).test_cases
    if not cases:
        raise HTTPException(404, "This policy version has no embedded test cases")
    out = []
    for tc in cases:
        res = svc.dry_run(db, s, {"actor": tc.actor, "action": tc.action, "resource": tc.resource, "destination": tc.destination,
                                  "record_count": tc.record_count, "context": tc.context})
        out.append({"name": tc.name, "expected": tc.expected_outcome, "actual": res["decision"]["outcome"],
                    "passed": tc.expected_outcome == res["decision"]["outcome"], "reason": res["decision"]["reason"]})
    db.commit()
    return {"policy": key, "version": p.current_version, "results": out, "passed": sum(r["passed"] for r in out), "total": len(out)}


eng = APIRouter(prefix="/api/sessions/{session_id}/engineering", tags=["engineering"])


@eng.get("/test-suite")
def suite(s: ScenarioSession = Depends(read_session)):
    d = definition_for(s)
    return {"cases": [c.model_dump() for c in d.policy_test_suite],
            "note": "Labelled synthetic dataset for policy engineering. 'should_prevent' is the expected enforcement outcome."}


def run_out(r: PolicyTestRun) -> dict[str, Any]:
    return {"id": r.id, "run_number": r.run_number, "policy_snapshot": r.policy_snapshot, "results": r.results,
            "metrics": r.metrics, "created_at": iso(r.created_at)}


@eng.post("/test-suite/run")
def suite_run(s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    r = svc.run_test_suite(db, s)
    db.commit()
    return run_out(r)


@eng.get("/test-suite/runs")
def suite_runs(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [run_out(r) for r in db.scalars(select(PolicyTestRun).where(PolicyTestRun.session_id == s.id).order_by(PolicyTestRun.run_number))]


@eng.get("/test-suite/compare")
def suite_compare(a: int, b: int, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    ra = db.scalar(select(PolicyTestRun).where(PolicyTestRun.session_id == s.id, PolicyTestRun.run_number == a))
    rb = db.scalar(select(PolicyTestRun).where(PolicyTestRun.session_id == s.id, PolicyTestRun.run_number == b))
    if ra is None or rb is None:
        raise HTTPException(404, "Run not found")
    return svc.compare_runs(ra, rb)


@eng.get("/dry-runs")
def dry_runs(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"id": e.id, "context": e.context, "outcome": e.final_outcome, "decisive_policy": e.decisive_policy,
             "trace": e.trace, "created_at": iso(e.created_at)}
            for e in db.scalars(select(PolicyEvaluation).where(PolicyEvaluation.session_id == s.id, PolicyEvaluation.dry_run.is_(True))
                                .order_by(PolicyEvaluation.id.desc()).limit(50))]


class ChangeIn(BaseModel):
    policy_key: str
    from_version: int
    to_version: int
    reason: str = Field(min_length=10, max_length=2000)
    expected_impact: str = Field(default="", max_length=2000)
    rollback_plan: str = Field(default="", max_length=2000)
    test_run_id: int | None = None


@eng.post("/change-records", status_code=201)
def change_record(body: ChangeIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    cr = svc.create_change_record(db, s, **body.model_dump())
    db.commit()
    return {"id": cr.id}


@eng.get("/change-records")
def change_records(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"id": c.id, "policy_key": c.policy_key, "from_version": c.from_version, "to_version": c.to_version, "reason": c.reason,
             "expected_impact": c.expected_impact, "rollback_plan": c.rollback_plan, "test_run_id": c.test_run_id,
             "created_at": iso(c.created_at)}
            for c in db.scalars(select(ChangeRecord).where(ChangeRecord.session_id == s.id).order_by(ChangeRecord.id))]
