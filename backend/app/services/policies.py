"""Policy management: versioning, status, dry-run testing, test suites and change records."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import ChangeRecord, Policy, PolicyTestRun, PolicyVersion, ScenarioSession
from .common import DomainError, as_utc
from .policy_engine import PolicyDefinition, diff_definitions
from .simulation import (
    advance_clock, build_context, definition_for, evaluate, get_asset, get_destination, get_identity, load_policies,
    record_action,
)

KEY_RE = re.compile(r"^POL-[A-Z0-9-]{2,40}$")
SCOPE_NOTE = ("Measured against {n} labelled synthetic test cases in this scenario only. These rates describe this "
              "test set and are not an estimate of production detection performance.")


def validate_definition(raw: dict[str, Any]) -> PolicyDefinition:
    try:
        return PolicyDefinition.model_validate(raw)
    except ValidationError as exc:
        msgs = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        raise DomainError("Invalid policy definition — " + "; ".join(msgs[:8]), 422) from exc


def get_policy(db: Session, s: ScenarioSession, key: str) -> Policy:
    p = db.scalar(select(Policy).where(Policy.session_id == s.id, Policy.key == key))
    if p is None:
        raise DomainError(f"Unknown policy '{key}'", 404)
    return p


def create_policy(db: Session, s: ScenarioSession, author: str, key: str, raw: dict[str, Any], note: str) -> Policy:
    if not KEY_RE.match(key):
        raise DomainError("Policy key must look like POL-XXXX (uppercase letters, digits, hyphens)")
    if db.scalar(select(Policy).where(Policy.session_id == s.id, Policy.key == key)):
        raise DomainError("A policy with this key already exists", 409)
    definition = validate_definition(raw)
    advance_clock(s)
    p = Policy(session_id=s.id, key=key, kind=definition.kind, status="ENABLED", current_version=1, baseline=False)
    p.versions.append(PolicyVersion(version=1, definition=definition.model_dump(mode="json"), change_note=note or "Created", author=author))
    db.add(p)
    db.flush()
    record_action(db, s, "POLICY_CREATE", {"policy": key, "version": 1})
    return p


def update_policy(db: Session, s: ScenarioSession, author: str, key: str, raw: dict[str, Any], note: str) -> PolicyVersion:
    p = get_policy(db, s, key)
    definition = validate_definition(raw)
    if definition.kind != p.kind:
        raise DomainError("Policy kind cannot change between versions; create a new policy instead")
    current = next(v for v in p.versions if v.version == p.current_version)
    new_def = definition.model_dump(mode="json")
    if new_def == current.definition:
        raise DomainError("No changes compared with the current version", 409)
    advance_clock(s)
    v = PolicyVersion(version=max(x.version for x in p.versions) + 1, definition=new_def, change_note=note or "Updated", author=author)
    p.versions.append(v)
    p.current_version = v.version
    db.flush()
    record_action(db, s, "POLICY_UPDATE", {"policy": key, "version": v.version})
    return v


def set_status(db: Session, s: ScenarioSession, key: str, status: str) -> Policy:
    if status not in ("ENABLED", "DISABLED"):
        raise DomainError("status must be ENABLED or DISABLED")
    p = get_policy(db, s, key)
    if p.status == status:
        raise DomainError(f"Policy already {status}", 409)
    p.status = status
    advance_clock(s)
    record_action(db, s, "POLICY_STATUS", {"policy": key, "status": status})
    return p


def rollback(db: Session, s: ScenarioSession, author: str, key: str, to_version: int) -> PolicyVersion:
    p = get_policy(db, s, key)
    target = next((v for v in p.versions if v.version == to_version), None)
    if target is None:
        raise DomainError("Version not found", 404)
    return update_policy(db, s, author, key, target.definition, f"Rollback to v{to_version}")


def diff(db: Session, s: ScenarioSession, key: str, a: int, b: int) -> list[dict[str, Any]]:
    p = get_policy(db, s, key)
    va = next((v for v in p.versions if v.version == a), None)
    vb = next((v for v in p.versions if v.version == b), None)
    if va is None or vb is None:
        raise DomainError("Version not found", 404)
    return diff_definitions(va.definition, vb.definition)


def _context_for(db: Session, s: ScenarioSession, spec: dict[str, Any]) -> dict[str, Any]:
    actor = get_identity(db, s, spec["actor"])
    asset = get_asset(db, s, spec["resource"])
    dest = get_destination(db, s, spec["destination"]) if spec.get("destination") else None
    hour = int(spec.get("hour", 12))
    return build_context(db, s, actor=actor, asset=asset, action=spec["action"], destination=dest,
                         record_count=spec.get("record_count"), context=spec.get("context") or {},
                         timestamp=datetime(2026, 3, 9, hour % 24, 0, tzinfo=timezone.utc))


def dry_run(db: Session, s: ScenarioSession, spec: dict[str, Any], candidate: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a hypothetical activity. Access control is NOT applied: this tests policy logic only.

    ``candidate`` optionally evaluates an unsaved policy definition alongside (or instead of) the saved version
    with the same key, so a learner can preview the effect of an edit before saving it.
    """
    ctx = _context_for(db, s, spec)
    policies = load_policies(db, s)
    if candidate:
        key = candidate.get("key") or "POL-DRAFT"
        cand_def = validate_definition(candidate["definition"])
        policies = [x for x in policies if x[0].key != key]
        draft = Policy(key=key, kind=cand_def.kind, status="ENABLED", current_version=0)
        policies.append((draft, PolicyVersion(version=0, definition=cand_def.model_dump(mode="json")), cand_def))
    res = evaluate(db, s, ctx, dry_run=True, transaction_id=f"dry-{s.event_seq}", policies=policies, persist=candidate is None)
    if candidate is None:
        advance_clock(s)
    public_ctx = {k: v for k, v in ctx.items() if not k.startswith("_")}
    return {"context": public_ctx, "entries": res["entries"], "decision": res["decision"],
            "note": "Policy-only evaluation: access permissions, account status and egress blocklists are not applied in dry runs.",
            "draft_included": candidate is not None}


def _metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for r in results if r["should_prevent"] and r["prevented"])
    fn = sum(1 for r in results if r["should_prevent"] and not r["prevented"])
    fp = sum(1 for r in results if not r["should_prevent"] and r["prevented"])
    tn = sum(1 for r in results if not r["should_prevent"] and not r["prevented"])
    precision = round(tp / (tp + fp), 3) if tp + fp else None
    recall = round(tp / (tp + fn), 3) if tp + fn else None
    return {"total": len(results), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall,
            "accuracy": round((tp + tn) / len(results), 3) if results else None,
            "alerts_on_allowed_cases": sum(1 for r in results if not r["should_prevent"] and r["alerts"]),
            "scope_note": SCOPE_NOTE.format(n=len(results))}


def run_test_suite(db: Session, s: ScenarioSession) -> PolicyTestRun:
    d = definition_for(s)
    if not d.policy_test_suite:
        raise DomainError("This scenario has no labelled policy test suite")
    policies = load_policies(db, s)
    results = []
    for case in d.policy_test_suite:
        spec = case.model_dump()
        ctx = _context_for(db, s, spec)
        res = evaluate(db, s, ctx, dry_run=True, transaction_id=f"suite-{case.id}", policies=policies, persist=False)
        outcome = res["decision"]["outcome"]
        prevented = outcome == "BLOCK"
        results.append({"id": case.id, "description": case.description, "should_prevent": case.should_prevent,
                        "outcome": outcome, "prevented": prevented, "decisive_policy": res["decision"]["decisive_policy"],
                        "alerts": [e["policy_key"] for e in res["entries"] if e["matched"] and e["alert"]],
                        "correct": prevented == case.should_prevent})
    n = (db.scalar(select(func.count(PolicyTestRun.id)).where(PolicyTestRun.session_id == s.id)) or 0) + 1
    run = PolicyTestRun(session_id=s.id, run_number=n,
                        policy_snapshot={p.key: {"version": pv.version, "status": p.status} for p, pv, _ in policies},
                        results=results, metrics=_metrics(results))
    db.add(run)
    db.flush()
    record_action(db, s, "POLICY_TEST_SUITE", {"run_number": n}, {"metrics": run.metrics})
    return run


def compare_runs(a: PolicyTestRun, b: PolicyTestRun) -> dict[str, Any]:
    ra = {r["id"]: r for r in a.results}
    changed = []
    for r in b.results:
        prev = ra.get(r["id"])
        if prev and prev["outcome"] != r["outcome"]:
            kind = ("fixed" if r["correct"] and not prev["correct"] else "regressed" if prev["correct"] and not r["correct"] else "changed")
            changed.append({"id": r["id"], "description": r["description"], "before": prev["outcome"], "after": r["outcome"], "kind": kind})
    return {"from_run": a.run_number, "to_run": b.run_number, "changed": changed,
            "regressions": sum(1 for c in changed if c["kind"] == "regressed"),
            "fixes": sum(1 for c in changed if c["kind"] == "fixed"),
            "policy_changes": {k: {"before": a.policy_snapshot.get(k), "after": v} for k, v in b.policy_snapshot.items()
                               if a.policy_snapshot.get(k) != v}}


def create_change_record(db: Session, s: ScenarioSession, *, policy_key: str, from_version: int, to_version: int,
                         reason: str, expected_impact: str, rollback_plan: str, test_run_id: int | None) -> ChangeRecord:
    p = get_policy(db, s, policy_key)
    versions = {v.version for v in p.versions}
    if from_version not in versions or to_version not in versions:
        raise DomainError("Versions must exist on the policy")
    if test_run_id is not None and db.scalar(select(PolicyTestRun).where(PolicyTestRun.id == test_run_id, PolicyTestRun.session_id == s.id)) is None:
        raise DomainError("Test run not found in this session", 404)
    cr = ChangeRecord(session_id=s.id, policy_key=policy_key, from_version=from_version, to_version=to_version,
                      reason=reason, expected_impact=expected_impact, rollback_plan=rollback_plan, test_run_id=test_run_id)
    db.add(cr)
    db.flush()
    record_action(db, s, "CHANGE_RECORD", {"policy": policy_key, "from": from_version, "to": to_version})
    return cr


def serialize_policy(p: Policy) -> dict[str, Any]:
    cur = next(v for v in p.versions if v.version == p.current_version)
    return {"key": p.key, "kind": p.kind, "status": p.status, "baseline": p.baseline, "current_version": p.current_version,
            "definition": cur.definition, "versions": [
                {"version": v.version, "author": v.author, "change_note": v.change_note, "created_at": as_utc(v.created_at).isoformat()}
                for v in p.versions]}
