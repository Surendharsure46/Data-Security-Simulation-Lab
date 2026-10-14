"""Task progress checks and the assessment (competency) engine.

Every check is a pure function of persisted session state. Scenario JSON selects
checks by name from the registries below; no scenario content is executed.
Identical state produces an identical score and ``inputs_digest``.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AccessGrant, Alert, AssessmentAttempt, CaseNote, ClassificationAssignment, DataAsset, DiscoveryScan,
    EvidenceReference, InvestigationCase, Policy, PolicyEvaluation, PolicyVersion, RemediationAction,
    ScenarioAction, ScenarioSession, SecurityEvent, SimIdentity,
)
from .investigation import primary_case, risk_score
from .scenario_defs import ScenarioDefinition, resolve_step
from .simulation import (
    CONTROL_CHANGE_ACTIONS, build_context, definition_for, evaluate, get_asset, get_destination, get_identity,
    label_ranks, last_action_seq, variant_params,
)

PREVENTED = {"BLOCKED", "DENIED", "FAILURE"}


# --------------------------------------------------------------------------- shared state helpers


class Ctx:
    """Lazy accessor bundle passed to every check."""

    def __init__(self, db: Session, s: ScenarioSession):
        self.db = db
        self.s = s
        self.d: ScenarioDefinition = definition_for(s)
        self.gt = self.d.ground_truth
        self.params = variant_params(s)
        self._cache: dict[str, Any] = {}

    @property
    def culprit(self) -> str:
        return self.params["culprit"]

    def runs(self) -> list[dict[str, Any]]:
        return list((self.s.flags or {}).get("runs", []))

    def first_standard_run(self) -> int | None:
        return next((r["run_number"] for r in self.runs() if r["mode"] == "standard"), None)

    def latest_validation_run(self) -> dict[str, Any] | None:
        vals = [r for r in self.runs() if r["mode"] == "validation"]
        return vals[-1] if vals else None

    def step_outcome(self, run_number: int, step: str) -> str | None:
        evs = self.db.scalars(select(SecurityEvent).where(
            SecurityEvent.session_id == self.s.id, SecurityEvent.run_number == run_number, SecurityEvent.step_key == step,
        )).all()
        if not evs:
            return None
        if any(e.result in PREVENTED for e in evs):
            return "PREVENTED"
        return "ALLOWED"

    def exfil_succeeded_in_first_run(self) -> bool | None:
        r = self.first_standard_run()
        if r is None:
            return None
        return self.step_outcome(r, self.gt["exfil_step"]) == "ALLOWED"

    def primary_case(self) -> InvestigationCase | None:
        if "case" not in self._cache:
            self._cache["case"] = primary_case(self.db, self.s)
        return self._cache["case"]

    def evidence(self, c: InvestigationCase) -> list[EvidenceReference]:
        return list(self.db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == c.id)))

    def notes(self, c: InvestigationCase) -> list[CaseNote]:
        return list(self.db.scalars(select(CaseNote).where(CaseNote.case_id == c.id)))

    def remediations(self) -> list[RemediationAction]:
        return list(self.db.scalars(select(RemediationAction).where(RemediationAction.session_id == self.s.id)
                                    .order_by(RemediationAction.seq)))

    def expected_outcome(self) -> dict[str, Any]:
        succeeded = self.exfil_succeeded_in_first_run()
        if succeeded is False:
            return {"exposure_status": ["ATTEMPT_PREVENTED", "NO_EVIDENCE_OF_EXFILTRATION"],
                    "determinations": ["ATTEMPTED_EXFILTRATION_PREVENTED"], "data_left_org": "NO", "records": 0}
        return {"exposure_status": self.gt["exposure_status"], "determinations": self.gt["determinations"],
                "data_left_org": "YES", "records": self.gt["records_exposed"]}


# --------------------------------------------------------------------------- task progress checks


def _t_scan_count(c: Ctx, p: dict) -> bool:
    return len(c.db.scalars(select(DiscoveryScan.id).where(DiscoveryScan.session_id == c.s.id)).all()) >= p["count"]


def _t_assets_viewed(c: Ctx, p: dict) -> bool:
    return set(p["assets"]) <= set((c.s.flags or {}).get("viewed_assets", []))


def _t_labeled_owner(c: Ctx, p: dict) -> bool:
    return all((a := get_asset(c.db, c.s, k)).label_key and a.owner_key for k in p["assets"])


def _t_grants_reviewed(c: Ctx, p: dict) -> bool:
    return any(g.review_decision for g in c.db.scalars(select(AccessGrant).where(
        AccessGrant.session_id == c.s.id, AccessGrant.asset_key == p["asset"])))


def _t_learner_versions(c: Ctx, p: dict) -> bool:
    n = c.db.scalars(select(PolicyVersion.id).join(Policy).where(
        Policy.session_id == c.s.id, PolicyVersion.author != "scenario-baseline")).all()
    return len(n) >= p["count"]


def _t_dry_runs(c: Ctx, p: dict) -> bool:
    evals = c.db.scalars(select(PolicyEvaluation).where(PolicyEvaluation.session_id == c.s.id, PolicyEvaluation.dry_run.is_(True))).all()
    return len(evals) >= p["count"] and len({e.final_outcome for e in evals}) >= 2


def _t_run_count(c: Ctx, p: dict) -> bool:
    return c.s.run_count >= p["count"]


def _t_alerts_dispositioned(c: Ctx, p: dict) -> bool:
    run = c.first_standard_run()
    if run is None:
        return False
    alerts = c.db.scalars(select(Alert).where(Alert.session_id == c.s.id, Alert.run_number == run)).all()
    return bool(alerts) and all(a.disposition for a in alerts)


def _t_case_evidence(c: Ctx, p: dict) -> bool:
    case = c.primary_case()
    return case is not None and len(c.evidence(case)) >= p["count"]


def _t_note_kinds(c: Ctx, p: dict) -> bool:
    case = c.primary_case()
    return case is not None and set(p["kinds"]) <= {n.kind for n in c.notes(case)}


def _t_scope(c: Ctx, p: dict) -> bool:
    case = c.primary_case()
    return bool(case and case.affected_asset_keys and case.exposure_status and case.severity
                and case.records_potentially_exposed is not None)


def _t_remediation_category(c: Ctx, p: dict) -> bool:
    cat = {r.type: r.category for r in c.d.remediation_catalog}
    return any(cat.get(r.action_type) == p["category"] for r in c.remediations())


def _t_control_fix(c: Ctx, p: dict) -> bool:
    runs = c.runs()
    if not runs:
        return False
    return last_action_seq(c.db, c.s, CONTROL_CHANGE_ACTIONS) > runs[0]["action_seq"]


def _t_validation_after_fix(c: Ctx, p: dict) -> bool:
    v = c.latest_validation_run()
    return v is not None and v["action_seq"] > last_action_seq(c.db, c.s, CONTROL_CHANGE_ACTIONS)


def _t_report_fields(c: Ctx, p: dict) -> bool:
    case = c.primary_case()
    return bool(case and all(x.strip() for x in (case.summary, case.root_cause_narrative, case.residual_risk, case.lessons_learned)))


TASK_CHECKS: dict[str, Callable[[Ctx, dict], bool]] = {
    "scan_count_at_least": _t_scan_count,
    "assets_viewed": _t_assets_viewed,
    "asset_labeled_with_owner": _t_labeled_owner,
    "grants_reviewed": _t_grants_reviewed,
    "learner_policy_versions_at_least": _t_learner_versions,
    "dry_runs_with_distinct_outcomes": _t_dry_runs,
    "run_count_at_least": _t_run_count,
    "run_alerts_dispositioned": _t_alerts_dispositioned,
    "case_evidence_at_least": _t_case_evidence,
    "case_note_kinds": _t_note_kinds,
    "case_scope_recorded": _t_scope,
    "remediation_category_applied": _t_remediation_category,
    "control_fix_after_run": _t_control_fix,
    "validation_run_after_last_fix": _t_validation_after_fix,
    "case_report_fields": _t_report_fields,
}


def task_progress(db: Session, s: ScenarioSession) -> list[dict[str, Any]]:
    c = Ctx(db, s)
    out = []
    for t in c.d.tasks:
        out.append({"key": t.key, "stage": t.stage, "phase": t.phase, "title": t.title, "description": t.description,
                    "done": bool(TASK_CHECKS[t.check.type](c, t.check.params)),
                    "hints_available": len(c.d.hints.get(t.key, [])),
                    "hints_revealed": len((s.hints_used or {}).get(t.key, []))})
    return out


# --------------------------------------------------------------------------- rubric checks
# Each returns (fraction 0..1, explanation).


def _r_label_matches(c: Ctx, p: dict) -> tuple[float, str]:
    truth = c.gt["labels"]
    ok, wrong = 0, []
    for k in p["assets"]:
        a = get_asset(c.db, c.s, k)
        if a.label_key in truth[k]:
            ok += 1
        else:
            wrong.append(f"{a.name} ({a.label_key or 'unlabeled'})")
    frac = ok / len(p["assets"])
    return frac, f"{ok}/{len(p['assets'])} assets correctly classified." + (f" Review: {', '.join(wrong)}." if wrong else "")


def _r_grants_revoked(c: Ctx, p: dict) -> tuple[float, str]:
    keys = c.gt["excessive_grants"]
    grants = {g.key: g for g in c.db.scalars(select(AccessGrant).where(AccessGrant.session_id == c.s.id))}
    done = [k for k in keys if grants[k].status == "REVOKED"]
    frac = len(done) / len(keys)
    return frac, ("Excessive permission removed." if frac == 1 else
                  "An excessive permission on the customer export is still active. Review which groups can read it and why.")


def _r_alert_dispositions(c: Ctx, p: dict) -> tuple[float, str]:
    group = c.gt["alert_groups"][p["group"]]
    run = c.first_standard_run()
    if run is None:
        return 0.0, "The business day was never run, so no alerts exist to triage."
    alerts = [a for a in c.db.scalars(select(Alert).where(Alert.session_id == c.s.id, Alert.run_number == run))
              if a.step_key in group["steps"]]
    if not alerts:
        if p["group"] == "malicious":
            return 0.0, "No alert was raised for the malicious activity in run 1 (detection gap)."
        return 1.0, "No alerts of this kind were generated (controls were tuned before the run)."
    ok = [a for a in alerts if a.disposition in group["accepted"]]
    frac = len(ok) / len(alerts)
    msg = f"{len(ok)}/{len(alerts)} alerts in this group dispositioned appropriately."
    if p["group"] == "ambiguous" and frac < 1:
        msg += " Evidence did not establish malicious intent; a supported conclusion was expected."
    if p["group"] == "benign" and frac < 1:
        msg += " Some legitimate business activity was treated as malicious or left untriaged."
    return frac, msg


def _r_case_determination(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None:
        return 0.0, "No investigation case opened."
    exp = c.expected_outcome()
    det_ok = case.determination in exp["determinations"]
    subjects = set(case.subject_identities or [])
    non_subject_steps = set(c.gt["legitimate_steps"]) | set(c.gt["ambiguous_steps"])
    innocent = {resolve_step(st, c.params)["actor"] for st in c.d.timeline if st.key in non_subject_steps} - {c.culprit}
    subj_ok = c.culprit in subjects and not (subjects & innocent)
    frac = 0.6 * det_ok + 0.4 * subj_ok
    parts = ["Determination supported by the run-1 evidence." if det_ok else
             f"Determination '{case.determination}' is not supported by what the run-1 events show."]
    parts.append("Subject identity correct." if subj_ok else
                 "Subject identities incomplete or include someone the evidence does not implicate.")
    return frac, " ".join(parts)


def _r_case_severity(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None or not case.severity:
        return 0.0, "No severity recorded."
    exp = c.expected_outcome()
    ri = c.gt["risk_inputs"]
    expected = risk_score(label_rank=label_ranks(c.db, c.s).get(ri["label"]), records=ri["records"],
                          destination_external=ri["destination_external"], data_left_org=exp["data_left_org"])["severity"]
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    diff = abs(order.index(case.severity) - order.index(expected))
    frac = 1.0 if diff == 0 else 0.5 if diff == 1 else 0.0
    return frac, ("Severity matches the risk model." if diff == 0 else
                  f"Severity {case.severity} differs from the risk-model result by {diff} level(s).")


def _r_case_evidence(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None:
        return 0.0, "No case."
    ev = c.evidence(case)
    event_ids = {e.ref_id for e in ev if e.ref_type == "EVENT"}
    run = c.first_standard_run()
    steps_linked = set()
    if event_ids:
        for e in c.db.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))):
            if e.run_number == run:
                steps_linked.add(e.step_key)
    alert_steps = set()
    alert_ids = {e.ref_id for e in ev if e.ref_type == "ALERT"}
    if alert_ids:
        alert_steps = {a.step_key for a in c.db.scalars(select(Alert).where(Alert.alert_id.in_(alert_ids)))}
    has_download = c.gt["download_step"] in steps_linked
    has_transfer = c.gt["exfil_step"] in steps_linked
    has_path = any((e.ref_type == "GRANT" and e.ref_id in c.gt["excessive_grants"]) or
                   (e.ref_type == "ASSET" and e.ref_id in c.gt["affected_assets_required"]) for e in ev)
    frac = (has_download + has_transfer + has_path) / 3
    missing = [n for n, ok in (("the bulk download event", has_download), ("the outbound transfer/DLP event", has_transfer),
                               ("the access path (grant or asset record)", has_path)) if not ok]
    if missing and alert_steps & {c.gt["download_step"], c.gt["exfil_step"]}:
        missing.append("(linking an alert is not the same as linking the underlying event)")
    return frac, "Evidence covers download, transfer and access path." if not missing else f"Missing evidence: {', '.join(missing)}."


def _r_case_notes(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None:
        return 0.0, "No case."
    notes = c.notes(case)
    obs = any(n.kind == "OBSERVATION" and n.evidence_ids for n in notes)
    inf = any(n.kind == "INFERENCE" for n in notes)
    unk = any(n.kind == "UNKNOWN" for n in notes)
    frac = (obs + inf + unk) / 3
    gaps = [g for g, ok in (("an observation citing evidence", obs), ("an inference", inf), ("an unknown", unk)) if not ok]
    return frac, "Notes separate observations, inferences and unknowns." if not gaps else f"Missing: {', '.join(gaps)}."


def _r_case_scope(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None:
        return 0.0, "No case."
    exp = c.expected_outcome()
    assets = set(case.affected_asset_keys or [])
    assets_ok = set(c.gt["affected_assets_required"]) <= assets <= set(c.gt["affected_assets_acceptable"])
    status_ok = case.exposure_status in exp["exposure_status"]
    rec = case.records_potentially_exposed
    if exp["records"] == 0:
        rec_ok = rec == 0
    else:
        rec_ok = rec is not None and abs(rec - exp["records"]) <= 0.05 * exp["records"]
    frac = 0.5 * assets_ok + 0.25 * status_ok + 0.25 * rec_ok
    notes = []
    if not assets_ok:
        notes.append("affected assets do not match what the events show")
    if not status_ok:
        notes.append("exposure status not supported by the transfer events")
    if not rec_ok:
        notes.append("record estimate inconsistent with the event record counts")
    return frac, "Scope supported by evidence." if not notes else "Scope issues: " + "; ".join(notes) + "."


def _validation_info(c: Ctx) -> tuple[dict | None, bool]:
    v = c.latest_validation_run()
    if v is None:
        return None, False
    after_fix = v["action_seq"] > last_action_seq(c.db, c.s, CONTROL_CHANGE_ACTIONS)
    return v, after_fix


def _r_validation_exfil(c: Ctx, p: dict) -> tuple[float, str]:
    v, after_fix = _validation_info(c)
    if v is None:
        return 0.0, "No control-validation replay was run."
    prevented = c.step_outcome(v["run_number"], c.gt["exfil_step"]) == "PREVENTED"
    if not prevented:
        return 0.0, f"In validation run {v['run_number']} the exfiltration step still succeeded."
    if not after_fix:
        return 0.5, "The path was closed in the last replay, but controls changed afterwards and were not re-verified."
    return 1.0, f"Validation run {v['run_number']} shows the exfiltration path closed."


def _r_validation_legit(c: Ctx, p: dict) -> tuple[float, str]:
    v, _ = _validation_info(c)
    if v is None:
        return 0.0, "No control-validation replay was run."
    steps = c.gt["legitimate_steps"]
    disrupted = [st for st in steps if c.step_outcome(v["run_number"], st) == "PREVENTED"]
    frac = (len(steps) - len(disrupted)) / len(steps)
    return frac, ("All legitimate activities still succeed." if not disrupted else
                  f"{len(disrupted)} legitimate business activities were blocked or denied in the replay (business disruption).")


def _r_dlp_depth(c: Ctx, p: dict) -> tuple[float, str]:
    asset = get_asset(c.db, c.s, c.gt["affected_assets_required"][0])
    culprit = get_identity(c.db, c.s, c.culprit)
    blocked = 0
    cases = [("UPLOAD", "dst-personal-cloud"), ("EMAIL", "dst-personal-webmail")]
    for action, dest_key in cases:
        ctx = build_context(c.db, c.s, actor=culprit, asset=asset, action=action, destination=get_destination(c.db, c.s, dest_key),
                            record_count=None, context={"device_managed": True},
                            timestamp=datetime(2026, 3, 9, 12, 0, tzinfo=timezone.utc))
        res = evaluate(c.db, c.s, ctx, dry_run=True, transaction_id="assessment", persist=False)
        blocked += res["decision"]["outcome"] == "BLOCK"
    frac = blocked / len(cases)
    return frac, (f"DLP blocks {blocked}/{len(cases)} canonical exfiltration paths independent of access control.")


def _r_subject_contained(c: Ctx, p: dict) -> tuple[float, str]:
    ident = get_identity(c.db, c.s, c.culprit)
    rems = [r for r in c.remediations() if r.target_key == c.culprit]
    disabled_verified = ident.status == "DISABLED" and any(r.action_type == "DISABLE_ACCOUNT" and r.status == "VERIFIED" for r in rems)
    if disabled_verified:
        return 1.0, "Subject account disabled and verified by sign-in probe."
    if ident.sessions_revoked_at is not None:
        return 0.5, "Sessions revoked, but the account can still sign in."
    return 0.0, "The subject identity was not contained."


def _r_escalated(c: Ctx, p: dict) -> tuple[float, str]:
    targets = {r.target_key for r in c.remediations() if r.action_type == "ESCALATE"}
    ok = bool(targets & set(p["any_of"]))
    return float(ok), ("Escalated to " + ", ".join(sorted(targets & set(p["any_of"]))) + "." if ok else
                       "A personal-data incident was not escalated to Privacy Office or Legal.")


def _r_report(c: Ctx, p: dict) -> tuple[float, str]:
    case = c.primary_case()
    if case is None:
        return 0.0, "No case."
    fields = [case.summary, case.root_cause_narrative, case.residual_risk, case.lessons_learned]
    filled = sum(1 for f in fields if f and len(f.strip()) >= 20)
    truth = set(c.gt["root_causes"])
    chosen = set(case.root_causes or [])
    unsupported = chosen - truth - {"MISSING_DATA_OWNER"}
    rc = max(0.0, len(chosen & truth) / len(truth) - 0.25 * len(unsupported))
    frac = 0.5 * filled / 4 + 0.5 * rc
    msg = f"{filled}/4 report sections substantive (20+ characters). Root causes: {len(chosen & truth)}/{len(truth)} identified"
    if unsupported:
        msg += f"; unsupported by evidence: {', '.join(sorted(unsupported))}"
    return frac, msg + "."


RUBRIC_CHECKS: dict[str, Callable[[Ctx, dict], tuple[float, str]]] = {
    "label_matches": _r_label_matches,
    "grants_revoked": _r_grants_revoked,
    "alert_dispositions": _r_alert_dispositions,
    "case_determination": _r_case_determination,
    "case_severity": _r_case_severity,
    "case_evidence_coverage": _r_case_evidence,
    "case_notes_quality": _r_case_notes,
    "case_scope": _r_case_scope,
    "validation_exfil_prevented": _r_validation_exfil,
    "validation_legitimate_allowed": _r_validation_legit,
    "dlp_blocks_canonical_exfil": _r_dlp_depth,
    "subject_contained": _r_subject_contained,
    "escalated_to": _r_escalated,
    "report_completeness": _r_report,
}


def _c_evidence_destroyed(c: Ctx) -> tuple[bool, str]:
    ident = get_identity(c.db, c.s, c.culprit)
    hit = bool(ident.attributes.get("evidence_destroyed"))
    return hit, "Device reimaged before evidence preservation; endpoint evidence lost." if hit else ""


def _c_not_verified(c: Ctx) -> tuple[bool, str]:
    v = c.latest_validation_run()
    if v is None:
        return True, "No control-validation replay was performed."
    if c.step_outcome(v["run_number"], c.gt["exfil_step"]) != "PREVENTED":
        return True, "The latest control-validation replay shows the exfiltration path still open."
    return False, ""


CRITICAL_CHECKS: dict[str, Callable[[Ctx], tuple[bool, str]]] = {
    "evidence_destroyed": _c_evidence_destroyed,
    "exfil_not_verified_closed": _c_not_verified,
}


# --------------------------------------------------------------------------- scoring


def _digest(db: Session, s: ScenarioSession) -> str:
    """Hash of every learner-controlled input the score depends on."""
    def rows(model, *order):
        out = []
        for r in db.scalars(select(model).where(model.session_id == s.id).order_by(*order)):
            d = {k: v for k, v in r.__dict__.items() if not k.startswith("_") and k not in ("id", "created_at", "updated_at")}
            out.append(d)
        return out
    payload = {
        "assets": [(a["key"], a["label_key"], a["owner_key"], a["quarantined"]) for a in rows(DataAsset, DataAsset.key)],
        "grants": [(g["key"], g["status"], g["review_decision"]) for g in rows(AccessGrant, AccessGrant.key)],
        "alerts": [(a["alert_id"], a["disposition"]) for a in rows(Alert, Alert.alert_id)],
        "identities": [(i["key"], i["status"], json.dumps(i["attributes"], sort_keys=True)) for i in rows(SimIdentity, SimIdentity.key)],
        "remediations": [(r["seq"], r["action_type"], r["target_key"], r["status"]) for r in rows(RemediationAction, RemediationAction.seq)],
        "actions": [(a["seq"], a["action_type"]) for a in rows(ScenarioAction, ScenarioAction.seq)],
        "events": [(e["event_id"], e["step_key"], e["result"]) for e in rows(SecurityEvent, SecurityEvent.seq)],
        "policies": [(p.key, p.status, p.current_version, json.dumps(next(v.definition for v in p.versions if v.version == p.current_version), sort_keys=True))
                     for p in db.scalars(select(Policy).where(Policy.session_id == s.id).order_by(Policy.key))],
        "cases": [],
        "flags": json.dumps(s.flags or {}, sort_keys=True),
    }
    for case in db.scalars(select(InvestigationCase).where(InvestigationCase.session_id == s.id).order_by(InvestigationCase.id)):
        payload["cases"].append({
            "fields": [case.determination, case.severity, case.exposure_status, case.records_potentially_exposed,
                       sorted(case.affected_asset_keys or []), sorted(case.subject_identities or []), sorted(case.root_causes or []),
                       case.summary, case.root_cause_narrative, case.residual_risk, case.lessons_learned, sorted(case.alert_ids or [])],
            "evidence": sorted((e.ref_type, e.ref_id) for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == case.id))),
            "notes": sorted((n.kind, n.text, tuple(n.evidence_ids or [])) for n in db.scalars(select(CaseNote).where(CaseNote.case_id == case.id))),
        })
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def score_session(db: Session, s: ScenarioSession) -> dict[str, Any]:
    c = Ctx(db, s)
    rubric = c.d.rubric
    criteria_out = []
    cat_points: dict[str, float] = {k: 0.0 for k in rubric.categories}
    cat_max: dict[str, float] = {k: 0.0 for k in rubric.categories}
    for crit in rubric.criteria:
        frac, why = RUBRIC_CHECKS[crit.check](c, crit.params)
        frac = max(0.0, min(1.0, frac))
        earned = round(crit.points * frac, 2)
        cat_points[crit.category] += earned
        cat_max[crit.category] += crit.points
        criteria_out.append({"key": crit.key, "category": crit.category, "description": crit.description,
                             "points": crit.points, "earned": earned, "explanation": why, "lessons": crit.lessons})
    category_scores = {}
    total = 0.0
    for k, cat in rubric.categories.items():
        pct = cat_points[k] / cat_max[k] if cat_max[k] else 0
        weighted = round(pct * cat.weight, 2)
        total += weighted
        category_scores[k] = {"name": cat.name, "weight": cat.weight, "percent": round(pct * 100, 1), "weighted": weighted}
    criticals = []
    for cc in rubric.critical_conditions:
        hit, why = CRITICAL_CHECKS[cc.check](c)
        if hit:
            criticals.append({"key": cc.key, "description": cc.description, "detail": why})
    total = round(total, 2)
    progress = task_progress(db, s)
    missing = [t["title"] for t in progress if not t["done"]]
    recs: dict[str, dict[str, Any]] = {}
    for cr in criteria_out:
        if cr["earned"] < 0.7 * cr["points"]:
            for lesson in cr["lessons"]:
                recs.setdefault(lesson, {"lesson_id": lesson, "because": []})["because"].append(cr["description"])
    return {
        "scenario_id": s.scenario_id, "rubric_version": rubric.version, "mode": s.mode,
        "total_score": total, "pass_threshold": rubric.pass_threshold,
        "passed": total >= rubric.pass_threshold and not criticals,
        "category_scores": category_scores, "criteria": criteria_out, "critical_failures": criticals,
        "missing_tasks": missing, "recommendations": list(recs.values()),
        "inputs_digest": _digest(db, s),
    }


def submit(db: Session, s: ScenarioSession, user_id: int, report_snapshot: str) -> AssessmentAttempt:
    result = score_session(db, s)
    attempt = AssessmentAttempt(
        session_id=s.id, user_id=user_id, scenario_id=s.scenario_id, rubric_version=result["rubric_version"],
        mode=s.mode, total_score=result["total_score"], passed=result["passed"],
        category_scores=result["category_scores"], criteria=result["criteria"],
        critical_failures=result["critical_failures"], missing_tasks=result["missing_tasks"],
        recommendations=result["recommendations"], inputs_digest=result["inputs_digest"],
        attempt_number=s.attempt_number, variant=s.variant, report_snapshot=report_snapshot,
    )
    db.add(attempt)
    db.flush()
    return attempt
