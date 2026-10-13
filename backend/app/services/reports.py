"""Report generation. Every report is derived from persisted session state; nothing is invented.

Reports are built as a neutral structure (title + sections) and rendered to
Markdown, HTML (fully escaped), JSON or CSV (tabular reports only).
"""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AccessGrant, Alert, AssessmentAttempt, CaseNote, ClassificationAssignment, ClassificationFinding, DataAsset,
    EvidenceReference, InvestigationCase, PolicyEvaluation, PolicyTestRun, RemediationAction, ScenarioSession,
    SecurityEvent, User,
)
from .common import DomainError, iso
from .investigation import primary_case
from .simulation import definition_for

REPORT_TYPES = {
    "inventory": "Data inventory",
    "classification-register": "Classification register",
    "policy-tests": "Policy test report",
    "incident-timeline": "Incident timeline",
    "case-report": "Investigation case report",
    "remediation-verification": "Remediation verification report",
    "assessment": "Competency assessment report",
}
TABULAR = {"inventory", "classification-register", "policy-tests", "incident-timeline", "remediation-verification"}
MODE_STATEMENT = ("Execution mode: SIMULATED. All data, identities and events are synthetic and were produced by "
                  "the Threatready simulation engine; no real system was affected.")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _table(columns: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    return {"kind": "table", "columns": columns, "rows": [["" if v is None else v for v in r] for r in rows]}


def _text(t: str) -> dict[str, Any]:
    return {"kind": "text", "content": t}


def _list(items: list[str]) -> dict[str, Any]:
    return {"kind": "list", "items": items}


def _assets(db: Session, s: ScenarioSession) -> list[DataAsset]:
    return list(db.scalars(select(DataAsset).where(DataAsset.session_id == s.id).order_by(DataAsset.key)))


def build(db: Session, s: ScenarioSession, report_type: str) -> dict[str, Any]:
    if report_type not in REPORT_TYPES:
        raise DomainError(f"Unknown report type. Available: {', '.join(REPORT_TYPES)}", 404)
    d = definition_for(s)
    learner = db.get(User, s.user_id)
    meta = {
        "title": f"{REPORT_TYPES[report_type]} — {d.title}",
        "report_type": report_type,
        "scenario": f"{d.id} v{d.version}",
        "session_id": s.id,
        "attempt": s.attempt_number,
        "mode": s.mode,
        "learner": learner.display_name if learner else "",
        "generated_at": _now(),
        "execution_mode": "SIMULATED",
        "timezone": "All timestamps are UTC.",
        "statement": MODE_STATEMENT,
    }
    sections: list[dict[str, Any]] = []
    builder = globals()[f"_build_{report_type.replace('-', '_')}"]
    builder(db, s, sections)
    return {**meta, "sections": sections}


def _build_inventory(db: Session, s: ScenarioSession, sections: list) -> None:
    findings: dict[str, list[ClassificationFinding]] = {}
    latest_scan = db.scalar(select(ClassificationFinding.scan_id).where(ClassificationFinding.session_id == s.id)
                            .order_by(ClassificationFinding.scan_id.desc()).limit(1))
    if latest_scan:
        for f in db.scalars(select(ClassificationFinding).where(ClassificationFinding.scan_id == latest_scan)):
            findings.setdefault(f.asset_key, []).append(f)
    rows = []
    for a in _assets(db, s):
        det = "; ".join(f"{f.detector}×{f.match_count} ({f.confidence})" for f in findings.get(a.key, []))
        rows.append([a.key, a.name, a.asset_type, a.data_structure, a.system, a.location, a.department,
                     a.owner_key or "MISSING", a.label_key or "UNLABELED", a.record_count, det or ("not scanned" if not latest_scan else "none")])
    sections.append({"heading": "Inventory", "body": _table(
        ["asset_key", "name", "type", "structure", "system", "location", "department", "owner", "label", "records", "detector_findings"], rows)})
    gaps = [f"{r[1]}: owner {r[7]}, label {r[8]}" for r in rows if r[7] == "MISSING" or r[8] == "UNLABELED"]
    sections.append({"heading": "Coverage gaps", "body": _list(gaps or ["No unlabeled or unowned assets."])})


def _build_classification_register(db: Session, s: ScenarioSession, sections: list) -> None:
    rows = [[a.key, a.name, a.label_key or "UNLABELED", a.owner_key or "MISSING", a.handling_notes, a.exception_note] for a in _assets(db, s)]
    sections.append({"heading": "Current register", "body": _table(["asset_key", "name", "label", "owner", "handling", "exception"], rows)})
    hist = db.scalars(select(ClassificationAssignment).where(ClassificationAssignment.session_id == s.id).order_by(ClassificationAssignment.id)).all()
    sections.append({"heading": "Change history", "body": _table(
        ["sim_time", "asset_key", "previous", "new", "owner", "justification"],
        [[iso(h.sim_time), h.asset_key, h.previous_label_key or "UNLABELED", h.label_key, h.owner_key, h.justification] for h in hist])})


def _build_policy_tests(db: Session, s: ScenarioSession, sections: list) -> None:
    runs = db.scalars(select(PolicyTestRun).where(PolicyTestRun.session_id == s.id).order_by(PolicyTestRun.run_number)).all()
    if runs:
        last = runs[-1]
        m = last.metrics
        sections.append({"heading": f"Latest test-suite run (#{last.run_number})", "body": _text(
            f"Cases: {m['total']}. TP {m['tp']}, FP {m['fp']}, TN {m['tn']}, FN {m['fn']}. "
            f"Precision {m['precision']}, recall {m['recall']}. {m['scope_note']}")})
        sections.append({"heading": "Case results", "body": _table(
            ["case", "description", "expected", "outcome", "decisive_policy", "correct"],
            [[r["id"], r["description"], "PREVENT" if r["should_prevent"] else "ALLOW", r["outcome"], r["decisive_policy"], r["correct"]] for r in last.results])})
        sections.append({"heading": "Run history", "body": _table(
            ["run", "precision", "recall", "fp", "fn", "policies"],
            [[r.run_number, r.metrics["precision"], r.metrics["recall"], r.metrics["fp"], r.metrics["fn"],
              ", ".join(f"{k} v{v['version']} {v['status']}" for k, v in r.policy_snapshot.items())] for r in runs])})
    else:
        sections.append({"heading": "Test-suite runs", "body": _text("No test-suite run has been executed.")})
    dry = db.scalars(select(PolicyEvaluation).where(PolicyEvaluation.session_id == s.id, PolicyEvaluation.dry_run.is_(True))
                     .order_by(PolicyEvaluation.id)).all()
    sections.append({"heading": "Ad-hoc policy tests (dry runs)", "body": _table(
        ["#", "actor", "action", "resource", "destination", "outcome", "decisive_policy"],
        [[i + 1, e.context.get("actor", {}).get("id"), e.context.get("action", {}).get("type"), e.context.get("resource", {}).get("id"),
          (e.context.get("destination") or {}).get("id"), e.final_outcome, e.decisive_policy] for i, e in enumerate(dry)])})


def _case_events(db: Session, s: ScenarioSession, case: InvestigationCase | None) -> list[SecurityEvent]:
    ids: set[str] = set()
    if case:
        ids |= {e.ref_id for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == case.id, EvidenceReference.ref_type == "EVENT"))}
        for al in db.scalars(select(Alert).where(Alert.alert_id.in_(case.alert_ids or []))):
            ids |= set(al.event_ids or [])
    if not ids:
        return []
    return list(db.scalars(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.event_id.in_(ids))
                           .order_by(SecurityEvent.timestamp, SecurityEvent.seq)))


def _primary_case(db: Session, s: ScenarioSession) -> InvestigationCase | None:
    return primary_case(db, s)


def _build_incident_timeline(db: Session, s: ScenarioSession, sections: list) -> None:
    case = _primary_case(db, s)
    evs = _case_events(db, s, case)
    if not evs:
        sections.append({"heading": "Timeline", "body": _text("No case with linked events or alerts exists yet.")})
        return
    sections.append({"heading": f"Timeline for case #{case.id}: {case.title}", "body": _table(
        ["timestamp_utc", "event_id", "source", "actor", "action", "resource", "destination", "result", "provenance", "summary"],
        [[iso(e.timestamp), e.event_id, e.source_system, e.actor_id, e.action, e.resource_id, e.destination, e.result, e.provenance, e.summary] for e in evs])})


def _build_case_report(db: Session, s: ScenarioSession, sections: list) -> None:
    case = _primary_case(db, s)
    if case is None:
        sections.append({"heading": "Case", "body": _text("No investigation case has been opened in this session.")})
        return
    notes = db.scalars(select(CaseNote).where(CaseNote.case_id == case.id).order_by(CaseNote.id)).all()
    ev = db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == case.id).order_by(EvidenceReference.id)).all()
    ev_label = {e.id: f"E{i + 1}" for i, e in enumerate(ev)}
    assets = {a.key: a for a in _assets(db, s)}
    rems = db.scalars(select(RemediationAction).where(RemediationAction.session_id == s.id).order_by(RemediationAction.seq)).all()

    def notes_of(kind: str) -> list[str]:
        return [n.text + (f" [evidence: {', '.join(ev_label.get(i, '?') for i in n.evidence_ids)}]" if n.evidence_ids else "")
                for n in notes if n.kind == kind] or ["None recorded."]

    sections.append({"heading": "1. Incident summary", "body": _text(case.summary or "Not yet written.")})
    sections.append({"heading": "2. Scope and objective", "body": _text(
        f"Case #{case.id} '{case.title}'. Alerts in scope: {', '.join(case.alert_ids or []) or 'none'}. "
        f"Determination: {case.determination or 'not recorded'}. Subject identities: {', '.join(case.subject_identities or []) or 'none recorded'}. "
        f"Hypothesis: {case.hypothesis or 'not recorded'}.")})
    evs = _case_events(db, s, case)
    sections.append({"heading": "3. Relevant timeline", "body": _table(
        ["timestamp_utc", "event_id", "actor", "action", "resource", "destination", "result"],
        [[iso(e.timestamp), e.event_id, e.actor_id, e.action, e.resource_id, e.destination, e.result] for e in evs])})
    sections.append({"heading": "4. Affected assets and data classifications", "body": _table(
        ["asset_key", "name", "current_label", "records"],
        [[k, assets[k].name if k in assets else "?", assets[k].label_key if k in assets else "?", assets[k].record_count if k in assets else ""]
         for k in case.affected_asset_keys or []])})
    sections.append({"heading": "   Exposure", "body": _text(
        f"Exposure status: {case.exposure_status or 'not recorded'}. Records potentially exposed: "
        f"{case.records_potentially_exposed if case.records_potentially_exposed is not None else 'not recorded'}. Severity: {case.severity or 'not recorded'}.")})
    sections.append({"heading": "5. Evidence references", "body": _table(
        ["ref", "type", "id", "label", "note"], [[ev_label[e.id], e.ref_type, e.ref_id, e.label, e.note] for e in ev])})
    sections.append({"heading": "6. Confirmed observations", "body": _list(notes_of("OBSERVATION"))})
    sections.append({"heading": "7. Inferences and uncertainties", "body": _list(
        [f"Inference: {t}" for t in notes_of("INFERENCE")] + [f"Unknown: {t}" for t in notes_of("UNKNOWN")] +
        [f"Hypothesis: {t}" for t in notes_of("HYPOTHESIS") if t != "None recorded."])})
    sections.append({"heading": "8. Root cause", "body": _text(
        (case.root_cause_narrative or "Not established.") + (f" Categories: {', '.join(case.root_causes)}." if case.root_causes else ""))})
    cat = {r.type: r.category for r in definition_for(s).remediation_catalog}
    contain = [r for r in rems if cat.get(r.action_type) in ("CONTAINMENT", "PRESERVATION")]
    other = [r for r in rems if r not in contain]
    rem_cols = ["#", "sim_time", "action", "target", "status", "verification", "justification"]

    def rem_rows(rs: list[RemediationAction]) -> list[list[Any]]:
        return [[r.seq, iso(r.sim_time), r.action_type, r.target_key, r.status, r.verification.get("check", ""), r.justification] for r in rs]

    sections.append({"heading": "9. Containment decisions", "body": _table(rem_cols, rem_rows(contain))})
    sections.append({"heading": "10. Remediation actions", "body": _table(rem_cols, rem_rows(other))})
    sections.append({"heading": "11. Verification results", "body": _list(_verification_lines(db, s))})
    sections.append({"heading": "12. Residual risk", "body": _text(case.residual_risk or "Not recorded.")})
    sections.append({"heading": "13. Lessons learned", "body": _text(case.lessons_learned or "Not recorded.")})
    sections.append({"heading": "14. Generation details", "body": _text(
        f"Generated {_now()} from session {s.id}, attempt {s.attempt_number}. {MODE_STATEMENT}")})


def run_outcomes(db: Session, s: ScenarioSession, run_number: int) -> list[dict[str, Any]]:
    """Per-activity outcome of a run, derived only from the recorded events (no ground truth)."""
    txs: dict[str, list[SecurityEvent]] = {}
    for e in db.scalars(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.run_number == run_number)
                        .order_by(SecurityEvent.seq)):
        txs.setdefault(e.transaction_id or e.event_id, []).append(e)
    out = []
    for evs in txs.values():
        first = evs[0]
        prevented = [e for e in evs if e.result in ("BLOCKED", "DENIED", "FAILURE")]
        out.append({
            "timestamp": iso(first.timestamp), "actor": first.actor_id,
            "action": next((e.action for e in evs if e.source_type in ("DLP", "EMAIL_GATEWAY", "PROXY", "ENDPOINT")), first.action),
            "resource": first.resource_id, "destination": next((e.destination for e in evs if e.destination), None),
            "outcome": "PREVENTED" if prevented else "COMPLETED",
            "prevented_by": f"{prevented[0].source_system}{' / ' + prevented[0].policy_id if prevented[0].policy_id else ''}" if prevented else None,
            "event_ids": [e.event_id for e in evs],
        })
    return out


def _verification_lines(db: Session, s: ScenarioSession) -> list[str]:
    lines = []
    for r in (s.flags or {}).get("runs", []):
        outcomes = run_outcomes(db, s, r["run_number"])
        prevented = [o for o in outcomes if o["outcome"] == "PREVENTED"]
        label = "Control-validation replay" if r["mode"] == "validation" else "Business-day run"
        lines.append(f"Run {r['run_number']} ({label}, {r['sim_day']}): {len(outcomes)} activities, {len(prevented)} prevented.")
        for o in prevented:
            lines.append(f"  Prevented: {o['actor']} {o['action']} {o['resource'] or ''}"
                         f"{' -> ' + o['destination'] if o['destination'] else ''} ({o['prevented_by']})")
    for r in db.scalars(select(RemediationAction).where(RemediationAction.session_id == s.id).order_by(RemediationAction.seq)):
        v = r.verification or {}
        line = f"{r.action_type} {r.target_key}: {r.status} — {v.get('check', '')}"
        if v.get("caveat"):
            line += f" (caveat: {v['caveat']})"
        lines.append(line)
    return lines or ["No runs or remediation actions recorded."]


def _build_remediation_verification(db: Session, s: ScenarioSession, sections: list) -> None:
    rems = db.scalars(select(RemediationAction).where(RemediationAction.session_id == s.id).order_by(RemediationAction.seq)).all()
    sections.append({"heading": "Remediation actions", "body": _table(
        ["#", "sim_time", "action", "target", "status", "before", "after", "verification"],
        [[r.seq, iso(r.sim_time), r.action_type, r.target_key, r.status, json.dumps(r.before_state, default=str),
          json.dumps(r.after_state, default=str), json.dumps(r.verification, default=str)] for r in rems])})
    grants = db.scalars(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.review_decision.is_not(None))).all()
    sections.append({"heading": "Access review decisions", "body": _table(
        ["grant", "asset", "principal", "permission", "decision", "status", "note"],
        [[g.key, g.asset_key, g.principal_key, g.permission, g.review_decision, g.status, g.review_note] for g in grants])})
    sections.append({"heading": "Replay verification", "body": _list(_verification_lines(db, s))})


def _build_assessment(db: Session, s: ScenarioSession, sections: list) -> None:
    attempt = db.scalar(select(AssessmentAttempt).where(AssessmentAttempt.session_id == s.id).order_by(AssessmentAttempt.id.desc()).limit(1))
    if attempt is None:
        # No score preview before submission: previews would let learners probe hidden answers.
        sections.append({"heading": "Status", "body": _text(
            "Not yet submitted. Scores are calculated on the server only when the session is submitted.")})
        return
    else:
        sections.append({"heading": "Status", "body": _text(
            f"Submitted {iso(attempt.submitted_at)} (attempt {attempt.attempt_number}, {attempt.mode} mode). Inputs digest {attempt.inputs_digest[:16]}…")})
        crit, cats, total, passed, crits, missing, recs = (attempt.criteria, attempt.category_scores, attempt.total_score,
                                                          attempt.passed, attempt.critical_failures, attempt.missing_tasks, attempt.recommendations)
    sections.append({"heading": "Result", "body": _text(
        f"Score {total}/100 — {'PASS' if passed else 'NOT PASSED'}. This is a Threatready platform assessment outcome for the "
        f"tasks listed below. It is not a professional certification and reports only what this scenario assessed.")})
    sections.append({"heading": "Category scores", "body": _table(
        ["category", "weight", "percent", "weighted"], [[v["name"], v["weight"], v["percent"], v["weighted"]] for v in cats.values()])})
    sections.append({"heading": "Criteria", "body": _table(
        ["criterion", "category", "earned", "points", "explanation"], [[c["description"], c["category"], c["earned"], c["points"], c["explanation"]] for c in crit])})
    sections.append({"heading": "Critical failures", "body": _list([f"{c['description']} {c['detail']}" for c in crits] or ["None."])})
    sections.append({"heading": "Missing tasks", "body": _list(missing or ["None."])})
    sections.append({"heading": "Recommended learning", "body": _list([f"{r['lesson_id']}: {'; '.join(r['because'])}" for r in recs] or ["None."])})


# --------------------------------------------------------------------------- renderers


def to_markdown(rep: dict[str, Any]) -> str:
    out = [f"# {rep['title']}", "", f"> {rep['statement']}", "",
           f"- Scenario: {rep['scenario']} (session {rep['session_id']}, attempt {rep['attempt']}, {rep['mode']} mode)",
           f"- Learner: {rep['learner']}", f"- Generated: {rep['generated_at']} — {rep['timezone']}", ""]

    def cell(v: Any) -> str:
        return str(v).replace("|", "\\|").replace("\n", " ")

    for sec in rep["sections"]:
        out += [f"## {sec['heading'].strip()}", ""]
        b = sec["body"]
        if b["kind"] == "text":
            out += [b["content"], ""]
        elif b["kind"] == "list":
            out += [f"- {i}" for i in b["items"]] + [""]
        else:
            if not b["rows"]:
                out += ["_No records._", ""]
                continue
            out.append("| " + " | ".join(b["columns"]) + " |")
            out.append("|" + "---|" * len(b["columns"]))
            out += ["| " + " | ".join(cell(v) for v in r) + " |" for r in b["rows"]]
            out.append("")
    return "\n".join(out)


def to_html(rep: dict[str, Any]) -> str:
    e = html.escape
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{e(rep['title'])}</title>",
        "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#1b2430;max-width:1200px}"
        "h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.6rem;border-bottom:1px solid #d5dbe3;padding-bottom:.3rem}"
        "table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{border:1px solid #d5dbe3;padding:.35rem .5rem;text-align:left;vertical-align:top}"
        "th{background:#eef2f7}.banner{background:#fff7e0;border:1px solid #e6c870;padding:.6rem .8rem;border-radius:6px}</style></head><body>",
        f"<h1>{e(rep['title'])}</h1>",
        f"<p class='banner'>{e(rep['statement'])}</p>",
        f"<p>Scenario {e(rep['scenario'])} · session {rep['session_id']} · attempt {rep['attempt']} · {e(rep['mode'])} mode · "
        f"learner {e(rep['learner'])} · generated {e(rep['generated_at'])} ({e(rep['timezone'])})</p>",
    ]
    for sec in rep["sections"]:
        parts.append(f"<h2>{e(sec['heading'].strip())}</h2>")
        b = sec["body"]
        if b["kind"] == "text":
            parts.append(f"<p>{e(b['content'])}</p>")
        elif b["kind"] == "list":
            parts.append("<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in b["items"]) + "</ul>")
        elif not b["rows"]:
            parts.append("<p><em>No records.</em></p>")
        else:
            parts.append("<table><thead><tr>" + "".join(f"<th>{e(c)}</th>" for c in b["columns"]) + "</tr></thead><tbody>")
            parts += ["<tr>" + "".join(f"<td>{e(str(v))}</td>" for v in r) + "</tr>" for r in b["rows"]]
            parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "".join(parts)


def to_csv(rep: dict[str, Any]) -> str:
    if rep["report_type"] not in TABULAR:
        raise DomainError("CSV export is available for tabular reports only")
    table = next(sec["body"] for sec in rep["sections"] if sec["body"]["kind"] == "table")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(table["columns"])
    for r in table["rows"]:
        # Neutralise spreadsheet formula injection.
        w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in r])
    return buf.getvalue()
