"""Security Event Explorer, alert triage, investigation cases, remediation and risk model."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    AccessGrant, Alert, CaseNote, ClassificationFinding, DataAsset, EvidenceReference, InvestigationCase,
    RemediationAction, ScenarioSession, SecurityEvent, SimIdentity,
)
from ..services.common import DomainError, iso
from ..services.investigation import (
    DETERMINATIONS, DISPOSITIONS, EXPOSURE_STATUSES, PARTIES, ROOT_CAUSES, SEVERITIES, apply_remediation, correlate,
    risk_score, verify_state,
)
from ..services.simulation import advance_clock, label_ranks, record_action
from .deps import alert_out, event_out, read_session, write_session

router = APIRouter(prefix="/api/sessions/{session_id}", tags=["investigation"])


@router.get("/investigation/vocabulary")
def vocabulary(s: ScenarioSession = Depends(read_session)):
    return {"dispositions": DISPOSITIONS, "determinations": DETERMINATIONS, "exposure_statuses": EXPOSURE_STATUSES,
            "root_causes": ROOT_CAUSES, "severities": SEVERITIES, "escalation_parties": PARTIES,
            "note_kinds": ["OBSERVATION", "INFERENCE", "UNKNOWN", "HYPOTHESIS"],
            "evidence_types": ["EVENT", "ALERT", "ASSET", "IDENTITY", "GRANT", "POLICY_VERSION", "FINDING"]}


# --------------------------------------------------------------------------- events


@router.get("/events")
def events(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db),
           q: str | None = Query(None, max_length=100), actor: str | None = None, resource: str | None = None,
           source_type: str | None = None, result: str | None = None, run: int | None = None, transaction: str | None = None,
           limit: int = Query(500, ge=1, le=2000)):
    qry = select(SecurityEvent).where(SecurityEvent.session_id == s.id)
    if actor:
        qry = qry.where(SecurityEvent.actor_id == actor)
    if resource:
        qry = qry.where(SecurityEvent.resource_id == resource)
    if source_type:
        qry = qry.where(SecurityEvent.source_type == source_type)
    if result:
        qry = qry.where(SecurityEvent.result == result)
    if run is not None:
        qry = qry.where(SecurityEvent.run_number == run)
    if transaction:
        qry = qry.where(SecurityEvent.transaction_id == transaction)
    if q:
        like = f"%{q}%"
        qry = qry.where(or_(SecurityEvent.summary.ilike(like), SecurityEvent.event_id.ilike(like),
                            SecurityEvent.actor_id.ilike(like), SecurityEvent.resource_id.ilike(like)))
    return [event_out(e) for e in db.scalars(qry.order_by(SecurityEvent.timestamp, SecurityEvent.seq).limit(limit))]


@router.get("/events/{event_id}")
def event(event_id: str, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    e = db.scalar(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.event_id == event_id))
    if e is None:
        raise HTTPException(404, "Event not found")
    related = db.scalars(select(SecurityEvent).where(SecurityEvent.session_id == s.id,
                                                     SecurityEvent.event_id.in_(e.related_event_ids or []))).all()
    alerts = [a for a in db.scalars(select(Alert).where(Alert.session_id == s.id)) if e.event_id in (a.event_ids or [])]
    return {**event_out(e), "related": [event_out(r) for r in related], "alerts": [alert_out(a) for a in alerts]}


# --------------------------------------------------------------------------- alerts


@router.get("/alerts")
def alerts(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db), status: str | None = None,
           run: int | None = None, undispositioned: bool = False):
    q = select(Alert).where(Alert.session_id == s.id)
    if status:
        q = q.where(Alert.status == status)
    if run is not None:
        q = q.where(Alert.run_number == run)
    if undispositioned:
        q = q.where(Alert.disposition.is_(None))
    return [alert_out(a) for a in db.scalars(q.order_by(Alert.timestamp, Alert.id))]


def _get_alert(db: Session, s: ScenarioSession, alert_id: str) -> Alert:
    a = db.scalar(select(Alert).where(Alert.session_id == s.id, Alert.alert_id == alert_id))
    if a is None:
        raise HTTPException(404, "Alert not found")
    return a


@router.get("/alerts/{alert_id}")
def alert(alert_id: str, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    a = _get_alert(db, s, alert_id)
    corr = correlate(db, s, a)
    ev = {e.event_id: e for e in db.scalars(select(SecurityEvent).where(
        SecurityEvent.session_id == s.id, SecurityEvent.event_id.in_([c["event_id"] for c in corr])))}
    cases = [c.id for c in db.scalars(select(InvestigationCase).where(InvestigationCase.session_id == s.id)) if a.alert_id in (c.alert_ids or [])]
    return {**alert_out(a), "correlated": [{**c, "event": event_out(ev[c["event_id"]])} for c in corr], "case_ids": cases,
            "correlation_method": "Events share an explicit attribute with the alert (transaction, recorded relation, actor or resource) "
                                  "within 24 hours. Time proximity alone never links events."}


class DispositionIn(BaseModel):
    disposition: Literal["TRUE_POSITIVE", "BENIGN_POSITIVE", "FALSE_POSITIVE", "UNDETERMINED"]
    note: str = Field(min_length=10, max_length=2000)


@router.post("/alerts/{alert_id}/disposition")
def disposition(alert_id: str, body: DispositionIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    a = _get_alert(db, s, alert_id)
    a.disposition = body.disposition
    a.disposition_note = body.note
    a.status = "CLOSED" if body.disposition in ("BENIGN_POSITIVE", "FALSE_POSITIVE") else "IN_PROGRESS"
    advance_clock(s)
    record_action(db, s, "ALERT_DISPOSITION", {"alert": alert_id, "disposition": body.disposition})
    db.commit()
    return alert_out(a)


# --------------------------------------------------------------------------- cases


def case_out(db: Session, c: InvestigationCase, *, detail: bool = False) -> dict:
    out = {"id": c.id, "title": c.title, "status": c.status, "alert_ids": c.alert_ids, "hypothesis": c.hypothesis,
           "severity": c.severity, "determination": c.determination, "subject_identities": c.subject_identities,
           "affected_asset_keys": c.affected_asset_keys, "exposure_status": c.exposure_status,
           "records_potentially_exposed": c.records_potentially_exposed, "root_causes": c.root_causes, "summary": c.summary,
           "root_cause_narrative": c.root_cause_narrative, "residual_risk": c.residual_risk, "lessons_learned": c.lessons_learned,
           "created_at": iso(c.created_at), "updated_at": iso(c.updated_at)}
    if detail:
        out["evidence"] = [{"id": e.id, "ref_type": e.ref_type, "ref_id": e.ref_id, "label": e.label, "note": e.note,
                            "created_at": iso(e.created_at)}
                           for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == c.id).order_by(EvidenceReference.id))]
        out["notes"] = [{"id": n.id, "kind": n.kind, "text": n.text, "evidence_ids": n.evidence_ids, "created_at": iso(n.created_at)}
                        for n in db.scalars(select(CaseNote).where(CaseNote.case_id == c.id).order_by(CaseNote.id))]
        out["remediations"] = [rem_out(r) for r in db.scalars(select(RemediationAction).where(RemediationAction.case_id == c.id).order_by(RemediationAction.seq))]
    return out


def _get_case(db: Session, s: ScenarioSession, case_id: int) -> InvestigationCase:
    c = db.scalar(select(InvestigationCase).where(InvestigationCase.session_id == s.id, InvestigationCase.id == case_id))
    if c is None:
        raise HTTPException(404, "Case not found")
    return c


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    alert_ids: list[str] = Field(default_factory=list, max_length=50)
    hypothesis: str = Field(default="", max_length=2000)


@router.get("/cases")
def cases(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [case_out(db, c) for c in db.scalars(select(InvestigationCase).where(InvestigationCase.session_id == s.id).order_by(InvestigationCase.id))]


@router.post("/cases", status_code=201)
def create_case(body: CaseIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    for aid in body.alert_ids:
        al = _get_alert(db, s, aid)
        if al.status == "NEW":
            al.status = "IN_PROGRESS"
    c = InvestigationCase(session_id=s.id, title=body.title, alert_ids=sorted(set(body.alert_ids)), hypothesis=body.hypothesis)
    db.add(c)
    db.flush()
    for aid in c.alert_ids:
        db.add(EvidenceReference(case_id=c.id, ref_type="ALERT", ref_id=aid, label=f"Alert {aid}"))
    advance_clock(s)
    record_action(db, s, "CASE_CREATE", {"case_id": c.id, "alerts": c.alert_ids})
    db.commit()
    return case_out(db, c, detail=True)


@router.get("/cases/{case_id}")
def get_case(case_id: int, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return case_out(db, _get_case(db, s, case_id), detail=True)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    status: Literal["OPEN", "CONTAINED", "CLOSED"] | None = None
    hypothesis: str | None = Field(default=None, max_length=4000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    determination: str | None = None
    subject_identities: list[str] | None = Field(default=None, max_length=20)
    affected_asset_keys: list[str] | None = Field(default=None, max_length=50)
    exposure_status: str | None = None
    records_potentially_exposed: int | None = Field(default=None, ge=0, le=100_000_000)
    root_causes: list[str] | None = Field(default=None, max_length=10)
    alert_ids: list[str] | None = Field(default=None, max_length=50)
    summary: str | None = Field(default=None, max_length=8000)
    root_cause_narrative: str | None = Field(default=None, max_length=8000)
    residual_risk: str | None = Field(default=None, max_length=8000)
    lessons_learned: str | None = Field(default=None, max_length=8000)


@router.patch("/cases/{case_id}")
def patch_case(case_id: int, body: CasePatch, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    data = body.model_dump(exclude_unset=True)
    if "determination" in data and data["determination"] not in DETERMINATIONS + [None]:
        raise DomainError(f"determination must be one of {DETERMINATIONS}")
    if "exposure_status" in data and data["exposure_status"] not in EXPOSURE_STATUSES + [None]:
        raise DomainError(f"exposure_status must be one of {EXPOSURE_STATUSES}")
    if "root_causes" in data and not set(data["root_causes"]) <= set(ROOT_CAUSES):
        raise DomainError(f"root_causes must be from {ROOT_CAUSES}")
    if "subject_identities" in data:
        known = {i.key for i in db.scalars(select(SimIdentity).where(SimIdentity.session_id == s.id))}
        if not set(data["subject_identities"]) <= known:
            raise DomainError("Unknown subject identity")
    if "affected_asset_keys" in data:
        known = {a.key for a in db.scalars(select(DataAsset).where(DataAsset.session_id == s.id))}
        if not set(data["affected_asset_keys"]) <= known:
            raise DomainError("Unknown asset key")
    if "alert_ids" in data:
        for aid in data["alert_ids"]:
            _get_alert(db, s, aid)
    for k, v in data.items():
        setattr(c, k, v)
    record_action(db, s, "CASE_UPDATE", {"case_id": c.id, "fields": sorted(data)})
    db.commit()
    return case_out(db, c, detail=True)


class NoteIn(BaseModel):
    kind: Literal["OBSERVATION", "INFERENCE", "UNKNOWN", "HYPOTHESIS"]
    text: str = Field(min_length=5, max_length=4000)
    evidence_ids: list[int] = Field(default_factory=list, max_length=20)


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    valid = {e.id for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == c.id))}
    if not set(body.evidence_ids) <= valid:
        raise DomainError("Notes may only cite evidence already linked to this case")
    if body.kind == "OBSERVATION" and not body.evidence_ids:
        raise DomainError("An observation must cite at least one linked evidence item; use INFERENCE or HYPOTHESIS otherwise")
    n = CaseNote(case_id=c.id, kind=body.kind, text=body.text, evidence_ids=body.evidence_ids)
    db.add(n)
    record_action(db, s, "CASE_NOTE", {"case_id": c.id, "kind": body.kind})
    db.commit()
    return {"id": n.id, "kind": n.kind, "text": n.text, "evidence_ids": n.evidence_ids}


@router.delete("/cases/{case_id}/notes/{note_id}")
def delete_note(case_id: int, note_id: int, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    n = db.scalar(select(CaseNote).where(CaseNote.case_id == c.id, CaseNote.id == note_id))
    if n is None:
        raise HTTPException(404, "Note not found")
    db.delete(n)
    record_action(db, s, "CASE_NOTE_DELETE", {"case_id": c.id, "note_id": note_id})
    db.commit()
    return {"ok": True}


class EvidenceIn(BaseModel):
    ref_type: Literal["EVENT", "ALERT", "ASSET", "IDENTITY", "GRANT", "POLICY_VERSION", "FINDING"]
    ref_id: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=1000)


def _evidence_label(db: Session, s: ScenarioSession, ref_type: str, ref_id: str) -> str:
    """Resolve an evidence reference against session state; reject anything that does not exist."""
    if ref_type == "EVENT":
        e = db.scalar(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.event_id == ref_id))
        if e:
            return f"{e.event_id} {iso(e.timestamp)} {e.summary}"[:300]
    elif ref_type == "ALERT":
        a = db.scalar(select(Alert).where(Alert.session_id == s.id, Alert.alert_id == ref_id))
        if a:
            return f"{a.alert_id} {a.title}"[:300]
    elif ref_type == "ASSET":
        a = db.scalar(select(DataAsset).where(DataAsset.session_id == s.id, DataAsset.key == ref_id))
        if a:
            return f"Asset {a.name} ({a.location})"[:300]
    elif ref_type == "IDENTITY":
        i = db.scalar(select(SimIdentity).where(SimIdentity.session_id == s.id, SimIdentity.key == ref_id))
        if i:
            return f"Identity {i.display_name} — {i.title} ({i.employment_type})"
    elif ref_type == "GRANT":
        g = db.scalar(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.key == ref_id))
        if g:
            return f"Grant {g.key}: {g.principal_type} {g.principal_key} {g.permission} on {g.asset_key} ({g.status})"
    elif ref_type == "POLICY_VERSION":
        from ..services.policies import get_policy
        key, _, ver = ref_id.partition("@v")
        try:
            p = get_policy(db, s, key)
            if ver and int(ver) in {v.version for v in p.versions}:
                return f"Policy {key} version {ver}"
        except (DomainError, ValueError):
            pass
    elif ref_type == "FINDING":
        if ref_id.isdigit():
            f = db.scalar(select(ClassificationFinding).where(ClassificationFinding.session_id == s.id, ClassificationFinding.id == int(ref_id)))
            if f:
                return f"Finding {f.detector}×{f.match_count} ({f.confidence}) on {f.asset_key}"
    raise DomainError(f"{ref_type} '{ref_id}' does not exist in this session", 404)


@router.post("/cases/{case_id}/evidence", status_code=201)
def add_evidence(case_id: int, body: EvidenceIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    label = _evidence_label(db, s, body.ref_type, body.ref_id)
    if db.scalar(select(EvidenceReference).where(EvidenceReference.case_id == c.id, EvidenceReference.ref_type == body.ref_type,
                                                 EvidenceReference.ref_id == body.ref_id)):
        raise HTTPException(409, "Evidence already linked")
    e = EvidenceReference(case_id=c.id, ref_type=body.ref_type, ref_id=body.ref_id, label=label, note=body.note)
    db.add(e)
    if body.ref_type == "EVENT":
        ev = db.scalar(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.event_id == body.ref_id))
        ev.evidence_refs = sorted(set((ev.evidence_refs or []) + [f"case:{c.id}"]))
    record_action(db, s, "CASE_EVIDENCE", {"case_id": c.id, "ref_type": body.ref_type, "ref_id": body.ref_id})
    db.commit()
    return {"id": e.id, "ref_type": e.ref_type, "ref_id": e.ref_id, "label": e.label, "note": e.note}


@router.delete("/cases/{case_id}/evidence/{evidence_id}")
def remove_evidence(case_id: int, evidence_id: int, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    e = db.scalar(select(EvidenceReference).where(EvidenceReference.case_id == c.id, EvidenceReference.id == evidence_id))
    if e is None:
        raise HTTPException(404, "Evidence not found")
    cited = [n for n in db.scalars(select(CaseNote).where(CaseNote.case_id == c.id)) if evidence_id in (n.evidence_ids or [])]
    if cited:
        raise DomainError("Evidence is cited by case notes; remove or edit those notes first", 409)
    db.delete(e)
    record_action(db, s, "CASE_EVIDENCE_REMOVE", {"case_id": c.id, "evidence_id": evidence_id})
    db.commit()
    return {"ok": True}


@router.get("/cases/{case_id}/timeline")
def case_timeline(case_id: int, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    c = _get_case(db, s, case_id)
    ids = {e.ref_id for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == c.id, EvidenceReference.ref_type == "EVENT"))}
    linked = set(ids)
    for a in db.scalars(select(Alert).where(Alert.session_id == s.id, Alert.alert_id.in_(c.alert_ids or []))):
        ids |= set(a.event_ids or [])
    evs = db.scalars(select(SecurityEvent).where(SecurityEvent.session_id == s.id, SecurityEvent.event_id.in_(ids))
                     .order_by(SecurityEvent.timestamp, SecurityEvent.seq)).all()
    return [{**event_out(e), "linked_as_evidence": e.event_id in linked} for e in evs]


# --------------------------------------------------------------------------- remediation & risk


def rem_out(r: RemediationAction) -> dict:
    return {"id": r.id, "seq": r.seq, "case_id": r.case_id, "action_type": r.action_type, "target_key": r.target_key,
            "justification": r.justification, "status": r.status, "before_state": r.before_state, "after_state": r.after_state,
            "verification": r.verification, "provenance": r.provenance, "sim_time": iso(r.sim_time)}


class RemediationIn(BaseModel):
    action_type: str = Field(max_length=40)
    target_key: str = Field(max_length=80)
    justification: str = Field(min_length=10, max_length=2000)
    case_id: int | None = None
    confirm_destructive: bool = False


@router.post("/remediation", status_code=201)
def remediate(body: RemediationIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    r = apply_remediation(db, s, action_type=body.action_type, target_key=body.target_key, justification=body.justification,
                          case_id=body.case_id, confirm_destructive=body.confirm_destructive)
    db.commit()
    return rem_out(r)


@router.get("/remediation")
def remediations(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [rem_out(r) for r in db.scalars(select(RemediationAction).where(RemediationAction.session_id == s.id).order_by(RemediationAction.seq))]


@router.post("/remediation/{rem_id}/verify")
def reverify(rem_id: int, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    r = db.scalar(select(RemediationAction).where(RemediationAction.session_id == s.id, RemediationAction.id == rem_id))
    if r is None:
        raise HTTPException(404, "Remediation action not found")
    advance_clock(s)
    r.verification = verify_state(db, s, r)
    if r.status not in ("RECORDED",):
        r.status = "VERIFIED" if r.verification.get("verified") else "VERIFICATION_FAILED"
    record_action(db, s, "REMEDIATION_VERIFY", {"remediation_id": r.id}, {"status": r.status})
    db.commit()
    return rem_out(r)


class RiskIn(BaseModel):
    label: str | None = None
    records: int = Field(ge=0, le=100_000_000)
    destination_external: bool
    data_left_org: Literal["YES", "NO", "UNKNOWN"]


@router.post("/risk-score")
def risk(body: RiskIn, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    ranks = label_ranks(db, s)
    if body.label is not None and body.label not in ranks:
        raise DomainError("Unknown label")
    return {**risk_score(label_rank=ranks.get(body.label) if body.label else None, records=body.records,
                         destination_external=body.destination_external, data_left_org=body.data_left_org),
            "model": "severity = sensitivity(0-3) + volume(0-2) + external destination(0/2) + data left org(0/1/2); "
                     ">=8 CRITICAL, 6-7 HIGH, 3-5 MEDIUM, <=2 LOW"}
