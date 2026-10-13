"""Synthetic enterprise inventory, discovery scanning, classification and access review."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..content.company import COMPANY
from ..db import get_db
from ..models import AccessGrant, ClassificationAssignment, DataAsset, ScenarioSession, SimGroup, SimIdentity, User
from ..security import current_user
from ..services import detection, discovery
from ..services.common import iso
from ..services.investigation import destinations
from ..services.simulation import access_path, get_asset, groups_of, record_action
from .deps import read_session, write_session

router = APIRouter(prefix="/api/sessions/{session_id}", tags=["environment"])


def identity_out(i: SimIdentity, groups: list[str]) -> dict:
    attrs = {k: v for k, v in (i.attributes or {}).items()}
    return {"key": i.key, "display_name": i.display_name, "email": i.email, "department": i.department, "title": i.title,
            "enterprise_role": i.enterprise_role, "employment_type": i.employment_type, "manager_key": i.manager_key,
            "status": i.status, "sessions_revoked_at": iso(i.sessions_revoked_at), "attributes": attrs, "groups": groups}


@router.get("/company")
def company(s: ScenarioSession = Depends(read_session)):
    return {**COMPANY, "provenance": "SIMULATED", "note": "Fictional organisation. All data is synthetic."}


@router.get("/identities")
def identities(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    groups = list(db.scalars(select(SimGroup).where(SimGroup.session_id == s.id)))
    out = []
    for i in db.scalars(select(SimIdentity).where(SimIdentity.session_id == s.id).order_by(SimIdentity.key)):
        out.append(identity_out(i, sorted(g.key for g in groups if i.key in g.members)))
    return out


@router.get("/groups")
def groups(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"key": g.key, "name": g.name, "description": g.description, "members": g.members}
            for g in db.scalars(select(SimGroup).where(SimGroup.session_id == s.id).order_by(SimGroup.key))]


@router.get("/destinations")
def list_destinations(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"key": d.key, "name": d.name, "kind": d.kind, "domain": d.domain, "category": d.category,
             "sanctioned": d.sanctioned, "internal": d.internal, "blocked": d.blocked} for d in destinations(db, s)]


@router.get("/labels")
def labels(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"key": lab.key, "name": lab.name, "rank": lab.rank, "description": lab.description, "handling": lab.handling}
            for lab in discovery.labels(db, s)]


@router.get("/assets")
def assets(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db),
           q: str | None = Query(None, max_length=100), label: str | None = None, department: str | None = None,
           unlabeled: bool = False, no_owner: bool = False):
    scan, findings = discovery.latest_findings(db, s)
    by_asset: dict[str, list] = {}
    for f in findings:
        by_asset.setdefault(f.asset_key, []).append(f)
    out = []
    for a in db.scalars(select(DataAsset).where(DataAsset.session_id == s.id).order_by(DataAsset.key)):
        if q and q.lower() not in f"{a.name} {a.location} {a.description} {a.key}".lower():
            continue
        if label and a.label_key != label:
            continue
        if department and a.department != department:
            continue
        if unlabeled and a.label_key:
            continue
        if no_owner and a.owner_key:
            continue
        fs = by_asset.get(a.key, [])
        out.append({**discovery.asset_summary(a), "detectors": sorted({f.detector for f in fs}),
                    "recommended_label": fs[0].recommended_label if fs else None, "scanned": scan is not None})
    return out


@router.get("/assets/{asset_key}")
def asset_detail(asset_key: str, session_id: int, user: User = Depends(current_user), db: Session = Depends(get_db),
                 s: ScenarioSession = Depends(read_session)):
    a = get_asset(db, s, asset_key)
    if s.user_id == user.id and s.status == "ACTIVE":
        viewed = list((s.flags or {}).get("viewed_assets", []))
        if a.key not in viewed:
            s.flags = {**(s.flags or {}), "viewed_assets": viewed + [a.key]}
            db.commit()
    _scan, findings = discovery.latest_findings(db, s)
    grants = db.scalars(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.asset_key == a.key).order_by(AccessGrant.key)).all()
    group_map = {g.key: g for g in db.scalars(select(SimGroup).where(SimGroup.session_id == s.id))}
    effective = []
    for i in db.scalars(select(SimIdentity).where(SimIdentity.session_id == s.id).order_by(SimIdentity.key)):
        p = access_path(db, s, i, a)
        if p["allowed"]:
            effective.append({"identity": i.key, "display_name": i.display_name, "employment_type": i.employment_type,
                              "department": i.department, "via": p["via"], "permission": p["permission"]})
    history = db.scalars(select(ClassificationAssignment).where(ClassificationAssignment.session_id == s.id,
                                                                ClassificationAssignment.asset_key == a.key).order_by(ClassificationAssignment.id)).all()
    return {
        **discovery.asset_summary(a), "description": a.description, "content_sample": a.content_sample,
        "handling_notes": a.handling_notes, "exception_note": a.exception_note, "provenance": "SIMULATED",
        "findings": [{"detector": f.detector, "match_count": f.match_count, "confidence": f.confidence, "evidence": f.evidence,
                      "recommended_label": f.recommended_label, "rule_keys": f.rule_keys} for f in findings if f.asset_key == a.key],
        "grants": [{"key": g.key, "principal_type": g.principal_type, "principal_key": g.principal_key,
                    "principal_name": group_map[g.principal_key].name if g.principal_key in group_map else g.principal_key,
                    "members": group_map[g.principal_key].members if g.principal_key in group_map else [g.principal_key],
                    "permission": g.permission, "justification": g.justification, "status": g.status,
                    "review_decision": g.review_decision, "review_note": g.review_note} for g in grants],
        "effective_access": effective,
        "classification_history": [{"label": h.label_key, "previous": h.previous_label_key, "owner": h.owner_key,
                                    "justification": h.justification, "sim_time": iso(h.sim_time)} for h in history],
    }


@router.get("/access")
def access_grants(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db), asset: str | None = None):
    q = select(AccessGrant).where(AccessGrant.session_id == s.id)
    if asset:
        q = q.where(AccessGrant.asset_key == asset)
    return [{"key": g.key, "asset_key": g.asset_key, "principal_type": g.principal_type, "principal_key": g.principal_key,
             "permission": g.permission, "justification": g.justification, "status": g.status,
             "review_decision": g.review_decision, "review_note": g.review_note, "revoked_at": iso(g.revoked_at)}
            for g in db.scalars(q.order_by(AccessGrant.key))]


@router.get("/identities/{identity_key}/access")
def identity_access(identity_key: str, s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    from ..services.simulation import get_identity
    i = get_identity(db, s, identity_key)
    out = []
    for a in db.scalars(select(DataAsset).where(DataAsset.session_id == s.id).order_by(DataAsset.key)):
        p = access_path(db, s, i, a)
        if p["allowed"]:
            out.append({"asset_key": a.key, "name": a.name, "label_key": a.label_key, "via": p["via"], "permission": p["permission"]})
    return {"identity": identity_key, "groups": groups_of(db, s, identity_key), "access": out}


class ReviewIn(BaseModel):
    decision: Literal["KEEP", "REVOKE"]
    note: str = Field(min_length=5, max_length=1000)


@router.post("/access/{grant_key}/review")
def review(grant_key: str, body: ReviewIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    g = discovery.review_grant(db, s, grant_key=grant_key, decision=body.decision, note=body.note)
    db.commit()
    return {"key": g.key, "status": g.status, "review_decision": g.review_decision, "review_note": g.review_note}


# --------------------------------------------------------------------------- discovery & classification


@router.get("/discovery/detectors")
def detectors(s: ScenarioSession = Depends(read_session)):
    return detection.detector_catalog()


@router.post("/discovery/scan")
def scan(s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    sc = discovery.run_scan(db, s)
    db.commit()
    return {"scan_number": sc.scan_number, "assets_scanned": sc.assets_scanned, "findings": sc.findings_count,
            "sim_time": iso(sc.sim_time), "provenance": "SIMULATED",
            "scope": "Each synthetic asset's stored content sample was inspected by the enabled detectors."}


@router.get("/discovery/findings")
def findings(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db),
             detector: str | None = None, min_confidence: str | None = None):
    scan, fs = discovery.latest_findings(db, s)
    order = detection.CONFIDENCE_ORDER
    out = [{"asset_key": f.asset_key, "detector": f.detector, "match_count": f.match_count, "confidence": f.confidence,
            "evidence": f.evidence, "recommended_label": f.recommended_label, "rule_keys": f.rule_keys}
           for f in fs if (not detector or f.detector == detector) and (not min_confidence or order[f.confidence] >= order.get(min_confidence, 0))]
    return {"scan": None if scan is None else {"scan_number": scan.scan_number, "sim_time": iso(scan.sim_time),
                                                "assets_scanned": scan.assets_scanned, "rule_snapshot": scan.rule_snapshot},
            "findings": out}


@router.get("/classification/rules")
def get_rules(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    return [{"key": r.key, "name": r.name, "detectors": r.detectors, "min_matches": r.min_matches,
             "min_confidence": r.min_confidence, "recommended_label": r.recommended_label, "enabled": r.enabled, "version": r.version}
            for r in discovery.rules(db, s)]


class RuleIn(BaseModel):
    enabled: bool
    min_matches: int = Field(ge=1, le=10_000)
    min_confidence: Literal["LOW", "MEDIUM", "HIGH"]
    recommended_label: str = Field(max_length=40)
    detectors: list[str] = Field(min_length=1, max_length=10)


@router.put("/classification/rules/{rule_key}")
def put_rule(rule_key: str, body: RuleIn, s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    r = discovery.update_rule(db, s, rule_key, enabled=body.enabled, min_matches=body.min_matches,
                              min_confidence=body.min_confidence, recommended_label=body.recommended_label, detectors=body.detectors)
    db.commit()
    return {"key": r.key, "version": r.version}


class AssignIn(BaseModel):
    asset_key: str = Field(max_length=60)
    label_key: str = Field(max_length=40)
    justification: str = Field(min_length=10, max_length=2000)
    owner_key: str | None = Field(default=None, max_length=60)
    handling_notes: str = Field(default="", max_length=2000)
    exception_note: str = Field(default="", max_length=2000)


@router.post("/classification/assign")
def assign(body: AssignIn, user: User = Depends(current_user), s: ScenarioSession = Depends(write_session), db: Session = Depends(get_db)):
    rec = discovery.assign_label(db, s, user.id, asset_key=body.asset_key, label_key=body.label_key, justification=body.justification,
                                 owner_key=body.owner_key, handling_notes=body.handling_notes, exception_note=body.exception_note)
    db.commit()
    return {"asset_key": rec.asset_key, "label_key": rec.label_key, "previous_label_key": rec.previous_label_key,
            "owner_key": rec.owner_key, "sim_time": iso(rec.sim_time)}


@router.get("/classification/register")
def register(s: ScenarioSession = Depends(read_session), db: Session = Depends(get_db)):
    hist = db.scalars(select(ClassificationAssignment).where(ClassificationAssignment.session_id == s.id).order_by(ClassificationAssignment.id)).all()
    return {
        "assets": [{**discovery.asset_summary(a), "handling_notes": a.handling_notes, "exception_note": a.exception_note}
                   for a in db.scalars(select(DataAsset).where(DataAsset.session_id == s.id).order_by(DataAsset.key))],
        "history": [{"asset_key": h.asset_key, "label": h.label_key, "previous": h.previous_label_key, "owner": h.owner_key,
                     "justification": h.justification, "handling_notes": h.handling_notes, "exception_note": h.exception_note,
                     "sim_time": iso(h.sim_time)} for h in hist],
    }
