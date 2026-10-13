"""Discovery scanning, classification register and access review."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    AccessGrant, ClassificationAssignment, ClassificationFinding, ClassificationLabel, ClassificationRule,
    DataAsset, DiscoveryScan, ScenarioSession,
)
from . import detection
from .common import DomainError, as_utc
from .investigation import apply_remediation
from .simulation import advance_clock, get_asset, get_identity, label_ranks, record_action


def rules(db: Session, s: ScenarioSession) -> list[ClassificationRule]:
    return list(db.scalars(select(ClassificationRule).where(ClassificationRule.session_id == s.id).order_by(ClassificationRule.key)))


def recommend(scan: dict[str, detection.DetectorResult], rule_list: list[ClassificationRule], ranks: dict[str, int]) -> tuple[str | None, list[str]]:
    """Highest-ranked label among enabled rules whose detector, count and confidence thresholds are met."""
    hits: list[tuple[int, str, str]] = []
    for r in rule_list:
        if not r.enabled:
            continue
        for det in r.detectors:
            res = scan.get(det)
            if res and res.match_count >= r.min_matches and \
                    detection.CONFIDENCE_ORDER[res.confidence] >= detection.CONFIDENCE_ORDER[r.min_confidence]:
                hits.append((ranks.get(r.recommended_label, -1), r.recommended_label, r.key))
                break
    if not hits:
        return None, []
    best = max(hits)
    return best[1], sorted({h[2] for h in hits})


def run_scan(db: Session, s: ScenarioSession) -> DiscoveryScan:
    advance_clock(s)
    rule_list = rules(db, s)
    ranks = label_ranks(db, s)
    n = (db.scalar(select(func.count(DiscoveryScan.id)).where(DiscoveryScan.session_id == s.id)) or 0) + 1
    scan = DiscoveryScan(session_id=s.id, scan_number=n, sim_time=as_utc(s.sim_clock),
                         rule_snapshot=[{"key": r.key, "detectors": r.detectors, "min_matches": r.min_matches,
                                         "min_confidence": r.min_confidence, "label": r.recommended_label,
                                         "enabled": r.enabled, "version": r.version} for r in rule_list])
    db.add(scan)
    db.flush()
    count = 0
    assets = db.scalars(select(DataAsset).where(DataAsset.session_id == s.id).order_by(DataAsset.key)).all()
    for a in assets:
        res = detection.scan_text(a.content_sample)
        label, rule_keys = recommend(res, rule_list, ranks)
        for det, r in res.items():
            db.add(ClassificationFinding(
                session_id=s.id, scan_id=scan.id, asset_key=a.key, detector=det, match_count=r.match_count,
                confidence=r.confidence, evidence=r.evidence, recommended_label=label,
                rule_keys=[k for k in rule_keys if det in next(x.detectors for x in rule_list if x.key == k)],
            ))
            count += 1
    scan.assets_scanned = len(assets)
    scan.findings_count = count
    record_action(db, s, "DISCOVERY_SCAN", {"scan_number": n}, {"findings": count})
    return scan


def latest_findings(db: Session, s: ScenarioSession) -> tuple[DiscoveryScan | None, list[ClassificationFinding]]:
    scan = db.scalar(select(DiscoveryScan).where(DiscoveryScan.session_id == s.id).order_by(DiscoveryScan.scan_number.desc()).limit(1))
    if scan is None:
        return None, []
    return scan, list(db.scalars(select(ClassificationFinding).where(ClassificationFinding.scan_id == scan.id)
                                 .order_by(ClassificationFinding.asset_key, ClassificationFinding.detector)))


def assign_label(db: Session, s: ScenarioSession, user_id: int, *, asset_key: str, label_key: str, justification: str,
                 owner_key: str | None, handling_notes: str, exception_note: str) -> ClassificationAssignment:
    asset = get_asset(db, s, asset_key)
    if label_key not in label_ranks(db, s):
        raise DomainError(f"Unknown label '{label_key}'")
    if owner_key:
        owner = get_identity(db, s, owner_key)
        if owner.employment_type in ("SERVICE", "TEST"):
            raise DomainError("A data owner must be an accountable person, not a service or test identity")
    advance_clock(s)
    rec = ClassificationAssignment(
        session_id=s.id, asset_key=asset.key, label_key=label_key, previous_label_key=asset.label_key,
        owner_key=owner_key or asset.owner_key, justification=justification, handling_notes=handling_notes,
        exception_note=exception_note, assigned_by=user_id, sim_time=as_utc(s.sim_clock),
    )
    asset.label_key = label_key
    if owner_key:
        asset.owner_key = owner_key
    asset.handling_notes = handling_notes
    asset.exception_note = exception_note
    db.add(rec)
    record_action(db, s, "CLASSIFY", {"asset": asset.key, "label": label_key, "owner": asset.owner_key},
                  {"previous": rec.previous_label_key})
    db.flush()
    return rec


def update_rule(db: Session, s: ScenarioSession, key: str, *, enabled: bool, min_matches: int, min_confidence: str,
                recommended_label: str, detectors: list[str]) -> ClassificationRule:
    r = db.scalar(select(ClassificationRule).where(ClassificationRule.session_id == s.id, ClassificationRule.key == key))
    if r is None:
        raise DomainError("Unknown classification rule", 404)
    if recommended_label not in label_ranks(db, s):
        raise DomainError(f"Unknown label '{recommended_label}'")
    unknown = [d for d in detectors if d not in detection.DETECTORS]
    if unknown or not detectors:
        raise DomainError(f"Unknown or empty detector list: {unknown}")
    if min_confidence not in detection.CONFIDENCE_ORDER:
        raise DomainError("min_confidence must be LOW, MEDIUM or HIGH")
    before = {"enabled": r.enabled, "min_matches": r.min_matches, "min_confidence": r.min_confidence,
              "recommended_label": r.recommended_label, "detectors": r.detectors}
    r.enabled, r.min_matches, r.min_confidence = enabled, min_matches, min_confidence
    r.recommended_label, r.detectors = recommended_label, detectors
    r.version += 1
    record_action(db, s, "CLASSIFICATION_RULE_UPDATE", {"rule": key, "before": before, "version": r.version})
    return r


def review_grant(db: Session, s: ScenarioSession, *, grant_key: str, decision: str, note: str) -> AccessGrant:
    g = db.scalar(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.key == grant_key))
    if g is None:
        raise DomainError("Unknown grant", 404)
    if decision not in ("KEEP", "REVOKE"):
        raise DomainError("decision must be KEEP or REVOKE")
    if decision == "REVOKE" and g.status == "ACTIVE":
        apply_remediation(db, s, action_type="REVOKE_GRANT", target_key=g.key, justification=note or "Access review",
                          case_id=None, confirm_destructive=False)
        record_action(db, s, "GRANT_REVIEW_REVOKE", {"grant": g.key, "note": note})
    else:
        record_action(db, s, "GRANT_REVIEW_KEEP" if decision == "KEEP" else "GRANT_REVIEW_REVOKE", {"grant": g.key, "note": note})
    g.review_decision = decision
    g.review_note = note
    return g


def labels(db: Session, s: ScenarioSession) -> list[ClassificationLabel]:
    return list(db.scalars(select(ClassificationLabel).where(ClassificationLabel.session_id == s.id).order_by(ClassificationLabel.rank)))


def asset_summary(a: DataAsset) -> dict[str, Any]:
    return {"key": a.key, "name": a.name, "asset_type": a.asset_type, "data_structure": a.data_structure, "system": a.system,
            "location": a.location, "department": a.department, "owner_key": a.owner_key, "label_key": a.label_key,
            "record_count": a.record_count, "size_bytes": a.size_bytes, "quarantined": a.quarantined}
