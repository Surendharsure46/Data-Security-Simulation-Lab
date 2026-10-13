"""Reusable learner journeys driven only through the public API."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

GOOD_LABELS = {
    "ast-cust-export-q1": ("restricted", "u-hpatel"),
    "ast-crm-customers": ("restricted", None),
    "ast-support-tickets": ("confidential", None),
    "ast-employee-directory": ("internal", None),
    "ast-cust-sample-masked": ("internal", None),
    "ast-qa-test-cards": ("internal", None),
    "ast-api-config": ("restricted", "u-tbrandt"),
    "ast-vendor-contract": ("confidential", None),
    "ast-cloud-customers-2025": ("restricted", "u-hpatel"),
}

BLOCK_POLICY = {
    "name": "Block sensitive customer data to personal or unsanctioned destinations",
    "description": "Blocks transfers of Confidential+ data, or content with regulated identifiers, to unsanctioned destinations.",
    "kind": "DLP",
    "priority": 10,
    "applies_to_actions": ["UPLOAD", "EMAIL", "COPY_TO_USB", "AI_PROMPT", "PRINT"],
    "conditions": {"match": "all", "conditions": [
        {"field": "destination.sanctioned", "op": "eq", "value": False},
        {"match": "any", "conditions": [
            {"field": "content.label", "op": "label_at_least", "value": "confidential"},
            {"field": "content.detected_types", "op": "contains_any", "value": ["CREDIT_CARD", "US_SSN", "IBAN", "SECRET_CREDENTIAL"]},
        ]},
    ]},
    "outcome": "BLOCK",
    "severity": "HIGH",
    "alert": True,
    "alert_title": "Blocked sensitive transfer to unsanctioned destination",
}


def api(client: TestClient, h: dict, method: str, path: str, expect: int | tuple = (200, 201), **kw) -> Any:
    r = client.request(method, path, headers=h, **kw)
    ok = (expect,) if isinstance(expect, int) else expect
    assert r.status_code in ok, f"{method} {path} -> {r.status_code}: {r.text}"
    return r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text


def prepare_and_run_baseline(client: TestClient, h: dict, sid: int) -> dict:
    base = f"/api/sessions/{sid}"
    api(client, h, "POST", f"{base}/discovery/scan")
    api(client, h, "GET", f"{base}/assets/ast-cust-export-q1")
    for key, (label, owner) in GOOD_LABELS.items():
        body = {"asset_key": key, "label_key": label, "justification": f"Classified as {label} based on scan evidence and context"}
        if owner:
            body["owner_key"] = owner
        api(client, h, "POST", f"{base}/classification/assign", json=body)
    return api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})


def find_alert(alerts: list[dict], actor: str, policy: str) -> dict:
    return next(a for a in alerts if a["actor_id"] == actor and a["policy_id"] == policy)


def good_investigation(client: TestClient, h: dict, sid: int, culprit: str = "u-jokafor", ambiguous: str = "u-rsilva",
                       exfil_action: str = "UPLOAD") -> int:
    base = f"/api/sessions/{sid}"
    alerts = api(client, h, "GET", f"{base}/alerts?run=1")
    culprit_alerts = [a for a in alerts if a["actor_id"] == culprit]
    for a in alerts:
        if a["actor_id"] == culprit:
            disp = "TRUE_POSITIVE"
        elif a["actor_id"] == ambiguous:
            disp = "UNDETERMINED"
        else:
            disp = "BENIGN_POSITIVE"
        api(client, h, "POST", f"{base}/alerts/{a['alert_id']}/disposition", json={"disposition": disp, "note": "Assessed against linked evidence"})
    case = api(client, h, "POST", f"{base}/cases", json={"title": "Customer export leaves company", "alert_ids": [a["alert_id"] for a in culprit_alerts]})
    cid = case["id"]
    events = api(client, h, "GET", f"{base}/events?actor={culprit}&run=1&resource=ast-cust-export-q1")
    download = next(e for e in events if e["action"] == "DOWNLOAD")
    transfer = next(e for e in events if e["source_type"] in ("PROXY", "EMAIL_GATEWAY") and e["action"] == exfil_action)
    ev1 = api(client, h, "POST", f"{base}/cases/{cid}/evidence", json={"ref_type": "EVENT", "ref_id": download["event_id"]})
    api(client, h, "POST", f"{base}/cases/{cid}/evidence", json={"ref_type": "EVENT", "ref_id": transfer["event_id"]})
    api(client, h, "POST", f"{base}/cases/{cid}/evidence", json={"ref_type": "GRANT", "ref_id": "g-02"})
    api(client, h, "POST", f"{base}/cases/{cid}/notes", json={"kind": "OBSERVATION", "text": "Bulk download of 48,210 records followed by an allowed transfer", "evidence_ids": [ev1["id"]]})
    api(client, h, "POST", f"{base}/cases/{cid}/notes", json={"kind": "INFERENCE", "text": "The export left the company through a personal channel"})
    api(client, h, "POST", f"{base}/cases/{cid}/notes", json={"kind": "UNKNOWN", "text": "Whether the external copy was further shared is unknown"})
    risk = api(client, h, "POST", f"{base}/risk-score", json={"label": "restricted", "records": 48210, "destination_external": True, "data_left_org": "YES"})
    api(client, h, "PATCH", f"{base}/cases/{cid}", json={
        "severity": risk["severity"], "determination": "CONFIRMED_DATA_EXFILTRATION", "subject_identities": [culprit],
        "affected_asset_keys": ["ast-cust-export-q1"], "exposure_status": "CONFIRMED_EXFILTRATION",
        "records_potentially_exposed": 48210, "root_causes": ["EXCESSIVE_PERMISSION", "MISSING_CLASSIFICATION", "MONITOR_ONLY_POLICY"],
    })
    return cid


def good_remediation(client: TestClient, h: dict, sid: int, cid: int, culprit: str = "u-jokafor") -> None:
    base = f"/api/sessions/{sid}"
    for action, target in (("PRESERVE_EVIDENCE", culprit), ("DISABLE_ACCOUNT", culprit), ("ESCALATE", "PRIVACY_OFFICE")):
        r = api(client, h, "POST", f"{base}/remediation", json={"action_type": action, "target_key": target, "case_id": cid,
                                                                 "justification": "Containment per incident procedure"})
        assert r["status"] in ("VERIFIED", "RECORDED"), r
    api(client, h, "POST", f"{base}/access/g-02/review", json={"decision": "REVOKE", "note": "Agents do not need bulk extracts"})
    api(client, h, "POST", f"{base}/policies", json={"key": "POL-DLP-CUSTOMER", "definition": BLOCK_POLICY, "change_note": "Close exfiltration path"})
    email = api(client, h, "GET", f"{base}/policies/POL-DLP-EMAIL")["definition"]
    email["exceptions"] = [{"id": "EX-PAYROLL", "description": "Payroll submissions to the contracted payroll provider",
                            "when": {"match": "all", "conditions": [
                                {"field": "destination.id", "op": "eq", "value": "dst-paybridge-email"},
                                {"field": "actor.department", "op": "eq", "value": "Finance"}]}}]
    api(client, h, "PUT", f"{base}/policies/POL-DLP-EMAIL", json={"definition": email, "change_note": "Tune payroll false positive"})
    api(client, h, "POST", f"{base}/policies/test", json={"actor": culprit, "action": "UPLOAD", "resource": "ast-cust-export-q1", "destination": "dst-personal-cloud"})
    api(client, h, "POST", f"{base}/policies/test", json={"actor": "u-emorales", "action": "UPLOAD", "resource": "ast-product-brochure", "destination": "dst-personal-cloud"})
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "validation"})
    api(client, h, "PATCH", f"{base}/cases/{cid}", json={
        "summary": "A support identity downloaded the full customer export and transferred it to a personal destination.",
        "root_cause_narrative": "Support agents inherited read access to nightly exports; the export was unlabeled and DLP was monitor-only.",
        "residual_risk": "The external copy cannot be recalled; other inherited folder permissions remain unreviewed.",
        "lessons_learned": "Review export locations, label bulk extracts at creation and pilot DLP to enforcement with tuning.",
    })
