"""End-to-end API test of the reference scenario (Section 10 of the specification)."""
from __future__ import annotations

from flow import api, good_investigation, good_remediation, prepare_and_run_baseline


def test_full_reference_scenario_passes_with_evidence(client, learner, session_a):
    sid, h = session_a, learner
    base = f"/api/sessions/{sid}"
    run1 = prepare_and_run_baseline(client, h, sid)
    assert run1["run_number"] == 1 and run1["alerts_generated"] == 5  # S00, S03, S07, S08 (now labeled), S06

    # The labelled export now matches the monitor-only pilot policy: the upload is alerted but still ALLOWED.
    ev = api(client, h, "GET", f"{base}/events?actor=u-jokafor&run=1&source_type=PROXY")
    assert ev and ev[0]["result"] == "ALLOWED" and ev[0]["provenance"] == "SIMULATED"

    cid = good_investigation(client, h, sid)
    good_remediation(client, h, sid, cid)

    # Validation replay: the clone of the original actor is stopped; legitimate business continues.
    val = api(client, h, "GET", f"{base}/events?run=2&actor=u-jokafor-val")
    assert any(e["result"] in ("DENIED", "BLOCKED") for e in val)
    payroll = api(client, h, "GET", f"{base}/events?run=2&actor=u-dkowalski&source_type=EMAIL_GATEWAY")
    assert payroll[0]["result"] == "ALLOWED"
    assert not [a for a in api(client, h, "GET", f"{base}/alerts?run=2") if a["actor_id"] == "u-dkowalski"]

    progress = api(client, h, "GET", base)["progress"]
    assert all(t["done"] for t in progress), [t["key"] for t in progress if not t["done"]]

    attempt = api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    assert attempt["passed"], attempt
    assert attempt["total_score"] >= 90, attempt["criteria"]
    assert not attempt["critical_failures"]
    assert "not a professional certification" in attempt["disclaimer"].lower()

    report = api(client, h, "GET", f"{base}/reports/case-report?format=md")
    assert "Execution mode: SIMULATED" in report and "u-jokafor" in report and "CONFIRMED_EXFILTRATION" in report
    # Session is read-only after submission.
    r = client.post(f"{base}/discovery/scan", headers=h)
    assert r.status_code == 409


def test_policy_change_changes_outcome_of_same_action(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    spec = {"actor": "u-jokafor", "action": "UPLOAD", "resource": "ast-cust-export-q1", "destination": "dst-personal-cloud"}
    first = api(client, h, "POST", f"{base}/activities", json=spec)
    assert first["outcome"] == "ALLOWED"
    from flow import BLOCK_POLICY
    api(client, h, "POST", f"{base}/policies", json={"key": "POL-DLP-BLOCK", "definition": BLOCK_POLICY})
    second = api(client, h, "POST", f"{base}/activities", json=spec)
    assert second["outcome"] == "BLOCKED"
    assert second["decision"]["decisive_policy"] == "POL-DLP-BLOCK"
    assert second["alerts"] and second["alerts"][0]["policy_id"] == "POL-DLP-BLOCK"
    assert second["alerts"][0]["triggering_event_id"] in [e["event_id"] for e in second["events"]]


def test_destroying_evidence_is_critical_failure(client, learner, session_a):
    h, sid = learner, session_a
    base = f"/api/sessions/{sid}"
    prepare_and_run_baseline(client, h, sid)
    cid = good_investigation(client, h, sid)
    r = client.post(f"{base}/remediation", headers=h, json={"action_type": "REIMAGE_DEVICE", "target_key": "u-jokafor",
                                                             "justification": "Rebuild the device quickly", "case_id": cid})
    assert r.status_code == 409  # destructive action requires explicit confirmation
    api(client, h, "POST", f"{base}/remediation", json={"action_type": "REIMAGE_DEVICE", "target_key": "u-jokafor",
                                                          "justification": "Rebuild the device quickly", "case_id": cid,
                                                          "confirm_destructive": True})
    good_remediation(client, h, sid, cid)
    attempt = api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    assert not attempt["passed"]
    assert any(c["key"] == "CF-EVIDENCE-DESTROYED" for c in attempt["critical_failures"])


def test_no_validation_replay_is_critical_failure(client, learner, session_a):
    h, sid = learner, session_a
    prepare_and_run_baseline(client, h, sid)
    attempt = api(client, h, "POST", f"/api/sessions/{sid}/submit", json={"confirm": True})
    assert not attempt["passed"]
    assert any(c["key"] == "CF-NOT-VERIFIED" for c in attempt["critical_failures"])
    assert attempt["missing_tasks"]
    assert attempt["recommendations"]
