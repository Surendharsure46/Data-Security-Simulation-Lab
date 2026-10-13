"""Scenario lifecycle, reproducibility, correlation, remediation verification and engineering metrics."""
from __future__ import annotations

from flow import BLOCK_POLICY, api, good_investigation, good_remediation, prepare_and_run_baseline


def _outcomes(client, h, sid, run):
    evs = api(client, h, "GET", f"/api/sessions/{sid}/events?run={run}")
    return [(e["timestamp"], e["actor_id"], e["action"], e["resource_id"], e["source_type"], e["result"], e["policy_id"]) for e in evs]


def test_replay_is_reproducible_across_sessions(client, learner):
    sids = []
    for _ in range(2):
        sid = api(client, learner, "POST", "/api/sessions", json={"scenario_id": "customer-data-export", "variant": "A"})["id"]
        api(client, learner, "POST", f"/api/sessions/{sid}/timeline/run", json={"mode": "standard"})
        sids.append(sid)
    assert _outcomes(client, learner, sids[0], 1) == _outcomes(client, learner, sids[1], 1)


def test_reset_restores_initial_state_and_keeps_attempts(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    before = _outcomes(client, h, session_a, 1)
    assert before == []
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    first = _outcomes(client, h, session_a, 1)
    api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    assert client.post(f"{base}/reset", headers=h, json={"confirm": False}).status_code == 409
    s = api(client, h, "POST", f"{base}/reset", json={"confirm": True, "new_variant": False})
    assert s["attempt_number"] == 2 and s["status"] == "ACTIVE" and s["run_count"] == 0
    assert api(client, h, "GET", f"{base}/events") == []
    assert api(client, h, "GET", f"{base}/assets/ast-cust-export-q1")["label_key"] is None
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    assert _outcomes(client, h, session_a, 1) == first
    assert len(api(client, h, "GET", f"{base}/attempts")) == 1


def test_reset_with_new_variant_changes_subject(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    api(client, h, "POST", f"{base}/reset", json={"confirm": True, "new_variant": True})
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    actors = {e["actor_id"] for e in api(client, h, "GET", f"{base}/events?resource=ast-cust-export-q1")}
    assert "u-rsilva" in actors and "u-jokafor" not in actors


def test_pause_blocks_changes_until_resume(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    api(client, learner, "POST", f"{base}/pause")
    assert client.post(f"{base}/discovery/scan", headers=learner).status_code == 409
    api(client, learner, "POST", f"{base}/resume")
    assert client.post(f"{base}/discovery/scan", headers=learner).status_code == 200


def test_alert_references_events_and_correlation_is_explained(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    alert = next(a for a in api(client, h, "GET", f"{base}/alerts") if a["actor_id"] == "u-jokafor")
    detail = api(client, h, "GET", f"{base}/alerts/{alert['alert_id']}")
    assert alert["triggering_event_id"] in alert["event_ids"]
    assert detail["policy_id"] == "POL-DET-BULK" and detail["policy_version"] == 1
    reasons = {r for c in detail["correlated"] for r in c["reasons"]}
    assert {"Same actor", "Same resource"} <= reasons
    # The later upload by the same actor of the same resource is correlated with an explicit reason.
    upload = [c for c in detail["correlated"] if c["event"]["action"] == "UPLOAD"]
    assert upload and all(c["reasons"] for c in upload)
    # Unrelated activity (payroll email) is not correlated merely by time.
    assert not [c for c in detail["correlated"] if c["event"]["actor_id"] == "u-dkowalski"]


def test_events_follow_common_schema(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    required = {"event_id", "timestamp", "organization_id", "scenario_id", "scenario_session_id", "actor_id", "resource_id", "action",
                "result", "data_classification", "source_type", "source_system", "provenance", "policy_id", "policy_version",
                "destination", "related_event_ids", "evidence_refs", "extension"}
    for e in api(client, h, "GET", f"{base}/events"):
        assert required <= set(e)
        assert e["provenance"] == "SIMULATED" and e["source_system"].startswith("kr-sim-")
        assert e["timestamp"].endswith("Z")


def test_revoke_sessions_alone_does_not_stop_sign_in(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    r = api(client, h, "POST", f"{base}/remediation", json={"action_type": "REVOKE_SESSIONS", "target_key": "u-jokafor",
                                                              "justification": "Terminate active sessions"})
    assert "still authenticate" in r["verification"]["caveat"]
    act = api(client, h, "POST", f"{base}/activities", json={"actor": "u-jokafor", "action": "SIGN_IN"})
    assert act["outcome"] == "SUCCESS"
    api(client, h, "POST", f"{base}/remediation", json={"action_type": "DISABLE_ACCOUNT", "target_key": "u-jokafor",
                                                          "justification": "Disable pending investigation"})
    assert api(client, h, "POST", f"{base}/activities", json={"actor": "u-jokafor", "action": "SIGN_IN"})["outcome"] == "DENIED"


def test_blocking_destination_disrupts_legitimate_use_in_replay(client, learner, session_a):
    h, sid = learner, session_a
    base = f"/api/sessions/{sid}"
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    api(client, h, "POST", f"{base}/remediation", json={"action_type": "BLOCK_DESTINATION", "target_key": "dst-personal-cloud",
                                                          "justification": "Stop uploads to personal cloud"})
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "validation"})
    brochure = api(client, h, "GET", f"{base}/events?run=2&actor=u-emorales")
    assert any(e["result"] == "BLOCKED" and e["source_type"] == "PROXY" for e in brochure)
    attempt = api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    crit = {c["key"]: c for c in attempt["criteria"]}
    assert crit["RV-PATH-CLOSED"]["earned"] == crit["RV-PATH-CLOSED"]["points"]
    assert crit["RV-NO-DISRUPTION"]["earned"] < crit["RV-NO-DISRUPTION"]["points"]


def test_changes_after_last_replay_are_flagged(client, learner, session_a):
    h, sid = learner, session_a
    base = f"/api/sessions/{sid}"
    prepare_and_run_baseline(client, h, sid)
    cid = good_investigation(client, h, sid)
    good_remediation(client, h, sid, cid)
    api(client, h, "POST", f"{base}/policies/POL-DLP-CUSTOMER/status", json={"status": "DISABLED"})
    progress = {t["key"]: t["done"] for t in api(client, h, "GET", base)["progress"]}
    assert progress["verify"] is False
    attempt = api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    crit = {c["key"]: c for c in attempt["criteria"]}
    assert crit["RV-PATH-CLOSED"]["earned"] == crit["RV-PATH-CLOSED"]["points"] / 2
    assert crit["RV-DLP-DEPTH"]["earned"] == 0


def test_preventing_exfiltration_before_the_run_changes_expected_conclusions(client, learner, session_a):
    """If controls stop the export in run 1, 'confirmed exfiltration' is no longer supported by evidence."""
    h, sid = learner, session_a
    base = f"/api/sessions/{sid}"
    api(client, h, "POST", f"{base}/policies", json={"key": "POL-DLP-CUSTOMER", "definition": BLOCK_POLICY})
    api(client, h, "POST", f"{base}/classification/assign", json={"asset_key": "ast-cust-export-q1", "label_key": "restricted",
                                                                    "justification": "Bulk customer PII with card numbers"})
    api(client, h, "POST", f"{base}/timeline/run", json={"mode": "standard"})
    up = api(client, h, "GET", f"{base}/events?run=1&actor=u-jokafor&source_type=PROXY")
    assert up[0]["result"] == "BLOCKED"
    cid = good_investigation(client, h, sid)  # claims CONFIRMED exfiltration, which the events contradict
    attempt = api(client, h, "POST", f"{base}/submit", json={"confirm": True})
    crit = {c["key"]: c for c in attempt["criteria"]}
    assert crit["DA-DETERMINATION"]["earned"] < crit["DA-DETERMINATION"]["points"]
    assert crit["EQ-SCOPE"]["earned"] < crit["EQ-SCOPE"]["points"]
    assert cid


def test_score_is_deterministic_for_identical_state(client, learner, session_a):
    from app import db as dbmod
    from app.models import ScenarioSession
    from app.services.assessment import score_session
    h, sid = learner, session_a
    prepare_and_run_baseline(client, h, sid)
    cid = good_investigation(client, h, sid)
    good_remediation(client, h, sid, cid)
    with dbmod.SessionLocal() as db:
        s = db.get(ScenarioSession, sid)
        a, b = score_session(db, s), score_session(db, s)
    assert a == b


def test_variant_b_full_flow(client, learner):
    sid = api(client, learner, "POST", "/api/sessions", json={"scenario_id": "customer-data-export", "variant": "B"})["id"]
    prepare_and_run_baseline(client, learner, sid)
    alerts = api(client, learner, "GET", f"/api/sessions/{sid}/alerts?run=1")
    assert {a["policy_id"] for a in alerts if a["actor_id"] == "u-rsilva"} >= {"POL-DET-BULK", "POL-DLP-EMAIL"}
    cid = good_investigation(client, learner, sid, culprit="u-rsilva", ambiguous="u-mchen", exfil_action="EMAIL")
    good_remediation(client, learner, sid, cid, culprit="u-rsilva")
    attempt = api(client, learner, "POST", f"/api/sessions/{sid}/submit", json={"confirm": True})
    assert attempt["passed"] and not attempt["critical_failures"], attempt["criteria"]


def test_engineering_test_suite_metrics_and_regression(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    r1 = api(client, h, "POST", f"/api/sessions/{session_a}/engineering/test-suite/run")
    assert r1["metrics"]["tp"] == 0 and r1["metrics"]["recall"] == 0.0
    assert "not an estimate of production" in r1["metrics"]["scope_note"]
    api(client, h, "POST", f"{base}/policies", json={"key": "POL-DLP-CUSTOMER", "definition": BLOCK_POLICY})
    r2 = api(client, h, "POST", f"/api/sessions/{session_a}/engineering/test-suite/run")
    assert r2["metrics"]["recall"] >= 0.8 and r2["metrics"]["fp"] == 0
    cmp = api(client, h, "GET", f"/api/sessions/{session_a}/engineering/test-suite/compare?a=1&b=2")
    assert cmp["fixes"] >= 5 and cmp["regressions"] == 0 and "POL-DLP-CUSTOMER" in cmp["policy_changes"]
    cr = api(client, h, "POST", f"/api/sessions/{session_a}/engineering/change-records", json={
        "policy_key": "POL-DLP-CUSTOMER", "from_version": 1, "to_version": 1, "reason": "Introduce enforcement for customer data",
        "expected_impact": "Blocks personal-destination transfers", "rollback_plan": "Disable policy", "test_run_id": r2["id"]})
    assert cr["id"]


def test_policy_versioning_diff_rollback_and_draft_preview(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    pol = api(client, h, "GET", f"{base}/policies/POL-DLP-CLOUD")
    d = pol["definition"]
    d["outcome"] = "BLOCK"
    spec = {"actor": "u-jokafor", "action": "UPLOAD", "resource": "ast-product-brochure", "destination": "dst-personal-cloud"}
    draft = api(client, h, "POST", f"{base}/policies/test", json={**spec, "draft": {"key": "POL-DLP-CLOUD", "definition": d}})
    assert draft["draft_included"]
    api(client, h, "PUT", f"{base}/policies/POL-DLP-CLOUD", json={"definition": d, "change_note": "Move to enforcement"})
    diff = api(client, h, "GET", f"{base}/policies/POL-DLP-CLOUD/diff?a=1&b=2")
    assert any(c["path"] == "outcome" and c["after"] == "BLOCK" for c in diff["changes"])
    assert client.put(f"{base}/policies/POL-DLP-CLOUD", headers=h, json={"definition": d, "change_note": "no-op"}).status_code == 409
    api(client, h, "POST", f"{base}/policies/POL-DLP-CLOUD/rollback", json={"to_version": 1})
    p = api(client, h, "GET", f"{base}/policies/POL-DLP-CLOUD")
    assert p["current_version"] == 3 and p["definition"]["outcome"] == "MONITOR"


def test_reports_all_types_and_formats(client, learner, session_a):
    h, sid = learner, session_a
    base = f"/api/sessions/{sid}"
    prepare_and_run_baseline(client, h, sid)
    cid = good_investigation(client, h, sid)
    good_remediation(client, h, sid, cid)
    api(client, h, "POST", f"{base}/engineering/test-suite/run")
    for t in api(client, h, "GET", f"{base}/reports"):
        for fmt in t["formats"]:
            r = client.get(f"{base}/reports/{t['type']}?format={fmt}", headers=h)
            assert r.status_code == 200, (t["type"], fmt, r.text)
            assert r.text.strip()
    md = client.get(f"{base}/reports/case-report?format=md", headers=h).text
    for n in range(1, 15):
        assert f"## {n}." in md
    export = client.get(f"{base}/export/events", headers=h)
    assert export.status_code == 200 and export.text.count("\n") == len(api(client, h, "GET", f"{base}/events"))
