"""Authorization, isolation, input validation and answer-protection tests."""
from __future__ import annotations

import json

from conftest import PASSWORD, register
from flow import api, prepare_and_run_baseline


def test_requires_authentication(client):
    assert client.get("/api/sessions").status_code == 401
    assert client.get("/api/sessions", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_weak_password_and_bad_username_rejected(client):
    r = client.post("/api/auth/register", json={"username": "x y", "display_name": "X", "password": "short"})
    assert r.status_code == 422 and r.json()["detail"] == "Invalid input"


def test_login_logout_and_token_revocation(client):
    register(client, "alice")
    r = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    tok = client.post("/api/auth/login", json={"username": "ALICE", "password": PASSWORD}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/auth/me", headers=h).json()["username"] == "alice"
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_login_rate_limited(client, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "login_rate_limit_per_minute", 3)
    register(client, "bob")
    codes = [client.post("/api/auth/login", json={"username": "bob", "password": "nope"}).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and 429 in codes[3:]


def test_cross_user_session_access_is_404(client, learner, session_a):
    other = register(client, "mallory")
    base = f"/api/sessions/{session_a}"
    for path in ("", "/assets", "/events", "/alerts", "/policies", "/reports/case-report", "/cases"):
        assert client.get(base + path, headers=other).status_code == 404, path
    assert client.post(f"{base}/discovery/scan", headers=other).status_code == 404
    assert client.post(f"{base}/timeline/run", headers=other, json={"mode": "standard"}).status_code == 404
    assert client.post(f"{base}/reset", headers=other, json={"confirm": True}).status_code == 404
    assert session_a not in [s["id"] for s in client.get("/api/sessions?all_users=true", headers=other).json()]


def test_staff_can_read_but_not_modify_learner_sessions(client, learner, session_a):
    from app import db as dbmod
    from app.models import User
    staff = register(client, "coach")
    with dbmod.SessionLocal() as db:
        u = db.query(User).filter_by(username="coach").one()
        u.role = "instructor"
        db.commit()
    base = f"/api/sessions/{session_a}"
    assert client.get(base, headers=staff).status_code == 200
    assert client.post(f"{base}/discovery/scan", headers=staff).status_code == 403
    assert client.get("/api/admin/users", headers=staff).status_code == 200
    assert client.get("/api/admin/users", headers=learner).status_code == 403


def test_hidden_answers_not_exposed_through_api(client, learner, session_a):
    h, base = learner, f"/api/sessions/{session_a}"
    prepare_and_run_baseline(client, h, session_a)
    blobs = [client.get(p, headers=h).text for p in (
        "/api/scenarios", "/api/scenarios/customer-data-export", base, f"{base}/events", f"{base}/alerts",
        f"{base}/actions", f"{base}/reports/remediation-verification?format=json", f"{base}/reports/assessment?format=json")]
    text = "\n".join(blobs)
    for secret in ("ground_truth", "step_key", "culprit", "malicious_steps", "alert_groups", "exfil_step", "\"S08\"", "excessive_grants"):
        assert secret not in text, secret
    # The variant parameters never appear either.
    assert "exfil_destination" not in text and "ambiguous_actor" not in text
    # No score preview before submission.
    rep = client.get(f"{base}/reports/assessment?format=json", headers=h).json()
    assert "Not yet submitted" in json.dumps(rep)


def test_assessment_mode_disables_hints_and_randomises_variant(client, learner):
    r = client.post("/api/sessions", headers=learner, json={"scenario_id": "customer-data-export", "mode": "ASSESSMENT", "variant": "A"})
    sid = r.json()["id"]
    assert client.post(f"/api/sessions/{sid}/hints/classify", headers=learner).status_code == 403
    assert "variant" not in r.json()


def test_hints_progressive_in_guided_mode(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    a = api(client, learner, "POST", f"{base}/hints/classify")
    b = api(client, learner, "POST", f"{base}/hints/classify")
    c = api(client, learner, "POST", f"{base}/hints/classify")
    assert len(a["hints"]) == 1 and len(b["hints"]) == 2 and c["remaining"] == 0 and len(c["hints"]) == 2


def test_input_validation_and_domain_errors(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    r = client.post(f"{base}/classification/assign", headers=learner, json={"asset_key": "ast-cust-export-q1", "label_key": "top-secret",
                                                                            "justification": "this is long enough"})
    assert r.status_code == 400 and "Unknown label" in r.json()["detail"]
    r = client.post(f"{base}/classification/assign", headers=learner, json={"asset_key": "ast-cust-export-q1", "label_key": "restricted",
                                                                            "justification": "x", "owner_key": "svc-crm-sync"})
    assert r.status_code == 422
    r = client.post(f"{base}/classification/assign", headers=learner, json={"asset_key": "ast-cust-export-q1", "label_key": "restricted",
                                                                            "justification": "service accounts cannot own data", "owner_key": "svc-crm-sync"})
    assert r.status_code == 400
    r = client.post(f"{base}/policies", headers=learner, json={"key": "POL-BAD", "definition": {"name": "bad", "conditions": {}, "outcome": "BLOCK"}})
    assert r.status_code == 422
    r = client.post(f"{base}/timeline/run", headers=learner, json={"mode": "validation"})
    assert r.status_code == 409
    r = client.post(f"{base}/cases/1/notes", headers=learner, json={"kind": "OBSERVATION", "text": "no case"})
    assert r.status_code == 404
    r = client.post(f"{base}/remediation", headers=learner, json={"action_type": "DELETE_TENANT", "target_key": "x", "justification": "not permitted at all"})
    assert r.status_code == 400


def test_observation_must_cite_evidence_and_evidence_must_exist(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    cid = api(client, learner, "POST", f"{base}/cases", json={"title": "Test case"})["id"]
    r = client.post(f"{base}/cases/{cid}/notes", headers=learner, json={"kind": "OBSERVATION", "text": "Unsupported claim"})
    assert r.status_code == 400
    r = client.post(f"{base}/cases/{cid}/evidence", headers=learner, json={"ref_type": "EVENT", "ref_id": "evt-999-99999"})
    assert r.status_code == 404


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_csv_export_neutralises_formula_injection(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    api(client, learner, "POST", f"{base}/classification/assign", json={
        "asset_key": "ast-pricing-model", "label_key": "confidential", "justification": "=HYPERLINK(\"http://evil.example\")"})
    csv_text = client.get(f"{base}/reports/classification-register?format=csv", headers=learner).text
    assert "=HYPERLINK" not in csv_text.replace("'=HYPERLINK", "")


def test_html_report_escapes_learner_content(client, learner, session_a):
    base = f"/api/sessions/{session_a}"
    cid = api(client, learner, "POST", f"{base}/cases", json={"title": "XSS check"})["id"]
    api(client, learner, "PATCH", f"{base}/cases/{cid}", json={"summary": "<script>alert(1)</script>"})
    r = client.get(f"{base}/reports/case-report?format=html", headers=learner)
    assert "<script>alert(1)</script>" not in r.text and "&lt;script&gt;" in r.text
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
