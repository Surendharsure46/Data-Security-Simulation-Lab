"""Learning journey: public welcome content, role choice, Levels 0-5 (fundamentals, knowledge check, labs),
mission assessment branches and automatic level unlocks."""
from __future__ import annotations

from conftest import register
from flow import api, good_investigation, good_remediation, prepare_and_run_baseline

from app.content.career import validate_career_content
from app.services.career import level_questions, mission_questions

EXPLANATION = ("I inspected the data, made the change the lab asked for and verified the result: the control now behaves as "
               "required and legitimate work still succeeds.")
VARIANT_ACTORS = {"A": dict(culprit="u-jokafor", ambiguous="u-rsilva", exfil_action="UPLOAD"),
                  "B": dict(culprit="u-rsilva", ambiguous="u-mchen", exfil_action="EMAIL")}


def answers(mid: str) -> list[int]:
    return [q["answer"] for q in mission_questions(mid)]


def check_answers(level: int) -> list[int]:
    return [q["answer"] for q in level_questions(level)]


def session_variant(sid: int) -> str:
    """Variants are never exposed by the API; tests read the hidden value from the database."""
    from app import db as dbmod
    from app.models import ScenarioSession
    with dbmod.SessionLocal() as db:
        return db.get(ScenarioSession, sid).variant


def read_all(client, h, level: int) -> dict:
    d = api(client, h, "GET", f"/api/career/levels/{level}")
    for item in d["fundamentals"]:
        d = api(client, h, "POST", f"/api/career/levels/{level}/read/{item['key']}")
    return d


def unlock_labs(client, h, level: int) -> dict:
    read_all(client, h, level)
    r = api(client, h, "POST", f"/api/career/levels/{level}/check", json={"answers": check_answers(level)})
    assert r["passed"], r
    return r


def start(client, h, mid: str) -> dict:
    return api(client, h, "POST", f"/api/career/missions/{mid}/start")


def understand(client, h, attempt: dict) -> None:
    r = api(client, h, "POST", f"/api/career/attempts/{attempt['id']}/understand", json={"answers": answers(attempt["mission"]["id"])})
    assert r["passed"]


def submit(client, h, attempt: dict, cited: list[int] | None = None) -> dict:
    return api(client, h, "POST", f"/api/career/attempts/{attempt['id']}/submit", json={"explanation": EXPLANATION, "cited_evidence": cited or []})


def do_demo(client, h) -> None:
    api(client, h, "POST", "/api/career/demo/scan", json={})
    api(client, h, "POST", "/api/career/demo/classify", json={"label": "restricted"})
    api(client, h, "POST", "/api/career/demo/transfer", json={"destination": "dst-personal-webmail"})
    api(client, h, "POST", "/api/career/demo/transfer", json={"destination": "dst-helpwise-sftp"})


def do_hashing(client, h) -> None:
    files = api(client, h, "GET", "/api/labs/encryption")["files"]
    digests = {f: api(client, h, "POST", "/api/labs/encryption/hash", json={"file": f})["sha256"] for f in files}
    manifest = api(client, h, "GET", "/api/labs/encryption")["manifest"]["original_batch_sha256"]
    api(client, h, "POST", "/api/labs/encryption/hash/answer", json={"modified_file": next(f for f, d in digests.items() if d != manifest)})


def complete_level0(client, h) -> dict:
    unlock_labs(client, h, 0)
    a = start(client, h, "MSN-001")
    understand(client, h, a)
    do_demo(client, h)
    assert submit(client, h, a)["status"] == "PASSED"
    b = start(client, h, "MSN-002")
    understand(client, h, b)
    do_hashing(client, h)
    return submit(client, h, b)


def solve_scenario(client, h, attempt: dict) -> list[int]:
    sid = attempt["session"]["id"]
    actors = VARIANT_ACTORS[session_variant(sid)]
    prepare_and_run_baseline(client, h, sid)
    cid = good_investigation(client, h, sid, **actors)
    good_remediation(client, h, sid, cid, culprit=actors["culprit"])
    return [e["id"] for e in api(client, h, "GET", f"/api/career/attempts/{attempt['id']}")["evidence_options"]["items"]]


def test_career_content_is_consistent():
    validate_career_content()


def test_answer_positions_are_shuffled_but_stable():
    positions = [q["answer"] for lv in range(6) for q in level_questions(lv)]
    assert len(set(positions)) >= 3  # not always the same option
    assert level_questions(2) == level_questions(2)


def test_public_content_needs_no_login_and_hides_answers(client):
    r = client.get("/api/career/public")
    assert r.status_code == 200
    body = r.json()
    assert [lv["level"] for lv in body["levels"]] == [0, 1, 2, 3, 4, 5]
    assert {x["key"] for x in body["roles"]} >= {"soc-analyst", "dlp-engineer"}
    assert body["welcome"]["sections"] and "answer" not in str(body)


def test_role_choice_starts_the_journey_at_level_zero(client, learner):
    prof = api(client, learner, "GET", "/api/career/profile")
    assert not prof["onboarding_complete"] and prof["career_level"] == 0
    assert client.get("/api/career/levels/0", headers=learner).json()["unlocked"] is False
    assert client.put("/api/career/role", headers=learner, json={"role": "astronaut"}).status_code == 422
    prof = api(client, learner, "PUT", "/api/career/role", json={"role": "soc-analyst"})
    assert prof["onboarding_complete"] and prof["role_title"] == "Trainee Data Security SOC Analyst"
    assert api(client, learner, "GET", "/api/curriculum")["selected_pathway"] == "soc-analyst"
    j = api(client, learner, "GET", "/api/career/journey")
    assert [lv["status"] for lv in j["levels"]] == ["CURRENT", "LOCKED", "LOCKED", "LOCKED", "LOCKED", "LOCKED"]
    assert j["next_step"]["type"] == "learn" and j["next_step"]["key"] == "briefing"


def test_level_steps_are_guided_in_order(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "foundation"})
    d = api(client, learner, "GET", "/api/career/levels/0")
    assert d["fundamentals"][0]["type"] == "briefing" and "organization" in d["fundamentals"][0]
    assert "answer" not in str(d["check"]["questions"])
    assert next(s for s in d["steps"] if s["type"] == "check")["status"] == "LOCKED"
    assert client.post("/api/career/levels/0/check", headers=learner, json={"answers": check_answers(0)}).status_code == 409
    assert client.post("/api/career/missions/MSN-001/start", headers=learner).status_code == 409
    assert client.get("/api/career/levels/1", headers=learner).json()["status"] == "LOCKED"
    assert client.post("/api/career/levels/1/read/M01-L3", headers=learner).status_code == 409
    d = read_all(client, learner, 0)
    assert d["next_step"]["type"] == "check"
    wrong = api(client, learner, "POST", "/api/career/levels/0/check", json={"answers": [(a + 1) % 4 for a in check_answers(0)]})
    assert not wrong["passed"] and "answer" not in str(wrong)
    ok = api(client, learner, "POST", "/api/career/levels/0/check", json={"answers": check_answers(0)})
    assert ok["passed"] and ok["next"]["next_mission"]["id"] == "MSN-001"
    d = api(client, learner, "GET", "/api/career/levels/0")
    assert [s["status"] for s in d["steps"] if s["type"] == "mission"] == ["CURRENT", "LOCKED"]
    assert client.post("/api/career/missions/MSN-002/start", headers=learner).status_code == 409


def test_demo_lab_fail_branch_then_retry_and_level_up(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "dlp-engineer"})
    unlock_labs(client, learner, 0)
    a = start(client, learner, "MSN-001")
    assert a["mission"]["kind"] == "DEMO" and "expected_label" not in str(a["mission"])
    assert client.post(f"/api/career/attempts/{a['id']}/submit", headers=learner, json={"explanation": EXPLANATION}).status_code == 409
    understand(client, learner, a)
    api(client, learner, "POST", "/api/career/demo/scan", json={})
    failed = submit(client, learner, a)
    assert failed["status"] == "NOT_PASSED" and failed["outcome"]["skill_gaps"] and failed["outcome"]["remedial_lessons"]
    assert failed["retry_options"] == ["PRACTICE"]
    again = api(client, learner, "POST", f"/api/career/attempts/{a['id']}/retry", json={"strategy": "PRACTICE"})
    assert again["understanding"]["carried_over_from"] == 1
    inspect = next(p for p in again["phases"] if p["key"] == "INSPECT")
    assert inspect["items"][0]["done"] is False  # the demo restarts on retry
    do_demo(client, learner)
    passed = submit(client, learner, again)
    assert passed["status"] == "PASSED" and passed["outcome"]["next"]["next_mission"]["id"] == "MSN-002"

    b = start(client, learner, "MSN-002")
    assert b["mission"]["exercises"][0]["steps"]  # step-by-step instructions for the guided lab session
    understand(client, learner, b)
    do_hashing(client, learner)
    done = submit(client, learner, b)
    nxt = done["outcome"]["next"]
    assert nxt["level_completed"] == 0 and nxt["level_unlocked"] == 1 and nxt["new_title"] == "Junior DLP Engineer"
    promo = api(client, learner, "GET", "/api/career/promotion")["pending"]
    assert promo["level"] == 1 and promo["completed_level"] == 0 and promo["missions"]
    api(client, learner, "POST", "/api/career/promotion/acknowledge")
    j = api(client, learner, "GET", "/api/career/journey")
    assert [lv["status"] for lv in j["levels"][:3]] == ["COMPLETED", "CURRENT", "LOCKED"] and j["pending_promotion"] is None


def test_scenario_lab_pass_records_skills_and_mission_sessions_are_locked(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "soc-analyst"})
    complete_level0(client, learner)
    api(client, learner, "POST", "/api/career/promotion/acknowledge")
    unlock_labs(client, learner, 1)
    a = start(client, learner, "MSN-101")
    assert a["session"]["mode"] == "GUIDED"
    understand(client, learner, a)
    cited = solve_scenario(client, learner, a)
    sid = a["session"]["id"]
    assert client.post(f"/api/sessions/{sid}/submit", headers=learner, json={"confirm": True}).status_code == 409
    assert client.post(f"/api/sessions/{sid}/reset", headers=learner, json={"confirm": True}).status_code == 409
    forged = client.post(f"/api/career/attempts/{a['id']}/submit", headers=learner, json={"explanation": EXPLANATION, "cited_evidence": [99999]})
    assert forged.status_code == 422
    done = submit(client, learner, a, cited)
    assert done["status"] == "PASSED" and all(r["met"] for r in done["outcome"]["required"])
    assert {s["skill"] for s in done["outcome"]["skills_recorded"]} >= {"data-classification", "control-validation"}
    assert done["outcome"]["next"]["next_mission"]["id"] == "MSN-102"


def test_scenario_fail_branch_offers_practice_or_new_variant(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "soc-analyst"})
    complete_level0(client, learner)
    unlock_labs(client, learner, 1)
    a = start(client, learner, "MSN-101")
    understand(client, learner, a)
    sid = a["session"]["id"]
    prepare_and_run_baseline(client, learner, sid)
    cid = api(client, learner, "POST", f"/api/sessions/{sid}/cases", json={"title": "Thin case", "alert_ids": []})["id"]
    ev = api(client, learner, "POST", f"/api/sessions/{sid}/cases/{cid}/evidence", json={"ref_type": "ASSET", "ref_id": "ast-cust-export-q1"})
    done = submit(client, learner, a, [ev["id"]])
    assert done["status"] == "NOT_PASSED" and any(not r["met"] for r in done["outcome"]["required"])
    assert "control-validation" in {g["skill"] for g in done["outcome"]["skill_gaps"]}
    assert done["retry_options"] == ["PRACTICE", "NEW_VARIANT"]
    practice = api(client, learner, "POST", f"/api/career/attempts/{a['id']}/retry", json={"strategy": "PRACTICE"})
    assert practice["session"]["mode"] == "GUIDED" and session_variant(practice["session"]["id"]) == session_variant(sid)
    nv = api(client, learner, "POST", f"/api/career/attempts/{practice['id']}/retry", json={"strategy": "NEW_VARIANT"})
    assert session_variant(nv["session"]["id"]) != session_variant(practice["session"]["id"])
    assert api(client, learner, "GET", f"/api/career/attempts/{practice['id']}")["status"] == "ABANDONED"


def test_level_one_complete_unlocks_level_two_where_practice_does_not_count(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "data-protection-engineer"})
    complete_level0(client, learner)
    unlock_labs(client, learner, 1)
    a = start(client, learner, "MSN-101")
    understand(client, learner, a)
    submit(client, learner, a, solve_scenario(client, learner, a))
    b = start(client, learner, "MSN-102")
    understand(client, learner, b)
    api(client, learner, "POST", "/api/labs/encryption/file/encrypt", json={"passphrase": "Correct-Horse-42!"})
    api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Wrong-Passphrase-1"})
    api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Correct-Horse-42!"})
    api(client, learner, "POST", "/api/labs/encryption/file/tamper")
    api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Correct-Horse-42!"})
    assert submit(client, learner, b)["status"] == "PASSED"
    c = start(client, learner, "MSN-103")
    understand(client, learner, c)
    api(client, learner, "POST", "/api/labs/database/reset")
    api(client, learner, "POST", "/api/labs/database/grants/revoke", json={"role": "support_agent", "table": "customers"})
    api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers"})
    api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers_masked LIMIT 5"})
    api(client, learner, "POST", "/api/labs/database/lookup", json={"mode": "vulnerable", "email": "x' OR '1'='1"})
    api(client, learner, "POST", "/api/labs/database/lookup", json={"mode": "parameterized", "email": "x' OR '1'='1"})
    done = submit(client, learner, c)
    assert done["status"] == "PASSED", done["outcome"]["required"]
    assert done["outcome"]["next"]["level_unlocked"] == 2
    prof = api(client, learner, "GET", "/api/career/profile")
    assert prof["career_level"] == 2 and prof["role_title"] == "Data Protection Engineer" and prof["pending_promotion"] == 2

    unlock_labs(client, learner, 2)
    d = start(client, learner, "MSN-201")
    assert d["session"]["mode"] == "ASSESSMENT" and d["counts"]
    practice = api(client, learner, "POST", f"/api/career/attempts/{d['id']}/retry", json={"strategy": "PRACTICE"})
    assert practice["counts"] is False and "practice_note" in practice


def test_attempts_are_private(client, learner):
    api(client, learner, "PUT", "/api/career/role", json={"role": "foundation"})
    unlock_labs(client, learner, 0)
    a = start(client, learner, "MSN-001")
    other = register(client, "learner2")
    assert client.get(f"/api/career/attempts/{a['id']}", headers=other).status_code == 404
    assert client.post(f"/api/career/attempts/{a['id']}/understand", headers=other, json={"answers": [1, 1]}).status_code == 404
