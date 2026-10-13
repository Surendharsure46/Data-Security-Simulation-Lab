"""Lab exercises: real cryptographic and SQLite operations plus simulated labs."""
from __future__ import annotations

import copy

from flow import api


def status(client, h, lab):
    return api(client, h, "GET", "/api/labs/status")[lab]["exercises"]


# --------------------------------------------------------------------------- encryption (REAL_LAB)


def test_hashing_exercise(client, learner):
    files = api(client, learner, "GET", "/api/labs/encryption")["files"]
    r = client.post("/api/labs/encryption/hash/answer", headers=learner, json={"modified_file": "payroll_batch_C.csv"})
    assert r.status_code == 409  # must hash first
    digests = {f: api(client, learner, "POST", "/api/labs/encryption/hash", json={"file": f})["sha256"] for f in files}
    manifest = api(client, learner, "GET", "/api/labs/encryption")["manifest"]["original_batch_sha256"]
    modified = [f for f, d in digests.items() if d != manifest]
    assert modified == ["payroll_batch_C.csv"]
    assert api(client, learner, "POST", "/api/labs/encryption/hash/answer", json={"modified_file": modified[0]})["correct"]
    assert status(client, learner, "encryption")["hashing"]


def test_file_encryption_real_roundtrip_wrong_key_and_tamper(client, learner):
    enc = api(client, learner, "POST", "/api/labs/encryption/file/encrypt", json={"passphrase": "Correct-Horse-42!"})
    assert enc["header"]["alg"] == "AES-256-GCM" and enc["provenance"] == "REAL_LAB"
    wrong = api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Wrong-Passphrase-1"})
    assert wrong["success"] is False and "InvalidTag" in wrong["error"]
    ok = api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Correct-Horse-42!"})
    assert ok["success"] and ok["matches_original"]
    api(client, learner, "POST", "/api/labs/encryption/file/tamper")
    tampered = api(client, learner, "POST", "/api/labs/encryption/file/decrypt", json={"passphrase": "Correct-Horse-42!"})
    assert tampered["success"] is False
    assert tampered["checks"] == {"wrong_key_rejected": True, "correct_ok": True, "tamper_rejected": True}
    assert status(client, learner, "encryption")["file_roundtrip"]


def test_envelope_rotation_keeps_data_ciphertext(client, learner):
    init = api(client, learner, "POST", "/api/labs/encryption/envelope/init")
    rot = api(client, learner, "POST", "/api/labs/encryption/envelope/rotate")
    assert rot["data_ciphertext_sha256"] == init["data_ciphertext_sha256"] and rot["data_unchanged_since_init"]
    assert rot["wrapped_dek_hex"] != init["wrapped_dek_hex"]
    old = api(client, learner, "POST", "/api/labs/encryption/envelope/decrypt", json={"kek_id": "kek-v1"})
    assert old["success"] is False and "InvalidUnwrap" in old["error"]
    new = api(client, learner, "POST", "/api/labs/encryption/envelope/decrypt", json={})
    assert new["success"] and new["matches_original"]
    assert status(client, learner, "encryption")["envelope_rotation"]


def test_tls_and_config_review(client, learner):
    wrong = api(client, learner, "POST", "/api/labs/encryption/tls/answer", json={"visible": ["url_path", "sni_hostname"]})
    assert not wrong["passed"] and "per_item" not in wrong
    right = api(client, learner, "POST", "/api/labs/encryption/tls/answer",
                json={"visible": ["destination_ip", "sni_hostname", "tls_version_and_cipher", "packet_sizes_and_timing"]})
    assert right["passed"]
    findings = api(client, learner, "POST", "/api/labs/encryption/config/validate")["findings"]
    assert {f["id"] for f in findings} >= {"ENC-01", "ENC-02", "ENC-03", "ENC-04", "ENC-05", "ENC-06", "ENC-07", "ENC-08"}
    good = {"tls_min_version": "TLS1.2", "cipher_suites": ["TLS_AES_256_GCM_SHA384"], "verify_server_certificate": True,
            "at_rest_algorithm": "AES-256-GCM", "key_location": "kms", "key_rotation_days": 365, "backup_encryption": True,
            "secret_storage": "vault"}
    api(client, learner, "PUT", "/api/labs/encryption/config", json=good)
    assert api(client, learner, "POST", "/api/labs/encryption/config/validate")["passed"]
    bad = {**good, "at_rest_algorithm": "ROT13"}
    assert client.put("/api/labs/encryption/config", headers=learner, json=bad).status_code == 400
    st = status(client, learner, "encryption")
    assert st["tls_metadata"] and st["config_review"]


# --------------------------------------------------------------------------- database (REAL_LAB)


def test_database_least_privilege_enforced_by_authorizer(client, learner):
    api(client, learner, "POST", "/api/labs/database/reset")
    before = api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers"})
    assert before["decision"] == "ALLOWED" and before["row_count"] == 300 and before["truncated"]
    api(client, learner, "POST", "/api/labs/database/grants/revoke", json={"role": "support_agent", "table": "customers"})
    denied = api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers"})
    assert denied["decision"] == "DENIED"
    ok = api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers_masked LIMIT 5"})
    assert ok["decision"] == "ALLOWED" and ok["row_count"] == 5
    assert status(client, learner, "database")["least_privilege"]


def test_database_dangerous_statements_denied(client, learner):
    for role, sql in (("support_agent", "DELETE FROM support_cases"), ("support_agent", "SELECT * FROM _lab_grants"),
                      ("dba", "ATTACH DATABASE 'x.db' AS x"), ("dba", "PRAGMA table_info(customers)"),
                      ("analyst", "SELECT * FROM support_cases")):
        r = api(client, learner, "POST", "/api/labs/database/query", json={"role": role, "sql": sql})
        assert r["decision"] in ("DENIED", "ERROR"), (role, sql, r)
    multi = api(client, learner, "POST", "/api/labs/database/query", json={"role": "dba", "sql": "SELECT 1; DROP TABLE customers"})
    assert multi["decision"] == "ERROR"
    still = api(client, learner, "POST", "/api/labs/database/query", json={"role": "dba", "sql": "SELECT count(*) FROM customers"})
    assert still["rows"][0][0] == 300


def test_sql_injection_vs_parameterized(client, learner):
    payload = "x' OR '1'='1"
    vuln = api(client, learner, "POST", "/api/labs/database/lookup", json={"mode": "vulnerable", "email": payload})
    assert vuln["row_count"] > 1
    safe = api(client, learner, "POST", "/api/labs/database/lookup", json={"mode": "parameterized", "email": payload})
    assert safe["row_count"] == 0 and safe["bound_parameters"] == [payload]
    union = api(client, learner, "POST", "/api/labs/database/lookup",
                json={"mode": "vulnerable", "email": "x' UNION SELECT role, table_name, privilege FROM _lab_grants --"})
    assert union["row_count"] == 0 and "prohibited" in (union["error"] or "")
    assert status(client, learner, "database")["injection"]


def test_masking_and_audit_and_backup_restore(client, learner):
    for col in ("card_number", "email", "dob"):
        api(client, learner, "PUT", "/api/labs/database/masking", json={"column": col, "enabled": True})
    r = api(client, learner, "POST", "/api/labs/database/query", json={"role": "support_agent", "sql": "SELECT * FROM customers_masked LIMIT 3"})
    card = r["rows"][0][r["columns"].index("card_number")]
    assert card.startswith("**** **** **** ")
    assert status(client, learner, "database")["masking"]

    entries = api(client, learner, "GET", "/api/labs/database/audit")["entries"]
    bulk = next(e for e in entries if e["source"] == "seeded-history" and e["rows_returned"] == 300)
    normal = next(e for e in entries if e["source"] == "seeded-history" and e["rows_returned"] == 1)
    assert not api(client, learner, "POST", "/api/labs/database/audit/identify", json={"audit_id": normal["id"]})["correct"]
    assert api(client, learner, "POST", "/api/labs/database/audit/identify", json={"audit_id": bulk["id"]})["correct"]

    b = api(client, learner, "POST", "/api/labs/database/backup")
    d = api(client, learner, "POST", "/api/labs/database/damage")
    assert d["customers_rows"] == 275
    assert not api(client, learner, "POST", "/api/labs/database/verify", json={"backup_id": b["backup_id"]})["match"]
    api(client, learner, "POST", "/api/labs/database/restore", json={"backup_id": b["backup_id"]})
    v = api(client, learner, "POST", "/api/labs/database/verify", json={"backup_id": b["backup_id"]})
    assert v["match"] and v["live_rows"] == 300
    assert client.post("/api/labs/database/restore", headers=learner, json={"backup_id": "../../etc/passwd"}).status_code == 400
    st = status(client, learner, "database")
    assert st["audit"] and st["backup_restore"]


def test_lab_files_are_isolated_per_user(client, learner):
    from conftest import register
    other = register(client, "otheruser")
    api(client, learner, "POST", "/api/labs/database/grants/revoke", json={"role": "support_agent", "table": "customers"})
    theirs = api(client, other, "GET", "/api/labs/database")["grants"]
    assert {"role": "support_agent", "table_name": "customers", "privilege": "SELECT"} in theirs


# --------------------------------------------------------------------------- simulated labs


def test_cloud_lab_assess_and_remediate_without_business_disruption(client, learner):
    ov = api(client, learner, "GET", "/api/labs/cloud")
    assert ov["provenance"] == "SIMULATED" and all(e["provenance"] == "SIMULATED" for e in ov["audit_events"])
    a = api(client, learner, "POST", "/api/labs/cloud/assess")
    assert a["buckets"][0]["bucket"] == "kr-analytics-exports"
    assert api(client, learner, "POST", "/api/labs/cloud/assess/answer", json={"bucket": "kr-analytics-exports"})["correct"]
    # Over-remediation: making the marketing website private breaks a documented requirement.
    api(client, learner, "POST", "/api/labs/cloud/change", json={"bucket": "kr-marketing-site", "field": "access", "value": "RESTRICTED"})
    for bucket, field, value in (("kr-analytics-exports", "access", "RESTRICTED"), ("kr-analytics-exports", "encryption", True),
                                 ("kr-analytics-exports", "access_logging", True), ("kr-hr-scans", "remove_principal", "acct-helpwise-vendor"),
                                 ("kr-hr-scans", "access_logging", True)):
        api(client, learner, "POST", "/api/labs/cloud/change", json={"bucket": bucket, "field": field, "value": value})
    api(client, learner, "POST", "/api/labs/cloud/assess")
    res = api(client, learner, "POST", "/api/labs/cloud/verify")
    assert not res["passed"] and any("marketing" in r for r in res["reasons"])
    api(client, learner, "POST", "/api/labs/cloud/change", json={"bucket": "kr-marketing-site", "field": "access", "value": "PUBLIC_READ"})
    assert not api(client, learner, "POST", "/api/labs/cloud/verify")["passed"]  # needs a re-assessment after the last change
    api(client, learner, "POST", "/api/labs/cloud/assess")
    assert api(client, learner, "POST", "/api/labs/cloud/verify")["passed"]


def test_privacy_lab_minimization_retention_and_legal_hold(client, learner):
    ov = api(client, learner, "GET", "/api/labs/privacy")
    fields = ov["fields"]
    decisions = {f: {"decision": "KEEP", "reason": "needed for purpose"} for f in fields}
    for f in ("national_id", "card_number", "date_of_birth"):
        decisions[f] = {"decision": "REMOVE", "reason": "not needed for newsletters"}
    assert api(client, learner, "PUT", "/api/labs/privacy/minimization", json={"decisions": decisions})["passed"]

    # Ignoring legal hold deletes held records: critical failure.
    api(client, learner, "POST", "/api/labs/privacy/retention/evaluate", json={"inactive_days": 730, "no_consent_days": 30, "respect_legal_hold": False})
    assert client.post("/api/labs/privacy/retention/execute", headers=learner, json={"confirm": False}).status_code == 409
    bad = api(client, learner, "POST", "/api/labs/privacy/retention/execute", json={"confirm": True})
    if bad["legal_hold_deleted"]:
        assert not bad["passed"]
    api(client, learner, "POST", "/api/labs/privacy/reset")
    api(client, learner, "PUT", "/api/labs/privacy/minimization", json={"decisions": decisions})
    prev = api(client, learner, "POST", "/api/labs/privacy/retention/evaluate", json={"inactive_days": 730, "no_consent_days": 30, "respect_legal_hold": True})
    assert prev["to_delete"] > 0
    good = api(client, learner, "POST", "/api/labs/privacy/retention/execute", json={"confirm": True})
    assert good["passed"] and not good["legal_hold_deleted"]
    report = client.get("/api/labs/privacy/report", headers=learner).text
    assert "not legal advice" in report and "Records deleted" in report
    st = status(client, learner, "privacy")
    assert st["minimization"] and st["retention"] and st["report"]


def test_ai_lab_gateway_rag_and_logging(client, learner):
    ov = api(client, learner, "GET", "/api/labs/ai")
    initial = api(client, learner, "POST", "/api/labs/ai/gateway/evaluate")
    assert not initial["passed"]
    policy = copy.deepcopy(ov["state"]["gateway_policy"])
    policy.update(outcome="BLOCK", conditions={"match": "any", "conditions": [
        {"match": "all", "conditions": [
            {"field": "destination.sanctioned", "op": "eq", "value": False},
            {"field": "content.detected_types", "op": "contains_any",
             "value": ["CREDIT_CARD", "SECRET_CREDENTIAL", "CONFIDENTIAL_MARKER", "CUSTOMER_ACCOUNT", "EMAIL_ADDRESS"]}]},
        {"field": "content.detected_types", "op": "contains_any", "value": ["CREDIT_CARD", "IBAN", "US_SSN", "SECRET_CREDENTIAL"]}]})
    res = api(client, learner, "PUT", "/api/labs/ai/gateway", json={"policy": policy})
    assert res["passed"], [r for r in res["results"] if not r["correct"]]
    assert api(client, learner, "POST", "/api/labs/ai/gateway/evaluate")["passed"]

    leak = api(client, learner, "POST", "/api/labs/ai/rag/query", json={"role": "support_agent", "query": "what is rita silva salary"})
    assert any(d["id"] in ("D2", "D5") for d in leak["results"])
    assert not api(client, learner, "POST", "/api/labs/ai/rag/tests")["passed"]
    api(client, learner, "PUT", "/api/labs/ai/rag", json={"enforce_acl": True, "index_restricted_docs": True})
    assert api(client, learner, "POST", "/api/labs/ai/rag/tests")["passed"]

    findings = api(client, learner, "PUT", "/api/labs/ai/logging", json={"prompt_logging": "full", "retention_days": 3650,
                                                                           "log_access": "all_staff", "vendor_training_opt_in": True})
    assert len(findings["findings"]) == 4
    assert api(client, learner, "PUT", "/api/labs/ai/logging", json={"prompt_logging": "redacted", "retention_days": 30,
                                                                       "log_access": "security_only", "vendor_training_opt_in": False})["passed"]
    st = status(client, learner, "ai")
    assert all(st.values())


def test_knowledge_check_graded_server_side(client, learner):
    q = api(client, learner, "GET", "/api/curriculum/quiz/M01-L1")
    assert "answer" not in str(q)
    bad = api(client, learner, "POST", "/api/curriculum/quiz/M01-L1", json={"answers": [0, 0, 0, 0]})
    assert not bad["passed"]
    good = api(client, learner, "POST", "/api/curriculum/quiz/M01-L1", json={"answers": [1, 1, 1, 1]})
    assert good["passed"]
    cur = api(client, learner, "GET", "/api/curriculum")
    lesson = next(x for x in cur["lessons"] if x["id"] == "M01-L1")
    assert lesson["completed"]
    assert next(m for m in cur["modules"] if m["id"] == "M10")["status"] == "PLANNED"


def test_specialist_pathway_unlocks_lessons(client, learner):
    cur = api(client, learner, "GET", "/api/curriculum")
    m08 = next(x for x in cur["lessons"] if x["id"] == "M08-L1")
    assert not m08["available"]
    api(client, learner, "PUT", "/api/curriculum/pathway", json={"pathway": "dlp-engineer"})
    cur = api(client, learner, "GET", "/api/curriculum")
    assert next(x for x in cur["lessons"] if x["id"] == "M08-L1")["available"]
    assert not next(x for x in cur["lessons"] if x["id"] == "M06-L1")["available"]
    dash = api(client, learner, "GET", "/api/dashboard")
    assert dash["pathway"]["id"] == "dlp-engineer" and dash["next_lesson"]


def test_integrations_are_honest(client, learner):
    ints = api(client, learner, "GET", "/api/integrations")
    purview = next(i for i in ints if i["key"] == "microsoft-purview")
    assert purview["status"] == "NOT_IMPLEMENTED" and not purview["enabled"] and not purview["tested"]
    assert all(i["status"] in ("IMPLEMENTED", "NOT_IMPLEMENTED", "GUIDE_ONLY") for i in ints)
