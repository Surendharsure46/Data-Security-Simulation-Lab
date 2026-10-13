"""Hands-on lab endpoints. Every response states its provenance (REAL_LAB or SIMULATED)."""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..labs import dblab, encryption as enc, get_state, lab_dir, passed_exercises, record_result, set_state, simlabs
from ..models import User
from ..security import current_user
from ..services.common import DomainError

router = APIRouter(prefix="/api/labs", tags=["labs"])

LAB_EXERCISES = {
    "encryption": {"mode": "REAL_LAB (TLS and config review: SIMULATED)",
                   "exercises": ["hashing", "file_roundtrip", "envelope_rotation", "tls_metadata", "config_review"]},
    "database": {"mode": "REAL_LAB", "exercises": ["least_privilege", "injection", "masking", "audit", "backup_restore"]},
    "cloud": {"mode": "SIMULATED", "exercises": ["assess", "remediate"]},
    "privacy": {"mode": "SIMULATED", "exercises": ["minimization", "retention", "report"]},
    "ai": {"mode": "SIMULATED", "exercises": ["prompt_gateway", "rag_acl", "retention"]},
}


def _pass_once(db: Session, user: User, lab: str, exercise: str, provenance: str, detail: dict[str, Any]) -> bool:
    if exercise in passed_exercises(db, user, lab):
        return False
    record_result(db, user, lab, exercise, True, provenance, detail)
    return True


@router.get("/status")
def status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {lab: {"mode": v["mode"], "exercises": {e: e in passed_exercises(db, user, lab) for e in v["exercises"]}}
            for lab, v in LAB_EXERCISES.items()}


# =========================================================================== encryption

ENC_DEFAULT: dict[str, Any] = {"hashed": [], "file": {}, "envelope": {}, "config": None}


class HashIn(BaseModel):
    file: str = Field(max_length=60)


class AnswerFileIn(BaseModel):
    modified_file: str = Field(max_length=60)


class PassIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=200)


class HmacIn(BaseModel):
    message: str = Field(max_length=2000)
    key_label: str = Field(default="lab-key", max_length=40)


@router.get("/encryption")
def enc_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    db.commit()
    return {"files": sorted(enc.HASH_FILES), "manifest": enc.MANIFEST, "state": {k: v for k, v in st.state.items() if k != "file"} |
            {"file": {k: v for k, v in (st.state.get("file") or {}).items() if k != "verifier"}},
            "passed": sorted(passed_exercises(db, user, "encryption")), "tls": {"capture": enc.TLS_CAPTURE, "items": enc.TLS_LABELS},
            "config_options": enc.CONFIG_OPTIONS, "config": st.state.get("config") or enc.WEAK_CONFIG}


@router.post("/encryption/hash")
def enc_hash(body: HashIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.hash_file(body.file)
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, hashed=sorted(set(st.state.get("hashed", [])) | {body.file}))
    db.commit()
    return {**res, "provenance": "REAL_LAB"}


@router.post("/encryption/hash/answer")
def enc_hash_answer(body: AnswerFileIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    if set(st.state.get("hashed", [])) != set(enc.HASH_FILES):
        raise DomainError("Hash all three files and compare them with the manifest before answering", 409)
    ok = body.modified_file == enc.TAMPERED_FILE
    if ok:
        _pass_once(db, user, "encryption", "hashing", "REAL_LAB", {"answer": body.modified_file})
    db.commit()
    return {"correct": ok, "explanation": "Its SHA-256 differs from the manifest; a single changed digit changes the whole digest." if ok
            else "That file's digest matches the manifest. Compare every digest with the published value."}


@router.post("/encryption/hmac")
def enc_hmac(body: HmacIn, user: User = Depends(current_user)):
    return {**enc.hmac_demo(body.message, body.key_label), "provenance": "REAL_LAB"}


def _verifier(passphrase: str, salt_hex: str) -> str:
    return hmac.new(enc._derive(passphrase, bytes.fromhex(salt_hex)), b"threatready-verifier", hashlib.sha256).hexdigest()


@router.post("/encryption/file/encrypt")
def enc_encrypt(body: PassIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = lab_dir(user, "crypto")
    res = enc.encrypt_sample(d, body.passphrase)
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, file={"encrypted": True, "tampered": False, "wrong_key_rejected": False, "correct_ok": False,
                        "tamper_rejected": False, "verifier": _verifier(body.passphrase, res["header"]["salt"])})
    db.commit()
    return res


@router.post("/encryption/file/decrypt")
def enc_decrypt(body: PassIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = lab_dir(user, "crypto")
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    f = dict(st.state.get("file") or {})
    if not f.get("encrypted"):
        raise DomainError("Encrypt the sample file first", 409)
    header, _hdr, _ct = enc._read_blob(d)
    correct_pass = hmac.compare_digest(_verifier(body.passphrase, header["salt"]), f["verifier"])
    res = enc.decrypt_sample(d, body.passphrase)
    if not res["success"] and not correct_pass and not f.get("tampered"):
        f["wrong_key_rejected"] = True
    if res["success"] and res["matches_original"]:
        f["correct_ok"] = True
    if not res["success"] and correct_pass and f.get("tampered"):
        f["tamper_rejected"] = True
    set_state(st, file=f)
    if all(f.get(k) for k in ("wrong_key_rejected", "correct_ok", "tamper_rejected")):
        _pass_once(db, user, "encryption", "file_roundtrip", "REAL_LAB", {k: f[k] for k in ("wrong_key_rejected", "correct_ok", "tamper_rejected")})
    db.commit()
    return {**res, "checks": {k: f.get(k, False) for k in ("wrong_key_rejected", "correct_ok", "tamper_rejected")}}


@router.post("/encryption/file/tamper")
def enc_tamper(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.tamper_sample(lab_dir(user, "crypto"))
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, file={**(st.state.get("file") or {}), "tampered": True})
    db.commit()
    return res


@router.post("/encryption/envelope/init")
def env_init(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.envelope_init(lab_dir(user, "crypto"))
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, envelope={"initial_data_sha256": res["data_ciphertext_sha256"], "rotated": False, "decrypted_after_rotation": False,
                            "data_unchanged": None})
    db.commit()
    return res


@router.post("/encryption/envelope/rotate")
def env_rotate(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.envelope_rotate(lab_dir(user, "crypto"))
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    e = dict(st.state.get("envelope") or {})
    e.update(rotated=True, data_unchanged=res["data_ciphertext_sha256"] == e.get("initial_data_sha256"))
    set_state(st, envelope=e)
    db.commit()
    return {**res, "data_unchanged_since_init": e["data_unchanged"]}


class EnvDecIn(BaseModel):
    kek_id: str | None = Field(default=None, max_length=20)


@router.post("/encryption/envelope/decrypt")
def env_decrypt(body: EnvDecIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.envelope_decrypt(lab_dir(user, "crypto"), body.kek_id)
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    e = dict(st.state.get("envelope") or {})
    if res["success"] and res["matches_original"] and e.get("rotated"):
        e["decrypted_after_rotation"] = True
    set_state(st, envelope=e)
    if e.get("rotated") and e.get("data_unchanged") and e.get("decrypted_after_rotation"):
        _pass_once(db, user, "encryption", "envelope_rotation", "REAL_LAB", e)
    db.commit()
    return res


class TlsIn(BaseModel):
    visible: list[str] = Field(max_length=20)


@router.post("/encryption/tls/answer")
def tls_answer(body: TlsIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = enc.grade_tls(body.visible)
    if res["passed"]:
        _pass_once(db, user, "encryption", "tls_metadata", "SIMULATED", {"answer": sorted(body.visible)})
    db.commit()
    return {k: v for k, v in res.items() if k != "per_item"} | {"provenance": "SIMULATED"}


class ConfigIn(BaseModel):
    tls_min_version: str
    cipher_suites: list[str] = Field(max_length=10)
    verify_server_certificate: bool
    at_rest_algorithm: str
    key_location: str
    key_rotation_days: int = Field(ge=0, le=3650)
    backup_encryption: bool
    secret_storage: str


@router.put("/encryption/config")
def put_config(body: ConfigIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    cfg = {"service": enc.WEAK_CONFIG["service"], **body.model_dump()}
    findings = enc.validate_config(cfg)  # validates allowed values
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, config=cfg)
    db.commit()
    return {"config": cfg, "findings_preview": len(findings)}


@router.post("/encryption/config/validate")
def validate_config(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    cfg = st.state.get("config") or enc.WEAK_CONFIG
    findings = enc.validate_config(cfg)
    if not findings:
        _pass_once(db, user, "encryption", "config_review", "SIMULATED", {"config": cfg})
    db.commit()
    return {"findings": findings, "passed": not findings, "provenance": "SIMULATED"}


@router.post("/encryption/config/reset")
def reset_config(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = get_state(db, user, "encryption", dict(ENC_DEFAULT))
    set_state(st, config=None)
    db.commit()
    return {"config": enc.WEAK_CONFIG}


# =========================================================================== database

DB_DEFAULT: dict[str, Any] = {"denied_after_revoke": False, "masked_ok_after_revoke": False, "vuln_demo": None, "param_safe": False,
                              "backup_id": None, "damaged": False, "restored": False}


def _db_dir(user: User):
    return lab_dir(user, "database")


@router.get("/database")
def db_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _db_dir(user)
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    db.commit()
    return {"roles": dblab.ROLES, "grants": dblab.grants(d), "masking": dblab.masking(d), "masked_view_sql": dblab.masked_view_sql(d),
            "backups": dblab.backups(d), "state": st.state, "passed": sorted(passed_exercises(db, user, "database")),
            "tables": sorted(dblab.USER_TABLES), "enforcement": "SQLite authorizer callback (SQLite has no native roles or GRANT)",
            "provenance": "REAL_LAB"}


@router.post("/database/reset")
def db_reset(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.init_db(_db_dir(user))
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    st.state = dict(DB_DEFAULT)
    db.commit()
    return res


class QueryIn(BaseModel):
    role: str = Field(max_length=30)
    sql: str = Field(min_length=1, max_length=2000)


_REFS_CUSTOMERS = re.compile(r"\bcustomers\b(?!_masked)", re.I)
_REFS_MASKED = re.compile(r"\bcustomers_masked\b", re.I)


@router.post("/database/query")
def db_query(body: QueryIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _db_dir(user)
    res = dblab.run_query(d, body.role, body.sql)
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    s = dict(st.state)
    revoked = not any(g["role"] == "support_agent" and g["table_name"] == "customers" for g in dblab.grants(d))
    if body.role == "support_agent" and revoked:
        if res["decision"] == "DENIED" and _REFS_CUSTOMERS.search(body.sql):
            s["denied_after_revoke"] = True
        if res["decision"] == "ALLOWED" and _REFS_MASKED.search(body.sql) and res["row_count"] > 0:
            s["masked_ok_after_revoke"] = True
    st.state = s
    if revoked and s["denied_after_revoke"] and s["masked_ok_after_revoke"]:
        _pass_once(db, user, "database", "least_privilege", "REAL_LAB", {"denied_after_revoke": True, "masked_ok": True})
    m = dblab.masking(d)
    if (body.role == "support_agent" and res["decision"] == "ALLOWED" and _REFS_MASKED.search(body.sql) and res["row_count"] > 0
            and all(m[c] for c in ("card_number", "email", "dob")) and "card_number" in res["columns"]):
        flat = " ".join(str(v) for row in res["rows"] for v in row)
        if not dblab.PAN_RE.search(flat) and not re.search(r"\b[a-z]{2,}\.[a-z]+\d*@", flat):
            _pass_once(db, user, "database", "masking", "REAL_LAB", {"columns_masked": [c for c, v in m.items() if v]})
    db.commit()
    return res


class GrantIn(BaseModel):
    role: str = Field(max_length=30)
    table: str = Field(max_length=40)


@router.post("/database/grants/revoke")
def db_revoke(body: GrantIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = dblab.revoke(_db_dir(user), body.role, body.table)
    if n == 0:
        raise DomainError("No such grant", 404)
    return {"revoked": n, "grants": dblab.grants(_db_dir(user)), "provenance": "REAL_LAB"}


@router.post("/database/grants/grant")
def db_grant(body: GrantIn, user: User = Depends(current_user)):
    dblab.grant(_db_dir(user), body.role, body.table)
    return {"grants": dblab.grants(_db_dir(user)), "provenance": "REAL_LAB"}


class LookupIn(BaseModel):
    mode: Literal["vulnerable", "parameterized"]
    email: str = Field(max_length=200)


@router.post("/database/lookup")
def db_lookup(body: LookupIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.lookup(_db_dir(user), body.mode, body.email)
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    s = dict(st.state)
    injected = "'" in body.email
    if body.mode == "vulnerable" and injected and res["row_count"] > 1:
        s["vuln_demo"] = body.email
    if body.mode == "parameterized" and injected and res["row_count"] == 0 and s.get("vuln_demo") == body.email:
        s["param_safe"] = True
    st.state = s
    if s.get("vuln_demo") and s.get("param_safe"):
        _pass_once(db, user, "database", "injection", "REAL_LAB", {"payload": s["vuln_demo"]})
    db.commit()
    return res


class MaskIn(BaseModel):
    column: str = Field(max_length=30)
    enabled: bool


@router.put("/database/masking")
def db_mask(body: MaskIn, user: User = Depends(current_user)):
    m = dblab.set_masking(_db_dir(user), body.column, body.enabled)
    return {"masking": m, "masked_view_sql": dblab.masked_view_sql(_db_dir(user)), "provenance": "REAL_LAB"}


@router.get("/database/audit")
def db_audit(user: User = Depends(current_user)):
    return {"entries": dblab.audit_log(_db_dir(user)), "provenance": "REAL_LAB",
            "note": "Entries with source 'seeded-history' are pre-loaded synthetic history; 'learner' entries record your real queries."}


class IdentifyIn(BaseModel):
    audit_id: int


@router.post("/database/audit/identify")
def db_identify(body: IdentifyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ok = body.audit_id in dblab.bulk_audit_ids(_db_dir(user))
    if ok:
        _pass_once(db, user, "database", "audit", "REAL_LAB", {"audit_id": body.audit_id})
    db.commit()
    return {"correct": ok, "explanation": "A support role read every customer row at 02:13 — bulk, after hours, from the unmasked table." if ok
            else "That entry is consistent with the role's normal single-record work. Look at rows returned, time and object."}


@router.post("/database/backup")
def db_backup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.backup(_db_dir(user))
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    st.state = {**st.state, "backup_id": res["backup_id"], "damaged": False, "restored": False}
    db.commit()
    return res


@router.post("/database/damage")
def db_damage(user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.damage(_db_dir(user))
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    st.state = {**st.state, "damaged": bool(st.state.get("backup_id"))}
    db.commit()
    return res


class BackupIn(BaseModel):
    backup_id: str = Field(max_length=60)


@router.post("/database/restore")
def db_restore(body: BackupIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.restore(_db_dir(user), body.backup_id)
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    st.state = {**st.state, "restored": st.state.get("damaged") and body.backup_id == st.state.get("backup_id")}
    db.commit()
    return res


@router.post("/database/verify")
def db_verify(body: BackupIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = dblab.verify_restore(_db_dir(user), body.backup_id)
    st = get_state(db, user, "database", dict(DB_DEFAULT))
    if res["match"] and st.state.get("restored") and body.backup_id == st.state.get("backup_id"):
        _pass_once(db, user, "database", "backup_restore", "REAL_LAB", res)
    db.commit()
    return res


# =========================================================================== cloud (simulated)


def _cloud(db: Session, user: User):
    import copy
    return get_state(db, user, "cloud", copy.deepcopy(simlabs.CLOUD_INITIAL))


@router.get("/cloud")
def cloud_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _cloud(db, user)
    db.commit()
    return {"buckets": st.state["buckets"], "access_options": simlabs.CLOUD_ACCESS_OPTIONS, "target": simlabs.CLOUD_TARGET,
            "audit_events": simlabs.cloud_audit_events(st.state), "assessments_run": st.state["assessments"],
            "risk_model": "exposure = sensitivity(0-3) × access breadth (public/all-authenticated 3, cross-account 2, org-wide 1, restricted 0) "
                          "+ 1 per missing control (encryption, access logging) when sensitivity ≥ Confidential",
            "passed": sorted(passed_exercises(db, user, "cloud")), "provenance": "SIMULATED",
            "note": "Simulated object storage. Events are synthetic and are not AWS, Azure or Google Cloud telemetry."}


@router.post("/cloud/assess")
def cloud_assess(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _cloud(db, user)
    s = dict(st.state)
    s["assessments"] += 1
    s["last_assessment_seq"] = s["seq"]
    st.state = s
    db.commit()
    return simlabs.cloud_assess(s)


class BucketAnswerIn(BaseModel):
    bucket: str = Field(max_length=60)


@router.post("/cloud/assess/answer")
def cloud_answer(body: BucketAnswerIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _cloud(db, user)
    if st.state["assessments"] < 1:
        raise DomainError("Run an assessment first", 409)
    import copy
    top = simlabs.cloud_assess(copy.deepcopy(simlabs.CLOUD_INITIAL))["buckets"][0]["bucket"]
    ok = body.bucket == top
    if ok:
        _pass_once(db, user, "cloud", "assess", "SIMULATED", {"bucket": body.bucket})
    db.commit()
    return {"correct": ok}


class CloudChangeIn(BaseModel):
    bucket: str = Field(max_length=60)
    field: Literal["access", "encryption", "access_logging", "remove_principal"]
    value: Any


@router.post("/cloud/change")
def cloud_change(body: CloudChangeIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _cloud(db, user)
    st.state = simlabs.cloud_change(st.state, body.bucket, body.field, body.value)
    db.commit()
    return {"buckets": st.state["buckets"], "audit_events": simlabs.cloud_audit_events(st.state)}


@router.post("/cloud/verify")
def cloud_verify(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _cloud(db, user)
    res = simlabs.cloud_remediation_result(st.state)
    if res["passed"]:
        _pass_once(db, user, "cloud", "remediate", "SIMULATED", {"total": res["assessment"]["total_exposure_non_public"]})
    db.commit()
    return res


@router.post("/cloud/reset")
def cloud_reset(user: User = Depends(current_user), db: Session = Depends(get_db)):
    import copy
    st = _cloud(db, user)
    st.state = copy.deepcopy(simlabs.CLOUD_INITIAL)
    db.commit()
    return {"ok": True}


# =========================================================================== privacy (simulated)


def _privacy(db: Session, user: User):
    return get_state(db, user, "privacy", simlabs.privacy_initial())


@router.get("/privacy")
def privacy_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _privacy(db, user)
    db.commit()
    return {"purpose": simlabs.PRIVACY_PURPOSE, "retention_standard": simlabs.RETENTION_STANDARD, "fields": simlabs.LEAD_FIELDS,
            "lab_today": simlabs.LAB_TODAY.isoformat(), "state": st.state, "passed": sorted(passed_exercises(db, user, "privacy")),
            "provenance": "SIMULATED",
            "note": "Disposable synthetic records. Deletion here permanently removes records from your lab copy only; reset restores them."}


class Decision(BaseModel):
    decision: Literal["KEEP", "REMOVE"]
    reason: str = Field(max_length=500)


class MinIn(BaseModel):
    decisions: dict[str, Decision]


@router.put("/privacy/minimization")
def privacy_min(body: MinIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    decisions = {k: v.model_dump() for k, v in body.decisions.items()}
    res = simlabs.privacy_grade_minimization(decisions)
    st = _privacy(db, user)
    st.state = {**st.state, "field_decisions": decisions, "minimization_result": res}
    if res["passed"]:
        _pass_once(db, user, "privacy", "minimization", "SIMULATED", res)
    db.commit()
    return res


class RetentionIn(BaseModel):
    inactive_days: int = Field(ge=1, le=10000)
    no_consent_days: int = Field(ge=1, le=10000)
    respect_legal_hold: bool


@router.post("/privacy/retention/evaluate")
def privacy_eval(body: RetentionIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _privacy(db, user)
    rule = body.model_dump()
    preview = simlabs.privacy_evaluate(st.state, rule)
    st.state = {**st.state, "retention": rule, "evaluations": st.state.get("evaluations", 0) + 1}
    db.commit()
    return {"rule": rule, "matches": preview, "to_delete": sum(1 for p in preview if p["action"] == "DELETE")}


class ConfirmIn(BaseModel):
    confirm: bool = False


@router.post("/privacy/retention/execute")
def privacy_exec(body: ConfirmIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not body.confirm:
        raise HTTPException(409, "Deletion is irreversible for this lab copy. Resubmit with confirm=true.")
    st = _privacy(db, user)
    rule = st.state.get("retention")
    if not rule:
        raise DomainError("Evaluate a retention rule first", 409)
    expected = simlabs.privacy_expected_deletions(st.state)
    plan = simlabs.privacy_evaluate(st.state, rule)
    delete_ids = {p["lead_id"] for p in plan if p["action"] == "DELETE"}
    held_deleted = sorted(i for i in delete_ids if next(x for x in st.state["leads"] if x["lead_id"] == i)["legal_hold"])
    s = dict(st.state)
    s["leads"] = [x for x in s["leads"] if x["lead_id"] not in delete_ids]
    s["deleted"] = sorted(set(s.get("deleted", [])) | delete_ids)
    if held_deleted:
        s["critical"] = f"Records under legal hold were deleted: {', '.join(held_deleted)}"
    st.state = s
    passed = not held_deleted and delete_ids == expected and not s.get("critical")
    if passed:
        _pass_once(db, user, "privacy", "retention", "SIMULATED", {"deleted": sorted(delete_ids)})
    db.commit()
    return {"deleted": sorted(delete_ids), "remaining": len(s["leads"]), "legal_hold_deleted": held_deleted, "passed": passed,
            "verification": f"Remaining records re-checked: {sum(1 for x in s['leads'] if x['lead_id'] in delete_ids)} deleted IDs still present.",
            "feedback": None if passed else ("Critical: legal hold must override deletion. Reset the lab to retry." if held_deleted
                                             else "The deleted set does not match the records standard. Reset the lab and compare your rule to the standard.")}


@router.get("/privacy/report")
def privacy_report(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _privacy(db, user)
    passed = passed_exercises(db, user, "privacy")
    md = simlabs.privacy_report(st.state, st.state.get("minimization_result"))
    if {"minimization", "retention"} <= passed:
        _pass_once(db, user, "privacy", "report", "SIMULATED", {})
    db.commit()
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


@router.post("/privacy/reset")
def privacy_reset(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _privacy(db, user)
    st.state = simlabs.privacy_initial()
    db.commit()
    return {"ok": True}


# =========================================================================== AI data security (simulated)


def _ai(db: Session, user: User):
    return get_state(db, user, "ai", simlabs.ai_initial())


@router.get("/ai")
def ai_overview(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    db.commit()
    return {"state": st.state, "prompts": [{k: v for k, v in p.items() if k != "should_block"} | {"expected": "BLOCK" if p["should_block"] else "ALLOW"}
                                           for p in simlabs.AI_PROMPTS],
            "destinations": simlabs.AI_DESTINATIONS, "documents": simlabs.RAG_DOCS, "roles": simlabs.RAG_ROLES,
            "rag_tests": simlabs.RAG_TESTS, "logging_options": simlabs.AI_LOG_OPTIONS,
            "passed": sorted(passed_exercises(db, user, "ai")), "provenance": "SIMULATED",
            "note": "No prompt is sent to any AI model. Retrieval is a deterministic keyword ranker used to test access control."}


class GatewayIn(BaseModel):
    policy: dict[str, Any]


@router.put("/ai/gateway")
def ai_gateway(body: GatewayIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = simlabs.ai_evaluate_prompts(body.policy)  # validates
    st = _ai(db, user)
    st.state = {**st.state, "gateway_policy": body.policy}
    db.commit()
    return res


@router.post("/ai/gateway/evaluate")
def ai_gateway_eval(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    res = simlabs.ai_evaluate_prompts(st.state["gateway_policy"])
    if res["passed"]:
        _pass_once(db, user, "ai", "prompt_gateway", "SIMULATED", {"correct": res["correct"]})
    db.commit()
    return res


class RagCfgIn(BaseModel):
    enforce_acl: bool
    index_restricted_docs: bool


@router.put("/ai/rag")
def ai_rag_cfg(body: RagCfgIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    st.state = {**st.state, "rag": body.model_dump()}
    db.commit()
    return st.state["rag"]


class RagQueryIn(BaseModel):
    role: str = Field(max_length=30)
    query: str = Field(min_length=1, max_length=300)


@router.post("/ai/rag/query")
def ai_rag_query(body: RagQueryIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    return {"results": simlabs.rag_retrieve(st.state["rag"], body.role, body.query), "config": st.state["rag"], "provenance": "SIMULATED"}


@router.post("/ai/rag/tests")
def ai_rag_tests(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    res = simlabs.rag_run_tests(st.state["rag"])
    if res["passed"]:
        _pass_once(db, user, "ai", "rag_acl", "SIMULATED", {"config": st.state["rag"]})
    db.commit()
    return res


class AiLogIn(BaseModel):
    prompt_logging: str
    retention_days: int = Field(ge=0, le=36500)
    log_access: str
    vendor_training_opt_in: bool


@router.put("/ai/logging")
def ai_logging(body: AiLogIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    cfg = body.model_dump()
    findings = simlabs.ai_logging_findings(cfg)
    st = _ai(db, user)
    st.state = {**st.state, "logging": cfg}
    if not findings:
        _pass_once(db, user, "ai", "retention", "SIMULATED", cfg)
    db.commit()
    return {"findings": findings, "passed": not findings, "provenance": "SIMULATED"}


@router.post("/ai/reset")
def ai_reset(user: User = Depends(current_user), db: Session = Depends(get_db)):
    st = _ai(db, user)
    st.state = simlabs.ai_initial()
    db.commit()
    return {"ok": True}
