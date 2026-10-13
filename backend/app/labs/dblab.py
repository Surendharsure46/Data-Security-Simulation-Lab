"""Database Security Lab (REAL_LAB) on a disposable per-user SQLite database.

SQLite has no native users, roles or GRANT statements. This lab enforces
application roles with SQLite's authorizer callback (``Connection.set_authorizer``),
which is SQLite's real mechanism for statement-level access decisions. The lab
documentation says so explicitly; it does not pretend SQLite behaves like
PostgreSQL or MySQL.

Safety: learner SQL runs only against the learner's own lab file, one statement at
a time, read-only for non-DBA roles, with ATTACH/DETACH/PRAGMA and internal tables
denied, a row cap and an instruction budget.
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..content.company import _luhn_complete, _name, _phone
from ..services.common import DomainError

ROLES = {
    "support_agent": "Front-line support: should read masked customer data and cases only",
    "analyst": "Analytics: masked customer data only",
    "reporting_svc": "Reporting service: support cases only",
    "dba": "Database administrator: full control",
}
INITIAL_GRANTS = [
    ("support_agent", "customers_masked", "SELECT"),
    ("support_agent", "support_cases", "SELECT"),
    ("support_agent", "customers", "SELECT"),  # excessive: added during a 2024 migration, never removed
    ("analyst", "customers_masked", "SELECT"),
    ("reporting_svc", "support_cases", "SELECT"),
]
USER_TABLES = {"customers", "support_cases", "customers_masked"}
MAX_ROWS = 200
MASK_EXPR = {
    "card_number": ("card_number", "'**** **** **** ' || substr(card_number, -4)"),
    "email": ("email", "substr(email, 1, 1) || '***@' || substr(email, instr(email, '@') + 1)"),
    "dob": ("dob", "substr(dob, 1, 4) || '-**-**'"),
    "phone": ("phone", "'(***) ***-' || substr(phone, -4)"),
}
PAN_RE = re.compile(r"\b\d{13,19}\b")


def db_path(d: Path) -> Path:
    return d / "kr_lab.sqlite"


def _connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=5)
    con.row_factory = sqlite3.Row
    return con


def _rebuild_masked_view(con: sqlite3.Connection) -> None:
    enabled = {r["column_name"] for r in con.execute("SELECT column_name FROM _lab_masking WHERE enabled = 1")}
    cols = ["id", "full_name"]
    for col in ("email", "phone", "dob", "card_number"):
        cols.append(f"{MASK_EXPR[col][1]} AS {col}" if col in enabled else col)
    cols.append("segment")
    con.execute("DROP VIEW IF EXISTS customers_masked")
    con.execute(f"CREATE VIEW customers_masked AS SELECT {', '.join(cols)} FROM customers")


_INIT_LOCK = threading.Lock()


def init_db(d: Path) -> dict[str, Any]:
    """Build the lab database in a temporary file and swap it in atomically, so concurrent
    requests never observe a half-initialised database."""
    with _INIT_LOCK:
        return _init_db_locked(d)


def _init_db_locked(d: Path) -> dict[str, Any]:
    path = db_path(d)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    rng = random.Random(4242)
    with closing(_connect(tmp)) as con:
        con.executescript(
            """
            CREATE TABLE customers (id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, dob TEXT,
                                    card_number TEXT, segment TEXT);
            CREATE TABLE support_cases (id INTEGER PRIMARY KEY, customer_id INTEGER, opened TEXT, subject TEXT, status TEXT);
            CREATE TABLE _lab_grants (role TEXT, table_name TEXT, privilege TEXT, PRIMARY KEY (role, table_name, privilege));
            CREATE TABLE _lab_audit (id INTEGER PRIMARY KEY, ts TEXT, role TEXT, statement TEXT, rows_returned INTEGER,
                                     decision TEXT, source TEXT);
            CREATE TABLE _lab_masking (column_name TEXT PRIMARY KEY, enabled INTEGER);
            """
        )
        for i in range(1, 301):
            f, l = _name(rng)
            con.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?)",
                        (i, f"{f} {l}", f"{f.lower()}.{l.lower()}{i}@example.com", _phone(rng),
                         f"{rng.randint(1950, 2004)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                         _luhn_complete("4", 16, rng), rng.choice(["retail", "premier", "small-business"])))
        for i in range(1, 121):
            con.execute("INSERT INTO support_cases VALUES (?,?,?,?,?)",
                        (i, rng.randint(1, 300), f"2026-03-{rng.randint(1, 9):02d}",
                         rng.choice(["Card declined", "Address change", "Fee dispute", "Statement copy"]), rng.choice(["open", "closed"])))
        con.executemany("INSERT INTO _lab_grants VALUES (?,?,?)", INITIAL_GRANTS)
        con.executemany("INSERT INTO _lab_masking VALUES (?,?)", [(c, 0) for c in MASK_EXPR])
        history = [
            ("2026-03-08T09:12:44Z", "support_agent", "SELECT * FROM customers_masked WHERE id = 118", 1),
            ("2026-03-08T09:40:02Z", "support_agent", "SELECT * FROM support_cases WHERE customer_id = 118", 3),
            ("2026-03-08T11:05:19Z", "analyst", "SELECT segment, count(*) FROM customers_masked GROUP BY segment", 3),
            ("2026-03-08T13:22:51Z", "reporting_svc", "SELECT status, count(*) FROM support_cases GROUP BY status", 2),
            ("2026-03-09T02:13:07Z", "support_agent", "SELECT * FROM customers", 300),
            ("2026-03-09T08:58:30Z", "support_agent", "SELECT * FROM customers_masked WHERE id = 42", 1),
        ]
        con.executemany("INSERT INTO _lab_audit (ts, role, statement, rows_returned, decision, source) VALUES (?,?,?,?,'ALLOWED','seeded-history')", history)
        _rebuild_masked_view(con)
        con.commit()
    os.replace(tmp, path)
    return {"path": path.name, "customers": 300, "support_cases": 120, "provenance": "REAL_LAB"}


def require_db(d: Path) -> Path:
    p = db_path(d)
    if not p.exists():
        with _INIT_LOCK:
            if not p.exists():
                _init_db_locked(d)
    return p


def grants(d: Path) -> list[dict[str, str]]:
    with closing(_connect(require_db(d))) as con:
        return [dict(r) for r in con.execute("SELECT role, table_name, privilege FROM _lab_grants ORDER BY role, table_name")]


def revoke(d: Path, role: str, table: str) -> int:
    with closing(_connect(require_db(d))) as con:
        cur = con.execute("DELETE FROM _lab_grants WHERE role = ? AND table_name = ?", (role, table))
        con.commit()
        return cur.rowcount


def grant(d: Path, role: str, table: str) -> None:
    if role not in ROLES or table not in USER_TABLES:
        raise DomainError("Unknown role or table")
    with closing(_connect(require_db(d))) as con:
        con.execute("INSERT OR IGNORE INTO _lab_grants VALUES (?,?, 'SELECT')", (role, table))
        con.commit()


def _authorizer(role: str, allowed_tables: set[str]):
    def auth(action, arg1, arg2, dbname, source):
        if role == "dba":
            if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA):
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and arg1 and arg1.startswith("_lab_"):
                return sqlite3.SQLITE_DENY
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE, sqlite3.SQLITE_DROP_TABLE,
                          sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_CREATE_TABLE) and arg1 and arg1.startswith("_lab_"):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_SELECT or action == sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            # Reads through a view report the view name in ``source``; the view grant then applies.
            obj = source if source else arg1
            if obj in allowed_tables:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY

    return auth


def _audit(con: sqlite3.Connection, role: str, sql: str, rows: int, decision: str) -> int:
    cur = con.execute("INSERT INTO _lab_audit (ts, role, statement, rows_returned, decision, source) VALUES (?,?,?,?,?, 'learner')",
                      (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), role, sql[:500], rows, decision))
    con.commit()
    return cur.lastrowid


def run_query(d: Path, role: str, sql: str) -> dict[str, Any]:
    if role not in ROLES:
        raise DomainError(f"Unknown role. Roles: {', '.join(ROLES)}")
    sql = sql.strip().rstrip(";")
    if not sql or len(sql) > 2000:
        raise DomainError("Provide one SQL statement (max 2000 characters)")
    path = require_db(d)
    with closing(_connect(path)) as admin:
        allowed = {r["table_name"] for r in admin.execute("SELECT table_name FROM _lab_grants WHERE role = ? AND privilege = 'SELECT'", (role,))}
    con = _connect(path)
    started = time.monotonic()
    con.set_progress_handler(lambda: 1 if time.monotonic() - started > 2 else 0, 10_000)
    con.set_authorizer(_authorizer(role, allowed))
    try:
        cur = con.execute(sql)
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchmany(MAX_ROWS + 1)
        truncated = len(rows) > MAX_ROWS
        total = len(rows) + (len(cur.fetchall()) if truncated else 0)
        rows = rows[:MAX_ROWS]
        con.commit()
        decision, error = "ALLOWED", None
    except sqlite3.DatabaseError as exc:
        cols, rows, total, truncated = [], [], 0, False
        msg = str(exc)
        decision = "DENIED" if "not authorized" in msg or "prohibited" in msg else "ERROR"
        error = msg
    except sqlite3.Warning as exc:
        cols, rows, total, truncated, decision, error = [], [], 0, False, "ERROR", str(exc)
    finally:
        con.set_authorizer(None)
        con.close()
    with closing(_connect(path)) as admin:
        audit_id = _audit(admin, role, sql, total, decision)
    return {"role": role, "decision": decision, "error": error, "columns": cols, "rows": [list(r) for r in rows],
            "row_count": total, "truncated": truncated, "audit_id": audit_id, "allowed_objects": sorted(allowed),
            "enforcement": "sqlite3 authorizer callback (SQLite has no native roles)", "provenance": "REAL_LAB"}


def lookup(d: Path, mode: str, email: str) -> dict[str, Any]:
    """Customer lookup as the support portal would implement it."""
    if mode not in ("vulnerable", "parameterized"):
        raise DomainError("mode must be vulnerable or parameterized")
    if len(email) > 200:
        raise DomainError("Input too long")
    path = require_db(d)
    con = _connect(path)
    con.set_authorizer(_authorizer("portal", {"customers"}))
    started = time.monotonic()
    con.set_progress_handler(lambda: 1 if time.monotonic() - started > 2 else 0, 10_000)
    try:
        if mode == "vulnerable":
            sql = f"SELECT id, full_name, email FROM customers WHERE email = '{email}'"  # deliberately vulnerable (lab)
            cur = con.execute(sql)
        else:
            sql = "SELECT id, full_name, email FROM customers WHERE email = ?"
            cur = con.execute(sql, (email,))
        rows = [list(r) for r in cur.fetchmany(MAX_ROWS)]
        error = None
    except (sqlite3.DatabaseError, sqlite3.Warning) as exc:
        rows, error = [], str(exc)
    finally:
        con.close()
    return {"mode": mode, "executed_sql": sql, "bound_parameters": [email] if mode == "parameterized" else [],
            "rows": rows, "row_count": len(rows), "error": error, "provenance": "REAL_LAB"}


def masking(d: Path) -> dict[str, bool]:
    with closing(_connect(require_db(d))) as con:
        return {r["column_name"]: bool(r["enabled"]) for r in con.execute("SELECT column_name, enabled FROM _lab_masking")}


def set_masking(d: Path, column: str, enabled: bool) -> dict[str, bool]:
    if column not in MASK_EXPR:
        raise DomainError("Unknown column")
    with closing(_connect(require_db(d))) as con:
        con.execute("UPDATE _lab_masking SET enabled = ? WHERE column_name = ?", (int(enabled), column))
        _rebuild_masked_view(con)
        con.commit()
    return masking(d)


def masked_view_sql(d: Path) -> str:
    with closing(_connect(require_db(d))) as con:
        return con.execute("SELECT sql FROM sqlite_master WHERE name = 'customers_masked'").fetchone()[0]


def audit_log(d: Path) -> list[dict[str, Any]]:
    with closing(_connect(require_db(d))) as con:
        return [dict(r) for r in con.execute("SELECT * FROM _lab_audit ORDER BY id DESC LIMIT 200")]


def bulk_audit_ids(d: Path, threshold: int = 100) -> list[int]:
    with closing(_connect(require_db(d))) as con:
        return [r["id"] for r in con.execute(
            "SELECT id FROM _lab_audit WHERE source = 'seeded-history' AND rows_returned >= ? AND role != 'dba'", (threshold,))]


def customers_checksum(path: Path) -> tuple[int, str]:
    with closing(_connect(path)) as con:
        rows = con.execute("SELECT * FROM customers ORDER BY id").fetchall()
    h = hashlib.sha256()
    for r in rows:
        h.update(repr(tuple(r)).encode())
    return len(rows), h.hexdigest()


def backup(d: Path) -> dict[str, Any]:
    src = require_db(d)
    bdir = d / "backups"
    bdir.mkdir(exist_ok=True)
    name = f"kr_lab_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.sqlite"
    with closing(_connect(src)) as s, closing(sqlite3.connect(str(bdir / name))) as t:
        s.backup(t)
    count, digest = customers_checksum(bdir / name)
    return {"backup_id": name, "customers_rows": count, "customers_sha256": digest, "provenance": "REAL_LAB"}


def damage(d: Path) -> dict[str, Any]:
    with closing(_connect(require_db(d))) as con:
        cur = con.execute("DELETE FROM customers WHERE id IN (SELECT id FROM customers ORDER BY id DESC LIMIT 25)")
        con.commit()
        deleted = cur.rowcount
    count, digest = customers_checksum(db_path(d))
    return {"deleted_rows": deleted, "customers_rows": count, "customers_sha256": digest,
            "scenario": "Simulated incident: a faulty clean-up script deleted 25 customer rows from the lab database.",
            "provenance": "REAL_LAB"}


def _backup_file(d: Path, backup_id: str) -> Path:
    if not re.fullmatch(r"kr_lab_\d{8}T\d{12}\.sqlite", backup_id):
        raise DomainError("Invalid backup id")
    p = d / "backups" / backup_id
    if not p.exists():
        raise DomainError("Backup not found", 404)
    return p


def restore(d: Path, backup_id: str) -> dict[str, Any]:
    src = _backup_file(d, backup_id)
    with closing(sqlite3.connect(str(src))) as s, closing(sqlite3.connect(str(db_path(d)))) as t:
        s.backup(t)
    count, digest = customers_checksum(db_path(d))
    return {"restored_from": backup_id, "customers_rows": count, "customers_sha256": digest, "provenance": "REAL_LAB"}


def verify_restore(d: Path, backup_id: str) -> dict[str, Any]:
    src = _backup_file(d, backup_id)
    bc, bd = customers_checksum(src)
    lc, ld = customers_checksum(db_path(d))
    return {"backup_rows": bc, "live_rows": lc, "backup_sha256": bd, "live_sha256": ld, "match": bc == lc and bd == ld,
            "provenance": "REAL_LAB"}


def backups(d: Path) -> list[str]:
    bdir = d / "backups"
    return sorted(p.name for p in bdir.glob("kr_lab_*.sqlite")) if bdir.exists() else []
