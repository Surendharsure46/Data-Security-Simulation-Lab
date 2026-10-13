"""Start a throw-away backend for end-to-end tests.

Creates a fresh SQLite database and lab directory under backend/var/e2e, applies the
Alembic migrations and serves the API on the given port (default 8099).
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
E2E_DIR = BACKEND / "var" / "e2e"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099

if E2E_DIR.exists():
    shutil.rmtree(E2E_DIR)
E2E_DIR.mkdir(parents=True)
os.environ["THREATREADY_DATABASE_URL"] = f"sqlite:///{(E2E_DIR / 'e2e.db').as_posix()}"
os.environ["THREATREADY_LAB_DATA_DIR"] = str(E2E_DIR / "labs")
os.environ["THREATREADY_PASSWORD_HASH_ITERATIONS"] = "10000"
os.environ["THREATREADY_FRONTEND_DIST"] = str(E2E_DIR / "no-dist")
sys.path.insert(0, str(BACKEND))

from app.cli import ensure_org_and_admin, upgrade  # noqa: E402

upgrade()
ensure_org_and_admin()

import uvicorn  # noqa: E402

uvicorn.run("app.main:app", host="127.0.0.1", port=PORT, log_level="warning")
