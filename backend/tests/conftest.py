from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="threatready-tests-"))
os.environ["THREATREADY_DATABASE_URL"] = f"sqlite:///{(_TMP / 'bootstrap.db').as_posix()}"
os.environ["THREATREADY_LAB_DATA_DIR"] = str(_TMP / "labs")
os.environ["THREATREADY_PASSWORD_HASH_ITERATIONS"] = "1000"
os.environ["THREATREADY_FRONTEND_DIST"] = str(_TMP / "no-dist")
os.environ["THREATREADY_LOGIN_RATE_LIMIT_PER_MINUTE"] = "1000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbmod  # noqa: E402
from app.db import Base  # noqa: E402
from app.security import login_limiter  # noqa: E402

PASSWORD = "Synthetic-Pass-123"


@pytest.fixture
def client(tmp_path):
    dbmod.configure(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    Base.metadata.create_all(dbmod.engine)
    from app.main import create_app

    login_limiter.reset()
    with TestClient(create_app()) as c:
        yield c
    dbmod.engine.dispose()


def register(client: TestClient, username: str) -> dict[str, str]:
    r = client.post("/api/auth/register", json={"username": username, "display_name": username.title(), "password": PASSWORD})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture
def learner(client):
    return register(client, "learner1")


@pytest.fixture
def session_a(client, learner):
    r = client.post("/api/sessions", json={"scenario_id": "customer-data-export", "mode": "GUIDED", "variant": "A"}, headers=learner)
    assert r.status_code == 201, r.text
    return r.json()["id"]
