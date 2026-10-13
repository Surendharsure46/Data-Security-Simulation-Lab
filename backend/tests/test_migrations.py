"""The Alembic migration chain must produce exactly the ORM schema."""
from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from app.cli import upgrade
from app.db import Base


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    upgrade(url)
    eng = create_engine(url)
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    eng.dispose()
    assert diff == [], diff
