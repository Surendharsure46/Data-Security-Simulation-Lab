"""Command-line administration.

    python -m app.cli init-db          # apply migrations, create default org, bootstrap admin if configured
    python -m app.cli create-user NAME --role instructor   # prompts for a password
    python -m app.cli validate-content # validate scenario definitions
    python -m app.cli reset-data --yes # delete the local database and lab files (development only)
"""
from __future__ import annotations

import argparse
import getpass
import shutil
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from . import db as dbmod
from .config import BACKEND_DIR, get_settings
from .models import Organization, User
from .security import hash_password


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url or get_settings().database_url)
    return cfg


def upgrade(url: str | None = None) -> None:
    url = url or get_settings().database_url
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(url), "head")


def ensure_org_and_admin() -> list[str]:
    s = get_settings()
    dbmod.configure()
    msgs = []
    with dbmod.SessionLocal() as db:
        org = db.scalar(select(Organization).order_by(Organization.id).limit(1))
        if org is None:
            org = Organization(name=s.default_organization, slug="default")
            db.add(org)
            db.flush()
            msgs.append(f"Created organisation '{org.name}'")
        if s.bootstrap_admin_password:
            if len(s.bootstrap_admin_password) < 12:
                raise SystemExit("THREATREADY_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
            if db.scalar(select(User).where(User.username == s.bootstrap_admin_username)) is None:
                db.add(User(org_id=org.id, username=s.bootstrap_admin_username, display_name="Administrator",
                            password_hash=hash_password(s.bootstrap_admin_password), role="admin"))
                msgs.append(f"Created administrator '{s.bootstrap_admin_username}'")
        else:
            msgs.append("No THREATREADY_BOOTSTRAP_ADMIN_PASSWORD set: no administrator created (learners can self-register).")
        db.commit()
    return msgs


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="threatready")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--role", choices=["learner", "instructor", "admin"], default="learner")
    cu.add_argument("--display-name", default=None)
    sub.add_parser("validate-content")
    rd = sub.add_parser("reset-data")
    rd.add_argument("--yes", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "init-db":
        upgrade()
        for m in ensure_org_and_admin():
            print(m)
        print("Database ready.")
    elif args.cmd == "create-user":
        pw = getpass.getpass("Password (min 10 chars, upper/lower/digit): ")
        if len(pw) < 10:
            print("Password too short", file=sys.stderr)
            return 1
        dbmod.configure()
        with dbmod.SessionLocal() as db:
            org = db.scalar(select(Organization).order_by(Organization.id).limit(1))
            if org is None:
                print("Run init-db first", file=sys.stderr)
                return 1
            if db.scalar(select(User).where(User.username == args.username.lower())):
                print("User exists", file=sys.stderr)
                return 1
            db.add(User(org_id=org.id, username=args.username.lower(), display_name=args.display_name or args.username,
                        password_hash=hash_password(pw), role=args.role))
            db.commit()
        print(f"Created {args.role} '{args.username.lower()}'")
    elif args.cmd == "validate-content":
        from .services.scenario_defs import all_definitions
        defs = all_definitions()
        for d in defs.values():
            print(f"OK  {d.id} v{d.version}: {len(d.timeline)} steps, {len(d.tasks)} tasks, {len(d.rubric.criteria)} criteria, {len(d.variants)} variants")
    elif args.cmd == "reset-data":
        if not args.yes:
            print("This deletes the local SQLite database and all lab files. Re-run with --yes to confirm.")
            return 1
        s = get_settings()
        if not s.database_url.startswith("sqlite:///"):
            print("reset-data only supports the local SQLite database", file=sys.stderr)
            return 1
        dbfile = Path(s.database_url.removeprefix("sqlite:///"))
        for f in (dbfile, dbfile.with_name(dbfile.name + "-wal"), dbfile.with_name(dbfile.name + "-shm")):
            if f.exists():
                f.unlink()
        if Path(s.lab_data_dir).exists():
            shutil.rmtree(s.lab_data_dir)
        print("Local data removed. Run 'python -m app.cli init-db' to recreate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
