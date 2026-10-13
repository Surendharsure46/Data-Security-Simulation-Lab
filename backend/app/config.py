"""Application configuration loaded from environment variables (prefix THREATREADY_)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="THREATREADY_",
        env_file=(str(BACKEND_DIR.parent / ".env"), str(BACKEND_DIR / ".env")),
        extra="ignore",
    )

    env: str = "development"
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'var' / 'threatready.db').as_posix()}"
    # Directory for REAL_LAB artefacts (encrypted files, lab SQLite databases, backups).
    lab_data_dir: Path = BACKEND_DIR / "var" / "labs"
    # Built frontend served by the backend in production mode (optional).
    frontend_dist: Path = BACKEND_DIR.parent / "frontend" / "dist"

    token_ttl_hours: int = 12
    password_hash_iterations: int = 600_000
    login_rate_limit_per_minute: int = 10
    allow_self_registration: bool = True

    # Bootstrap administrator. No default password: if unset, no admin is created.
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None
    default_organization: str = "Threatready Training Org"

    # Optional AI explanations. Disabled by default; core features never depend on it.
    ai_provider: str = "none"


@lru_cache
def get_settings() -> Settings:
    return Settings()
