"""Centralized configuration via pydantic-settings.

All environment variable parsing + validation lives here. Import
``get_settings()`` wherever config is needed and rely on its cached
singleton. Changing settings in tests requires ``get_settings.cache_clear()``.

Fail-fast behaviour
-------------------
The class emits warnings for missing secrets but does not raise — the
actual fail-fast guards live in ``app.auth`` and ``app.devices`` so that
importing this module remains cheap (and test fixtures can reassemble
the environment before touching security-sensitive modules).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration sourced from env vars (+ optional .env file).

    Field aliases keep the ``NKS_WDC_*`` naming so env vars don't shift
    between releases. ``extra="ignore"`` lets the service ignore unrelated
    env variables (Docker injects many).
    """

    # ── Secrets ─────────────────────────────────────────────────────────
    jwt_secret: Optional[str] = Field(None, alias="NKS_WDC_JWT_SECRET")
    session_secret: Optional[str] = Field(None, alias="NKS_WDC_SESSION_SECRET")
    catalog_secret_legacy: Optional[str] = Field(None, alias="NKS_WDC_CATALOG_SECRET")
    """Legacy combined secret — fallback for JWT + session when the
    dedicated vars are unset. Retired in Phase 2.1 but still honoured
    for operator convenience during rollout."""

    # ── Admin bootstrap ─────────────────────────────────────────────────
    admin_user: str = Field("admin", alias="NKS_WDC_CATALOG_ADMIN_USER")
    admin_pass: Optional[str] = Field(None, alias="NKS_WDC_CATALOG_ADMIN_PASS")

    # ── Toggles ─────────────────────────────────────────────────────────
    dev_mode: bool = Field(False, alias="NKS_WDC_CATALOG_DEV")
    allow_cors: bool = Field(False, alias="NKS_WDC_CATALOG_ALLOW_CORS")
    auto_migrate: bool = Field(False, alias="NKS_WDC_CATALOG_AUTO_MIGRATE")
    disable_rate_limits: bool = Field(False, alias="NKS_WDC_DISABLE_RATE_LIMITS")

    # ── Storage ─────────────────────────────────────────────────────────
    database_url: Optional[str] = Field(None, alias="DATABASE_URL")
    state_dir: Optional[str] = Field(None, alias="NKS_WDC_CATALOG_STATE_DIR")

    # ── Tunables ────────────────────────────────────────────────────────
    jwt_expire_days: int = Field(30, alias="NKS_WDC_JWT_EXPIRE_DAYS")
    bcrypt_rounds: int = Field(12, alias="NKS_WDC_BCRYPT_ROUNDS")
    session_max_age: int = Field(60 * 60 * 24 * 7, alias="NKS_WDC_SESSION_MAX_AGE")
    max_request_bytes: int = Field(1024 * 1024, alias="NKS_WDC_MAX_REQUEST_BYTES")
    catalog_cache_seconds: int = Field(60, alias="NKS_WDC_CATALOG_CACHE_SECONDS")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
        case_sensitive=False,
    )

    # ── Derived helpers ─────────────────────────────────────────────────
    @property
    def resolved_state_dir(self) -> Path:
        """Directory for SQLite + config-sync blobs. Respects explicit env,
        falls back to ``<repo>/state`` to match the legacy layout."""
        if self.state_dir:
            return Path(self.state_dir).resolve()
        return (Path(__file__).parent.parent / "state").resolve()

    @property
    def resolved_jwt_secret(self) -> Optional[str]:
        return self.jwt_secret or self.catalog_secret_legacy

    @property
    def resolved_session_secret(self) -> Optional[str]:
        return self.session_secret or self.catalog_secret_legacy


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached singleton — call ``get_settings.cache_clear()`` in tests."""
    return Settings()


def reload_settings() -> Settings:
    """Explicit cache reset + fresh read. Convenience wrapper for tests."""
    get_settings.cache_clear()
    return get_settings()


__all__ = ["Settings", "get_settings", "reload_settings"]
