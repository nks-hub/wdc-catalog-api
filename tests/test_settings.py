"""Tests for the pydantic-settings-based Settings class."""

from __future__ import annotations

import pytest

from app.settings import Settings, get_settings, reload_settings


@pytest.fixture(autouse=True)
def _clear_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_defaults_applied_when_env_empty(monkeypatch):
    for k in list(os.environ):  # type: ignore[name-defined]
        if k.startswith("NKS_WDC_"):
            monkeypatch.delenv(k, raising=False)
    s = reload_settings()
    assert s.admin_user == "admin"
    assert s.jwt_expire_days == 30
    assert s.bcrypt_rounds == 12
    assert s.max_request_bytes == 1024 * 1024


def test_secret_fallback_chain(monkeypatch):
    monkeypatch.setenv("NKS_WDC_CATALOG_SECRET", "legacy-secret")
    monkeypatch.delenv("NKS_WDC_JWT_SECRET", raising=False)
    monkeypatch.delenv("NKS_WDC_SESSION_SECRET", raising=False)
    s = reload_settings()
    assert s.resolved_jwt_secret == "legacy-secret"
    assert s.resolved_session_secret == "legacy-secret"


def test_dedicated_secrets_override_legacy(monkeypatch):
    monkeypatch.setenv("NKS_WDC_CATALOG_SECRET", "legacy")
    monkeypatch.setenv("NKS_WDC_JWT_SECRET", "jwt-only")
    monkeypatch.setenv("NKS_WDC_SESSION_SECRET", "session-only")
    s = reload_settings()
    assert s.resolved_jwt_secret == "jwt-only"
    assert s.resolved_session_secret == "session-only"


def test_resolved_state_dir_uses_env(monkeypatch, tmp_path):
    monkeypatch.setenv("NKS_WDC_CATALOG_STATE_DIR", str(tmp_path))
    s = reload_settings()
    assert s.resolved_state_dir == tmp_path.resolve()


def test_booleans_parse_from_env(monkeypatch):
    monkeypatch.setenv("NKS_WDC_CATALOG_DEV", "1")
    monkeypatch.setenv("NKS_WDC_CATALOG_ALLOW_CORS", "true")
    s = reload_settings()
    assert s.dev_mode is True
    assert s.allow_cors is True


# Import at bottom so monkeypatch fixture can delete env vars without
# polluting the os.environ snapshot used inside the first test.
import os  # noqa: E402
