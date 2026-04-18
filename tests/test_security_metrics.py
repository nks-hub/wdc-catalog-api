"""`nks_wdc_security_events_total{action}` counter — increments
from `audit.emit` when action is on the SECURITY_ACTION_ALLOWLIST."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    """Trigger create_all via the FastAPI lifespan once per module so
    direct `session_factory()` calls find the audit_events table."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app):
        yield


def _get_counter(action: str) -> float:
    """Read the current `nks_wdc_security_events_total{action=...}` value.
    Returns 0 if the label hasn't been seen yet."""
    from app.observability import SECURITY_EVENTS

    # prometheus_client samples are per-label-set; find ours.
    for metric in SECURITY_EVENTS.collect():
        for sample in metric.samples:
            if (
                sample.name == "nks_wdc_security_events_total"
                and sample.labels.get("action") == action
            ):
                return float(sample.value)
    return 0.0


def test_increment_on_allowlisted_action():
    """Emitting a `login.failed` audit event bumps the counter."""
    from app.audit import emit
    from app.db import session_factory

    before = _get_counter("login.failed")
    with session_factory() as db:
        emit(
            db,
            request=None,
            actor=None,
            action="login.failed",
            resource_type="account",
            resource_id="1",
        )
        db.commit()
    after = _get_counter("login.failed")
    assert after == before + 1.0


def test_non_allowlisted_action_does_not_increment():
    """An arbitrary admin action (e.g. `app.updated`) must NOT move
    the counter — cardinality discipline."""
    from app.audit import emit
    from app.db import session_factory

    before = _get_counter("app.updated")
    with session_factory() as db:
        emit(
            db,
            request=None,
            actor=None,
            action="app.updated",
            resource_type="app",
            resource_id="x",
        )
        db.commit()
    after = _get_counter("app.updated")
    # Label never created → still zero.
    assert after == before == 0.0


def test_metrics_endpoint_exposes_counter(monkeypatch):
    """The /metrics endpoint emits the security counter in Prometheus
    text format after at least one increment."""
    from app.audit import emit
    from app.db import session_factory
    from fastapi.testclient import TestClient
    from app.main import app

    with session_factory() as db:
        emit(
            db,
            request=None,
            actor=None,
            action="permission.denied",
            resource_type="account",
            resource_id="1",
        )
        db.commit()

    with TestClient(app) as c:
        r = c.get("/metrics")
        assert r.status_code == 200
        assert "nks_wdc_security_events_total" in r.text
        assert 'action="permission.denied"' in r.text


def test_allowlist_covers_expected_actions():
    """Sanity — the allowlist contains the core security-significant
    action names so future refactors don't accidentally shrink it."""
    from app.observability import SECURITY_ACTION_ALLOWLIST

    required = {
        "login.failed",
        "totp.login_failed",
        "permission.denied",
        "password.change_failed",
        "user.tokens_revoked",
        "session.killed",
        "session.killed_others",
    }
    missing = required - SECURITY_ACTION_ALLOWLIST
    assert not missing, f"allowlist missing core actions: {missing}"
