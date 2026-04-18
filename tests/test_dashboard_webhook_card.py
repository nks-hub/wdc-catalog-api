"""Tests for the dashboard 24h webhook health stat-card."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, WebhookDelivery, session_factory
from app.main import app


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _set_2fa_required(value: bool) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from sqlalchemy import select as _sel

    from app.db import Account

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def _clear_webhook_deliveries() -> None:
    from sqlalchemy import delete

    with session_factory() as db:
        db.execute(delete(WebhookDelivery))
        db.commit()


def _seed_deliveries(ok: int, failed: int) -> None:
    with session_factory() as db:
        for _ in range(ok):
            db.add(
                WebhookDelivery(
                    url="http://h/hook",
                    event_action="test",
                    status_code=204,
                    duration_ms=5,
                    error=None,
                )
            )
        for _ in range(failed):
            db.add(
                WebhookDelivery(
                    url="http://h/hook",
                    event_action="test",
                    status_code=500,
                    duration_ms=20,
                    error="HTTP 500",
                )
            )
        db.commit()


@pytest.fixture()
def admin_client() -> TestClient:
    """Authenticated admin client with TOTP + 2FA gate reset."""
    _clear_webhook_deliveries()
    with TestClient(app) as c:
        _reset_totp()
        _set_2fa_required(False)

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        c.get("/admin/account")

        yield c

        _set_2fa_required(False)
        _reset_totp()
        _clear_webhook_deliveries()


def test_dashboard_no_deliveries_shows_empty_state(admin_client: TestClient) -> None:
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "Webhooks \u00b7 24h" in r.text
    assert "No deliveries in last 24h" in r.text
    assert "Triage failed" not in r.text


def test_dashboard_shows_sent_and_failed_counts(admin_client: TestClient) -> None:
    import re
    _seed_deliveries(ok=7, failed=2)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    # Sent count appears inside the webhook card under a `Sent` label.
    # The surrounding markup grew a KPI delta chip in v0.37.0 so the
    # old tight `>Sent</span><b>7</b>` assertion breaks — tolerate
    # whitespace + a possible delta span between the label and the
    # count by matching on the label followed by the count within
    # a short character window.
    assert re.search(r">Sent</span>\s*<b>\s*7\b", r.text) is not None
    assert "22.2%" in r.text


def test_dashboard_triage_link_only_when_failures(admin_client: TestClient) -> None:
    _seed_deliveries(ok=3, failed=0)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "status_filter=failed" not in r.text

    _seed_deliveries(ok=0, failed=1)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "/admin/ops/webhooks?status_filter=failed" in r.text
