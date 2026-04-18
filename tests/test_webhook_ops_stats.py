"""Tests for webhook delivery stats on /admin/ops."""

from __future__ import annotations


import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, WebhookDelivery, session_factory
from app.main import app


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


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


def _set_2fa_required(value: bool) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _clear_deliveries() -> None:
    from sqlalchemy import delete

    with session_factory() as db:
        db.execute(delete(WebhookDelivery))
        db.commit()


def _seed_deliveries(ok: int = 0, failed: int = 0) -> None:
    with session_factory() as db:
        for _ in range(ok):
            db.add(WebhookDelivery(
                url="http://h/hook",
                event_action="test",
                status_code=204,
                duration_ms=5,
                error=None,
            ))
        for _ in range(failed):
            db.add(WebhookDelivery(
                url="http://h/hook",
                event_action="test",
                status_code=500,
                duration_ms=5,
                error="timeout",
            ))
        db.commit()


@pytest.fixture()
def admin_client() -> TestClient:
    """Authenticated admin client with TOTP + 2FA gate reset."""
    _clear_deliveries()
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

    _clear_deliveries()


def test_ops_page_no_webhook_deliveries_hides_sparkline(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert "Sent · 24h" in r.text
    assert "deliveries/hour" not in r.text


def test_ops_page_shows_24h_counts(admin_client: TestClient) -> None:
    _seed_deliveries(ok=3, failed=2)
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    body = r.text
    # ok count appears next to the Sent label
    assert "Sent · 24h" in body
    # The rendered ok count should be 3 — check it appears after the label
    sent_idx = body.index("Sent · 24h")
    assert "3" in body[sent_idx:sent_idx + 80]
    # Failed pill
    assert 'pill pill-suspended">2' in body


def test_ops_page_renders_sparkline_when_non_zero(admin_client: TestClient) -> None:
    _seed_deliveries(ok=1)
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert "deliveries/hour" in r.text
