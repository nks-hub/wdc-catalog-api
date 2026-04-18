"""Tests for /admin/invites/history CSV export and email/date filters."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app


def _set_2fa_required(value: bool) -> None:
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


@pytest.fixture()
def admin_client() -> TestClient:
    """Authenticated admin client with TOTP + 2FA gate reset."""
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


def _seed_invite(email: str, consumed_at: datetime) -> str:
    """Insert a ConsumedInvite row and return its nonce."""
    from app.db import ConsumedInvite, session_factory

    nonce = uuid.uuid4().hex
    with session_factory() as db:
        row = ConsumedInvite(nonce=nonce, email=email, consumed_at=consumed_at)
        db.add(row)
        db.commit()
    return nonce


def _cleanup_nonces(*nonces: str) -> None:
    from app.db import ConsumedInvite, session_factory

    with session_factory() as db:
        for nonce in nonces:
            row = db.get(ConsumedInvite, nonce)
            if row is not None:
                db.delete(row)
        db.commit()


def test_csv_endpoint_returns_all_rows(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    n1 = _seed_invite("alpha@test.com", now - timedelta(hours=3))
    n2 = _seed_invite("beta@test.com", now - timedelta(hours=2))
    n3 = _seed_invite("gamma@test.com", now - timedelta(hours=1))
    try:
        r = admin_client.get("/admin/invites/history.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        # Header + at least 3 data rows (other tests may have seeded rows too)
        assert lines[0] == "email,consumed_at,account_id,nonce"
        emails_in_csv = [ln.split(",")[0] for ln in lines[1:]]
        assert "alpha@test.com" in emails_in_csv
        assert "beta@test.com" in emails_in_csv
        assert "gamma@test.com" in emails_in_csv
    finally:
        _cleanup_nonces(n1, n2, n3)


def test_csv_filters_by_email_substring(admin_client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    n_alice = _seed_invite("alice@ex.com", now - timedelta(hours=2))
    n_bob = _seed_invite("bob@ex.com", now - timedelta(hours=1))
    try:
        r = admin_client.get("/admin/invites/history.csv?email=alice")
        assert r.status_code == 200
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        data_lines = lines[1:]  # skip header
        assert any("alice@ex.com" in ln for ln in data_lines)
        assert not any("bob@ex.com" in ln for ln in data_lines)
    finally:
        _cleanup_nonces(n_alice, n_bob)


def test_html_page_filters_by_date_range(admin_client: TestClient) -> None:
    early = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc)
    n_early = _seed_invite("early@range.com", early)
    n_late = _seed_invite("late@range.com", late)
    try:
        r = admin_client.get("/admin/invites/history?since=2026-04-12")
        assert r.status_code == 200
        assert "late@range.com" in r.text
        assert "early@range.com" not in r.text
    finally:
        _cleanup_nonces(n_early, n_late)


def test_csv_rejects_unauthenticated() -> None:
    with TestClient(app) as c:
        r = c.get("/admin/invites/history.csv", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers.get("location", "")
