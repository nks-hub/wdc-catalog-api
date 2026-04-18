"""Tests for the /admin/accounts/locked aggregate view.

Covers the v0.45.0 admin drill-down that lists accounts currently
inside a timed lockout window or at/above the 5-fails threshold, plus
the one-click unlock form that round-trips the caller back via the
``next`` form field on ``/admin/users/{id}/unlock``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    with TestClient(app, client=("127.0.0.1", 50000)):
        yield


def _admin_client() -> TestClient:
    """Log the bootstrap admin in and return a session-cookied client."""
    c = TestClient(app, client=("127.0.0.1", 50000))
    c.get("/login")
    csrf = c.cookies.get("nks_wdc_csrf") or ""
    r = c.post(
        "/login",
        data={"username": "admin", "password": "admin", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, (
        f"bootstrap login failed: {r.status_code} {r.text[:200]}"
    )
    return c


def _clear_locked_accounts() -> None:
    """Unlock every account so the list view starts empty."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        for acct in db.scalars(_sel(Account)).all():
            acct.failed_login_count = 0
            acct.locked_until = None
        db.commit()


def _make_locked_account(email: str, *, lock_minutes: int = 30) -> int:
    """Insert-or-update an Account with locked_until in the future."""
    from app.auth import hash_password
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        existing = db.scalar(_sel(Account).where(Account.email == email))
        if existing is None:
            existing = Account(
                email=email,
                password_hash=hash_password("correct-horse"),
                role="user",
            )
            db.add(existing)
            db.flush()
        existing.locked_until = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(minutes=lock_minutes)
        )
        existing.failed_login_count = 5
        db.commit()
        return existing.id


def _make_threshold_account(email: str) -> int:
    """Account at the 5-fails threshold but with no active timed lock."""
    from app.auth import hash_password
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        existing = db.scalar(_sel(Account).where(Account.email == email))
        if existing is None:
            existing = Account(
                email=email,
                password_hash=hash_password("correct-horse"),
                role="user",
            )
            db.add(existing)
            db.flush()
        existing.locked_until = None
        existing.failed_login_count = 5
        db.commit()
        return existing.id


def test_unauthenticated_redirects_to_login():
    """No session cookie → session-auth middleware bounces to /login."""
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/admin/accounts/locked", follow_redirects=False)
    assert r.status_code in (302, 303), r.text
    assert r.headers["location"].startswith("/login")


def test_empty_state_renders_when_no_locked_accounts():
    _clear_locked_accounts()
    c = _admin_client()
    try:
        r = c.get("/admin/accounts/locked")
    finally:
        c.close()
    assert r.status_code == 200, r.text
    assert "Locked accounts" in r.text
    assert "No accounts currently locked" in r.text


def test_locked_account_visible_in_list():
    _clear_locked_accounts()
    email = "locked-view-timed@example.com"
    _make_locked_account(email)

    c = _admin_client()
    try:
        r = c.get("/admin/accounts/locked")
    finally:
        c.close()
    assert r.status_code == 200, r.text
    assert email in r.text
    # The per-row unlock form carries the round-trip `next` pointer.
    assert 'name="next" value="/admin/accounts/locked"' in r.text


def test_threshold_account_visible_even_without_timed_lock():
    """An account at failed_login_count >= 5 with locked_until=NULL is
    still a victim-axis signal and must surface in the aggregate view."""
    _clear_locked_accounts()
    email = "locked-view-threshold@example.com"
    _make_threshold_account(email)

    c = _admin_client()
    try:
        r = c.get("/admin/accounts/locked")
    finally:
        c.close()
    assert r.status_code == 200, r.text
    assert email in r.text


def test_unlock_with_next_redirects_back_to_locked_view():
    """POST /admin/users/{id}/unlock with next=/admin/accounts/locked
    must 303 back to the aggregate page and clear the lockout."""
    from app.db import Account, session_factory

    _clear_locked_accounts()
    email = "unlock-roundtrip@example.com"
    acct_id = _make_locked_account(email)

    c = _admin_client()
    try:
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            f"/admin/users/{acct_id}/unlock",
            data={"_csrf": csrf, "next": "/admin/accounts/locked"},
            follow_redirects=False,
        )
    finally:
        c.close()
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/admin/accounts/locked"

    with session_factory() as db:
        acct = db.get(Account, acct_id)
        assert acct is not None
        assert acct.locked_until is None
        assert (acct.failed_login_count or 0) == 0


def test_unlock_with_unsafe_next_falls_back_to_user_detail():
    """Open-redirect guard — only /admin/-prefixed `next` values are
    honored. Arbitrary external targets must route to the default."""
    _clear_locked_accounts()
    email = "unlock-open-redirect@example.com"
    acct_id = _make_locked_account(email)

    c = _admin_client()
    try:
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            f"/admin/users/{acct_id}/unlock",
            data={"_csrf": csrf, "next": "https://evil.example.com/"},
            follow_redirects=False,
        )
    finally:
        c.close()
    assert r.status_code == 303, r.text
    assert r.headers["location"] == f"/admin/users/{acct_id}"


def test_user_unlocked_on_security_allowlist():
    """Regression — the v0.45.0 addition stays on the Prometheus
    security-events allowlist alongside the rest of the user-lifecycle
    audit actions."""
    from app.observability import SECURITY_ACTION_ALLOWLIST

    assert "user.unlocked" in SECURITY_ACTION_ALLOWLIST
