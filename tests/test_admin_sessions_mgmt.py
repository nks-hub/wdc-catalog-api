"""Task 1 tests: AdminSession table + fingerprint tracking in current_user."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _reset_totp(username: str = "admin") -> None:
    """Disable TOTP for the admin account (call INSIDE a live TestClient ctx)."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == f"{username}@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def _login(client: TestClient, username: str = "admin", password: str = "admin") -> None:
    """Drive the login form; asserts 303 redirect to /admin."""
    client.get("/login")
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        "/login",
        data={"username": username, "password": password, "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"login failed: {r.status_code} {r.text[:200]}"


# ---------------------------------------------------------------------------
# Test 1: login writes an AdminSession row
# ---------------------------------------------------------------------------


def test_login_writes_session_row() -> None:
    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    with TestClient(app) as client:
        # create_all has now run; safe to touch DB
        _reset_totp()

        # Ensure no stale session rows for admin.
        with session_factory() as db:
            user = db.scalar(_sel(User).where(User.username == "admin"))
            if user is not None:
                for row in db.scalars(
                    _sel(AdminSession).where(AdminSession.user_id == user.id)
                ).all():
                    db.delete(row)
                db.commit()

        _login(client)

        with session_factory() as db:
            user = db.scalar(_sel(User).where(User.username == "admin"))
            assert user is not None
            rows = db.scalars(
                _sel(AdminSession).where(AdminSession.user_id == user.id)
            ).all()

        assert len(rows) >= 1, "Expected at least one AdminSession row after login"
        row = rows[0]
        assert row.user_id == user.id
        assert row.fingerprint and len(row.fingerprint) == 64
        assert row.revoked_at is None


# ---------------------------------------------------------------------------
# Test 2: revoked session bounces back to /login
# ---------------------------------------------------------------------------


def test_revoked_session_bounces_to_login() -> None:
    from datetime import datetime, timezone

    from app.auth import SESSION_COOKIE, _fingerprint
    from app.db import AdminSession, session_factory
    from sqlalchemy import select as _sel

    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        signed = client.cookies.get(SESSION_COOKIE) or ""
        fp = _fingerprint(signed)

        with session_factory() as db:
            row = db.scalar(_sel(AdminSession).where(AdminSession.fingerprint == fp))
            assert row is not None, "No session row found for the active cookie"
            row.revoked_at = datetime.now(timezone.utc)
            db.commit()

        # Next admin request must redirect to /login.
        r = client.get("/admin", follow_redirects=False)
        assert r.status_code in (302, 303), (
            f"Expected redirect after revocation, got {r.status_code}"
        )
        assert "/login" in r.headers.get("location", "")


# ---------------------------------------------------------------------------
# Test 3: legacy signed cookie (no DB row) still grants access + row created
# ---------------------------------------------------------------------------


def test_legacy_sessions_without_row_still_work() -> None:
    from app.auth import SESSION_COOKIE, _fingerprint, _signer
    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    with TestClient(app) as client:
        # App is up; make sure admin account exists by visiting /admin/account
        # via a normal login first to provision the paired Account row.
        _reset_totp()
        _login(client)
        client.get("/admin/account")  # provisions paired Account row

        # Craft a signed cookie exactly as issue_session does, but skip DB write.
        signed = _signer.sign(b"admin").decode("ascii")
        fp = _fingerprint(signed)

        # Ensure no row exists for this fingerprint.
        with session_factory() as db:
            existing = db.scalar(_sel(AdminSession).where(AdminSession.fingerprint == fp))
            if existing is not None:
                db.delete(existing)
                db.commit()

    # Start a fresh TestClient so we have a clean cookie jar.
    with TestClient(app) as client2:
        client2.cookies.set(SESSION_COOKIE, signed)

        r = client2.get("/admin", follow_redirects=False)
        assert r.status_code == 200, (
            f"Legacy session should still work, got {r.status_code}"
        )

        # After the request, current_user should have lazily created a row.
        with session_factory() as db:
            row = db.scalar(_sel(AdminSession).where(AdminSession.fingerprint == fp))
            user = db.scalar(_sel(User).where(User.username == "admin"))

        assert row is not None, "current_user should have written a legacy session row"
        assert user is not None
        assert row.user_id == user.id
