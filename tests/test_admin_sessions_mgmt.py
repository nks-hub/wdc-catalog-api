"""Task 1 tests: AdminSession table + fingerprint tracking in current_user."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _reset_totp(username: str = "admin") -> None:
    """Disable TOTP for the admin account AND clear the global-enforcement
    flag (call INSIDE a live TestClient ctx).

    Test-order hazard: ``test_2fa_enforcement.py`` may leave
    ``GlobalPolicy.require_2fa_for_admins=True`` if a prior test fails
    before teardown. With the flag still on + TOTP disabled, every
    admin-router request bounces to ``/admin/account?flash=totp-required``
    — including the ``kill-others`` POST that a downstream test asserts
    actually ran. The redirect satisfies the ``in (302, 303)`` status
    check but the SQL UPDATE never fires, leaving synthetic rows alive
    and failing the ``revoked_at is not None`` assertion.

    Resetting both pieces here gives every test in this file a clean
    "plain admin / no 2FA policy" starting state regardless of who ran
    before.
    """
    from app.db import Account, GlobalPolicy, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == f"{username}@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
        policy = db.get(GlobalPolicy, 1)
        if policy is not None and policy.require_2fa_for_admins:
            policy.require_2fa_for_admins = False
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
# Shared DB helper
# ---------------------------------------------------------------------------


def _clear_sessions(username: str = "admin") -> None:
    """Delete all AdminSession rows for the given username."""
    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        user = db.scalar(_sel(User).where(User.username == username))
        if user is not None:
            for row in db.scalars(
                _sel(AdminSession).where(AdminSession.user_id == user.id)
            ).all():
                db.delete(row)
            db.commit()


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


# ---------------------------------------------------------------------------
# Test 4: account page lists the current session with "this browser" pill
# ---------------------------------------------------------------------------


def test_sessions_page_lists_current() -> None:
    with TestClient(app) as client:
        _reset_totp()
        _clear_sessions()
        _login(client)

        r = client.get("/admin/account", follow_redirects=True)
        assert r.status_code == 200
        assert "Active sessions" in r.text
        assert "this browser" in r.text


# ---------------------------------------------------------------------------
# Test 5: killing another session bounces that browser to /login
# ---------------------------------------------------------------------------


def test_kill_other_session() -> None:
    from app.auth import SESSION_COOKIE, _fingerprint
    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    with TestClient(app) as client_a, TestClient(app) as client_b:
        _reset_totp()
        _clear_sessions()

        # Login client A — creates real session row.
        _login(client_a)
        signed_a = client_a.cookies.get(SESSION_COOKIE) or ""
        fp_a = _fingerprint(signed_a)

        # Login client B — same fingerprint (same admin/admin cookie), so
        # the idempotent path is hit and NO new row is created. To simulate
        # a distinct browser, we insert a synthetic session row for B.
        _login(client_b)

        with session_factory() as db:
            user = db.scalar(_sel(User).where(User.username == "admin"))
            assert user is not None
            # Insert a synthetic session row that mimics client B's "other browser".
            fake_fp = "b" * 64  # distinct from client A's real fingerprint
            existing_b = db.scalar(
                _sel(AdminSession).where(AdminSession.fingerprint == fake_fp)
            )
            if existing_b is None:
                b_row = AdminSession(
                    user_id=user.id,
                    fingerprint=fake_fp,
                    ip="127.0.0.2",
                    user_agent="TestBrowser/B",
                )
                db.add(b_row)
                db.commit()
                b_id = b_row.id
            else:
                existing_b.revoked_at = None
                db.commit()
                b_id = existing_b.id

        # Fetch CSRF from client A then kill B's session.
        client_a.get("/admin/account")
        csrf = client_a.cookies.get("nks_wdc_csrf") or ""
        r = client_a.post(
            f"/admin/account/sessions/{b_id}/kill",
            data={"_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code in (302, 303), f"kill returned {r.status_code}"

        # B's row must now be revoked.
        with session_factory() as db:
            b_row = db.get(AdminSession, b_id)
            assert b_row is not None
            assert b_row.revoked_at is not None, "B's session should be revoked"

        # If client_b still holds the synthetic fingerprint in its cookie,
        # its next request would bounce — but TestClient's real cookie is
        # the same signed admin cookie (fp_a), which is still live. The
        # meaningful check is the DB state above. We verify the raw DB
        # revocation guarantees the UI path by also confirming A is unaffected.
        with session_factory() as db:
            a_row = db.scalar(
                _sel(AdminSession).where(AdminSession.fingerprint == fp_a)
            )
            assert a_row is not None
            assert a_row.revoked_at is None, "A's session should still be active"


# ---------------------------------------------------------------------------
# Test 6: kill-others revokes synthetic sessions, preserves the caller's
# ---------------------------------------------------------------------------


def test_kill_others_preserves_current() -> None:
    """Pre-insert 3 AdminSession rows (1 real + 2 synthetic), call
    kill-others from the real session, verify only the synthetic ones
    get revoked_at set.

    Rationale: admin/admin always signs to the same cookie within one
    pytest process (same ephemeral key), so three TestClient logins
    produce ONE AdminSession row. We therefore insert 2 extra rows with
    distinct fingerprints directly into the DB to simulate two other
    active browsers.
    """
    from app.auth import SESSION_COOKIE, _fingerprint
    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    with TestClient(app) as client:
        _reset_totp()
        _clear_sessions()
        _login(client)

        signed = client.cookies.get(SESSION_COOKIE) or ""
        real_fp = _fingerprint(signed)

        # Ensure the real session row exists (login wrote it).
        with session_factory() as db:
            user = db.scalar(_sel(User).where(User.username == "admin"))
            assert user is not None

            real_row = db.scalar(
                _sel(AdminSession).where(AdminSession.fingerprint == real_fp)
            )
            assert real_row is not None

            # Insert two synthetic "other browser" rows.
            synthetic_fps = ["c" * 64, "d" * 64]
            synthetic_ids = []
            for sfp in synthetic_fps:
                existing = db.scalar(
                    _sel(AdminSession).where(AdminSession.fingerprint == sfp)
                )
                if existing is None:
                    s_row = AdminSession(
                        user_id=user.id,
                        fingerprint=sfp,
                        ip="127.0.0.3",
                        user_agent="SyntheticBrowser",
                    )
                    db.add(s_row)
                    db.flush()
                    synthetic_ids.append(s_row.id)
                else:
                    existing.revoked_at = None
                    db.flush()
                    synthetic_ids.append(existing.id)
            db.commit()

        # POST kill-others from the real client session.
        client.get("/admin/account")
        csrf = client.cookies.get("nks_wdc_csrf") or ""
        r = client.post(
            "/admin/account/sessions/kill-others",
            data={"_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code in (302, 303), f"kill-others returned {r.status_code}"

        # The real session must still be active.
        with session_factory() as db:
            real_row = db.scalar(
                _sel(AdminSession).where(AdminSession.fingerprint == real_fp)
            )
            assert real_row is not None
            assert real_row.revoked_at is None, "Caller's own session must not be revoked"

            # Both synthetic rows must now be revoked.
            for sid in synthetic_ids:
                s = db.get(AdminSession, sid)
                assert s is not None
                assert s.revoked_at is not None, f"Synthetic session {sid} should be revoked"
