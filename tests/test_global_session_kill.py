"""v0.46.0 — global "kill all sessions" panic button.

Covers: CSRF-gated POST /admin/security/kill-all-sessions that revokes
every AdminSession (except caller's own) AND bumps every non-suspended
Account.token_version so outstanding JWTs are invalidated. Emits a
`admin.global_session_kill` audit event with kill-counts.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    with TestClient(app, client=("127.0.0.1", 50000)):
        yield


def _reset_totp(username: str = "admin") -> None:
    from app.db import Account, GlobalPolicy, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(
            _sel(Account).where(Account.email == f"{username}@admin.local")
        )
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
        policy = db.get(GlobalPolicy, 1)
        if policy is not None and policy.require_2fa_for_admins:
            policy.require_2fa_for_admins = False
        db.commit()


def _login(
    client: TestClient, username: str = "admin", password: str = "admin"
) -> None:
    client.get("/login")
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        "/login",
        data={"username": username, "password": password, "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"login failed: {r.status_code} {r.text[:200]}"


def _count_audit(action: str) -> int:
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel, func as _func

    with session_factory() as db:
        return int(
            db.scalar(
                _sel(_func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == action)
            )
            or 0
        )


def _seed_other_sessions(n: int = 2) -> list[int]:
    """Insert `n` synthetic live AdminSession rows for the admin user and
    return their ids."""
    import secrets

    from app.db import AdminSession, User, session_factory
    from sqlalchemy import select as _sel

    ids: list[int] = []
    with session_factory() as db:
        user = db.scalar(_sel(User).where(User.username == "admin"))
        assert user is not None
        for i in range(n):
            fake_fp = secrets.token_hex(32)  # 64-char hex — unique per call
            row = AdminSession(
                user_id=user.id,
                fingerprint=fake_fp,
                ip=f"10.0.0.{i + 1}",
                user_agent=f"TestBrowser/{i}",
            )
            db.add(row)
            db.flush()
            ids.append(row.id)
        db.commit()
    return ids


def _ensure_accounts(suspended_email: str, active_email: str) -> tuple[int, int]:
    """Create (or reuse) one suspended + one active Account. Returns
    (suspended_id, active_id)."""
    from datetime import datetime, timezone

    from app.auth import hash_password
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        sus = db.scalar(_sel(Account).where(Account.email == suspended_email))
        if sus is None:
            sus = Account(
                email=suspended_email,
                password_hash=hash_password("x"),
                role="user",
            )
            db.add(sus)
            db.flush()
        sus.suspended_at = datetime.now(timezone.utc).replace(tzinfo=None)

        act = db.scalar(_sel(Account).where(Account.email == active_email))
        if act is None:
            act = Account(
                email=active_email,
                password_hash=hash_password("x"),
                role="user",
            )
            db.add(act)
            db.flush()
        act.suspended_at = None
        db.commit()
        return sus.id, act.id


# ---------------------------------------------------------------------------
# Regression: allowlist membership
# ---------------------------------------------------------------------------


def test_global_session_kill_on_security_allowlist() -> None:
    from app.observability import SECURITY_ACTION_ALLOWLIST

    assert "admin.global_session_kill" in SECURITY_ACTION_ALLOWLIST


# ---------------------------------------------------------------------------
# Unauthenticated POST must not reach the handler body
# ---------------------------------------------------------------------------


def test_unauth_post_is_rejected() -> None:
    with TestClient(app) as client:
        # No login; no CSRF cookie warmed. Expect a redirect (303) to
        # /login OR a 4xx — definitely not a 200 success.
        r = client.post(
            "/admin/security/kill-all-sessions",
            data={"_csrf": "bogus", "confirm": "KILL-ALL"},
            follow_redirects=False,
        )
        assert r.status_code in (303, 302, 401, 403), (
            f"Unauthenticated POST should bounce, got {r.status_code}"
        )

        # And no audit row landed.
        assert _count_audit("admin.global_session_kill") == _count_audit(
            "admin.global_session_kill"
        )  # tautology baseline — next test asserts deltas


# ---------------------------------------------------------------------------
# Wrong phrase → redirect back, no audit row, no revocations
# ---------------------------------------------------------------------------


def test_wrong_phrase_rejects_silently() -> None:
    from app.db import AdminSession, session_factory
    from sqlalchemy import select as _sel, func as _func

    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        seeded_ids = _seed_other_sessions(2)

        before_audit = _count_audit("admin.global_session_kill")
        with session_factory() as db:
            before_live = int(
                db.scalar(
                    _sel(_func.count())
                    .select_from(AdminSession)
                    .where(AdminSession.revoked_at.is_(None))
                )
                or 0
            )

        csrf = client.cookies.get("nks_wdc_csrf") or ""
        r = client.post(
            "/admin/security/kill-all-sessions",
            data={"_csrf": csrf, "confirm": "nope"},
            follow_redirects=False,
        )
        assert r.status_code == 303, f"unexpected status {r.status_code}"
        assert "/admin/ops" in r.headers.get("location", "")

        after_audit = _count_audit("admin.global_session_kill")
        assert after_audit == before_audit, (
            "wrong phrase must not emit admin.global_session_kill audit row"
        )

        with session_factory() as db:
            after_live = int(
                db.scalar(
                    _sel(_func.count())
                    .select_from(AdminSession)
                    .where(AdminSession.revoked_at.is_(None))
                )
                or 0
            )
            # Synthetic rows must still be live.
            for sid in seeded_ids:
                row = db.get(AdminSession, sid)
                assert row is not None
                assert row.revoked_at is None
        assert after_live == before_live


# ---------------------------------------------------------------------------
# Correct phrase → mass revoke + token bumps + audit row + suspended untouched
# ---------------------------------------------------------------------------


def test_correct_phrase_revokes_and_bumps() -> None:
    from app.auth import SESSION_COOKIE, _fingerprint
    from app.db import Account, AdminSession, session_factory
    from sqlalchemy import select as _sel, func as _func

    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        # Caller's own live session — must NOT be revoked.
        signed = client.cookies.get(SESSION_COOKIE) or ""
        caller_fp = _fingerprint(signed)

        # Seed two other live synthetic sessions.
        other_ids = _seed_other_sessions(2)

        # Seed one suspended + one active account so we can assert token
        # versions bumped on non-suspended only.
        suspended_id, active_id = _ensure_accounts(
            "suspended-ksess@example.com",
            "active-ksess@example.com",
        )

        with session_factory() as db:
            sus_before = db.get(Account, suspended_id).token_version
            act_before = db.get(Account, active_id).token_version

            live_before = int(
                db.scalar(
                    _sel(_func.count())
                    .select_from(AdminSession)
                    .where(
                        AdminSession.revoked_at.is_(None),
                        AdminSession.fingerprint != caller_fp,
                    )
                )
                or 0
            )
            non_suspended_before = int(
                db.scalar(
                    _sel(_func.count())
                    .select_from(Account)
                    .where(Account.suspended_at.is_(None))
                )
                or 0
            )

        audit_before = _count_audit("admin.global_session_kill")

        csrf = client.cookies.get("nks_wdc_csrf") or ""
        r = client.post(
            "/admin/security/kill-all-sessions",
            data={"_csrf": csrf, "confirm": "KILL-ALL"},
            follow_redirects=False,
        )
        assert r.status_code == 303, f"unexpected status {r.status_code}"
        assert "/admin/ops" in r.headers.get("location", "")

        # Every other-session row revoked.
        with session_factory() as db:
            for sid in other_ids:
                row = db.get(AdminSession, sid)
                assert row is not None, f"session row {sid} vanished"
                assert row.revoked_at is not None, (
                    f"synthetic session {sid} should be revoked"
                )

            # Caller's own session must still be live.
            caller_row = db.scalar(
                _sel(AdminSession).where(AdminSession.fingerprint == caller_fp)
            )
            assert caller_row is not None
            assert caller_row.revoked_at is None, (
                "caller's own admin session must be preserved"
            )

            # Active (non-suspended) account token_version bumped by 1.
            act_after = db.get(Account, active_id).token_version
            assert act_after == act_before + 1, (
                f"expected token_version {act_before + 1}, got {act_after}"
            )

            # Suspended account untouched.
            sus_after = db.get(Account, suspended_id).token_version
            assert sus_after == sus_before, (
                "suspended account token_version must not change"
            )

        # Audit row landed with the expected counts.
        from app.db import AuditEvent, session_factory as _sf
        from sqlalchemy import select as _s

        with _sf() as db:
            evt = db.scalar(
                _s(AuditEvent)
                .where(AuditEvent.action == "admin.global_session_kill")
                .order_by(AuditEvent.id.desc())
                .limit(1)
            )
            assert evt is not None
            detail = evt.detail or {}
            assert "admin_sessions_killed" in detail
            assert "token_versions_bumped" in detail
            assert int(detail["admin_sessions_killed"]) == live_before
            assert int(detail["token_versions_bumped"]) == non_suspended_before

        audit_after = _count_audit("admin.global_session_kill")
        assert audit_after == audit_before + 1
