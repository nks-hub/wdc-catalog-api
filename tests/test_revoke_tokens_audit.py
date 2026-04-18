"""Regression test — `/admin/users/{id}/revoke-tokens` must audit.

Mass JWT revocation is a security-critical admin action; before
v0.36.0 it silently bumped `Account.token_version` without leaving
a trace in the audit log.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    with TestClient(app) as c:
        from app.db import Account, GlobalPolicy, session_factory
        from sqlalchemy import select as _sel

        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                acct.totp_enabled = False
                acct.totp_secret = None
                acct.totp_recovery_hashes = None
                acct.totp_enabled_at = None
            policy = db.get(GlobalPolicy, 1)
            if policy is not None:
                policy.require_2fa_for_admins = False
                policy.admin_ip_allowlist = None
            db.commit()

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


def test_revoke_tokens_emits_audit_event(admin_client: TestClient) -> None:
    """Mass-revoke path must leave a trail."""
    from app.db import Account, AuditEvent, session_factory
    from app.auth import hash_password
    from sqlalchemy import select as _sel

    with session_factory() as db:
        target = db.scalar(
            _sel(Account).where(Account.email == "revoke-target@example.com")
        )
        if target is None:
            target = Account(
                email="revoke-target@example.com",
                password_hash=hash_password("unused"),
                role="user",
                token_version=1,
            )
            db.add(target)
            db.commit()
            db.refresh(target)
        tid = target.id
        prev_tv = target.token_version

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        f"/admin/users/{tid}/revoke-tokens",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    # token_version bumped by exactly 1.
    with session_factory() as db:
        fresh = db.get(Account, tid)
        assert fresh.token_version == prev_tv + 1

    # Audit row exists with the expected detail.
    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "user.tokens_revoked")
            .where(AuditEvent.resource_id == str(tid))
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert evt.resource_type == "account"
    assert (evt.detail or {}).get("target_email") == "revoke-target@example.com"
    assert (evt.detail or {}).get("token_version_before") == prev_tv
    assert (evt.detail or {}).get("token_version_after") == prev_tv + 1


def test_revoke_tokens_404_does_not_audit(admin_client: TestClient) -> None:
    """Missing user → 404, no audit row written."""
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel, func

    with session_factory() as db:
        before_count = (
            db.scalar(
                _sel(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "user.tokens_revoked")
            )
            or 0
        )

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/users/9999999/revoke-tokens",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 404

    with session_factory() as db:
        after_count = (
            db.scalar(
                _sel(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "user.tokens_revoked")
            )
            or 0
        )
    assert after_count == before_count
