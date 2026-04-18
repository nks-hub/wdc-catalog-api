"""Regression tests — PAT mint + revoke must emit audit events.

Without these, a compromised admin account could mint a long-lived
bearer token and leave zero trace in the audit log. Both the admin-UI
POST and the JSON API path are covered.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    """Login + reset any TOTP state so the session cookie lands clean."""
    with TestClient(app) as c:
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

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


def _latest_event(action: str):
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        return db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )


def test_admin_ui_create_emits_pat_created(admin_client: TestClient) -> None:
    admin_client.get("/admin/account")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/account/tokens",
        data={"_csrf": csrf, "name": "audit-test-pat", "ttl_days": "30"},
    )
    assert r.status_code == 200

    evt = _latest_event("pat.created")
    assert evt is not None
    assert evt.resource_type == "pat"
    assert evt.detail and evt.detail.get("name") == "audit-test-pat"
    assert (evt.detail or {}).get("prefix", "").startswith("nks_pat_")


def test_admin_ui_revoke_emits_pat_revoked(admin_client: TestClient) -> None:
    admin_client.get("/admin/account")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    # Mint one we'll revoke.
    admin_client.post(
        "/admin/account/tokens",
        data={"_csrf": csrf, "name": "doomed"},
    )

    # Find it in the DB so we can target by id.
    from app.db import Account, PersonalAccessToken, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        row = db.scalar(
            _sel(PersonalAccessToken)
            .where(PersonalAccessToken.account_id == acct.id)
            .where(PersonalAccessToken.name == "doomed")
            .order_by(PersonalAccessToken.id.desc())
        )
        assert row is not None
        token_id = row.id

    r = admin_client.post(
        f"/admin/account/tokens/{token_id}/revoke",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    evt = _latest_event("pat.revoked")
    assert evt is not None
    assert evt.resource_id == str(token_id)


def test_json_api_create_and_revoke_emits_events():
    """Exercise the /api/v1/auth/tokens JSON path — same audit coverage."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel
    from app.auth import hash_password
    from app.devices import create_token as _create_jwt

    # Make (or reuse) a regular account so we can mint a JWT for it.
    with session_factory() as db:
        acct = db.scalar(
            _sel(Account).where(Account.email == "pat-audit-json@example.com")
        )
        if acct is None:
            acct = Account(
                email="pat-audit-json@example.com",
                password_hash=hash_password("correct-horse-battery-staple"),
                role="user",
            )
            db.add(acct)
            db.commit()
            db.refresh(acct)
        account_id = acct.id
        token_version = acct.token_version

    # Issue a session JWT directly so we bypass the login-flow machinery.
    jwt_token = _create_jwt(
        account_id,
        "pat-audit-json@example.com",
        token_version=token_version,
    )
    auth_header = {"Authorization": f"Bearer {jwt_token}"}

    with TestClient(app) as c:
        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "ci-pipeline", "ttl_days": 14},
            headers=auth_header,
        )
        assert r.status_code == 201, r.text
        pat_id = r.json()["id"]

        evt = _latest_event("pat.created")
        assert evt is not None and evt.resource_id == str(pat_id)

        r2 = c.delete(f"/api/v1/auth/tokens/{pat_id}", headers=auth_header)
        assert r2.status_code == 204
        evt2 = _latest_event("pat.revoked")
        assert evt2 is not None and evt2.resource_id == str(pat_id)
