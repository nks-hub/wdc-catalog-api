"""Audit free-text search via `?q=<substring>`.

Extends `_audit_filter_stmt` with an ILIKE across action, resource_id,
actor_email, and JSON-cast detail — useful when the structured filter
form can't pinpoint "which row triggered this thing" during an incident.
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


def _seed(
    action: str,
    *,
    resource_id: str | None = None,
    actor_email: str | None = None,
    detail: dict | None = None,
) -> None:
    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        db.add(
            AuditEvent(
                action=action,
                resource_type="test",
                resource_id=resource_id,
                actor_email=actor_email,
                detail=detail,
            )
        )
        db.commit()


def test_q_matches_action_substring(admin_client: TestClient) -> None:
    _seed("test.freetext.abcxyz123")
    r = admin_client.get("/admin/audit?q=abcxyz123")
    assert r.status_code == 200
    assert "test.freetext.abcxyz123" in r.text


def test_q_matches_actor_email_substring(admin_client: TestClient) -> None:
    unique_email = "needle-ft@example.com"
    _seed("test.freetext.email", actor_email=unique_email)
    r = admin_client.get("/admin/audit?q=needle-ft")
    assert r.status_code == 200
    assert unique_email in r.text


def test_q_matches_resource_id_substring(admin_client: TestClient) -> None:
    _seed("test.freetext.resource", resource_id="res-unique-id-9988")
    r = admin_client.get("/admin/audit?q=unique-id-9988")
    assert r.status_code == 200
    assert "res-unique-id-9988" in r.text


def test_q_matches_detail_json_substring(admin_client: TestClient) -> None:
    _seed("test.freetext.detail", detail={"reason": "magic-cookie-xyz-777"})
    r = admin_client.get("/admin/audit?q=magic-cookie-xyz-777")
    assert r.status_code == 200
    assert "magic-cookie-xyz-777" in r.text


def test_q_combined_with_action_filter(admin_client: TestClient) -> None:
    """q + structured filter AND together — matches must satisfy both."""
    _seed("test.filter.one", resource_id="shared-xyz")
    _seed("test.filter.two", resource_id="shared-xyz")

    # Structured filter on action=test.filter.one AND q=shared-xyz → 1 hit.
    r = admin_client.get("/admin/audit?action=test.filter.one&q=shared-xyz")
    assert r.status_code == 200
    assert "test.filter.one" in r.text
    # test.filter.two would match q but fail structured filter — so it
    # should NOT appear.
    assert "test.filter.two" not in r.text
