"""Regression tests — registration + JSON login must audit.

Before v0.8.3, `/api/v1/auth/register` and `/api/v1/auth/login` left no
audit trail. Compliance + incident response both need them.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def _latest(action: str):
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        return db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )


def test_register_emits_account_registered() -> None:
    with TestClient(app) as c:
        r = c.post(
            "/api/v1/auth/register",
            json={
                "email": "audit-register@example.com",
                "password": "correct-horse-battery-staple",
            },
        )
        # Either 200 (fresh) or 409 (already registered from a prior run).
        if r.status_code == 409:
            return

        assert r.status_code == 200, r.text
        evt = _latest("account.registered")
        assert evt is not None
        assert (evt.detail or {}).get("email") == "audit-register@example.com"


def test_login_success_emits_login_ok() -> None:
    email = "audit-login@example.com"
    password = "correct-horse-battery-staple"

    with TestClient(app) as c:
        # Ensure the account exists (idempotent).
        c.post(
            "/api/v1/auth/register",
            json={"email": email, "password": password},
        )

        r = c.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert r.status_code == 200, r.text
        evt = _latest("login.ok")
        assert evt is not None
        # resource_id is the account id; actor_id matches.
        assert evt.actor_id == int(evt.resource_id)
