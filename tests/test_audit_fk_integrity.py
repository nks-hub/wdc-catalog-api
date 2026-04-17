"""Audit records must survive account deletion.

SQLite silently ignores ``ondelete='SET NULL'`` unless
``PRAGMA foreign_keys=ON`` runs on every connection. Regression test that
the pragma actually takes effect: deleting an account must null out
``audit_events.actor_id`` while preserving ``actor_email`` so the
history stays meaningful during compliance audits.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import audit
from app.db import Account, AuditEvent, session_factory
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_audit_event_survives_account_delete(client: TestClient) -> None:
    # Ensure the app + DB are wired up.
    assert client.get("/healthz").status_code == 200

    with session_factory() as db:
        account = Account(
            email="audit-fk-target@example.com",
            password_hash="x" * 64,
            role="user",
        )
        db.add(account)
        db.flush()
        audit.emit(
            db,
            actor=account,
            action="test.fk_survival",
            resource_type="test",
            resource_id="1",
        )
        db.commit()

        # Delete the account — SET NULL must fire on audit_events.actor_id.
        db.delete(account)
        db.commit()

        row = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "test.fk_survival")
        )
        assert row is not None, "audit row was cascaded away"
        assert row.actor_id is None, "actor_id should be nulled by FK"
        assert row.actor_email == "audit-fk-target@example.com", (
            "actor_email must survive — it's the only identifier left after delete"
        )
