"""Regression test — `/api/v1/auth/login` against a locked account
must emit `login.locked_out` audit event before 423'ing.

Distinct signal from `login.failed` (bad password attempt) — lockout
means someone's pounding on a known-locked door, which is worth a
separate Prometheus series for alerting.
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


def _create_locked_account(email: str, lock_minutes: int = 30):
    """Insert an Account with locked_until set in the future."""
    from app.db import Account, session_factory
    from app.auth import hash_password
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


def test_locked_account_login_emits_locked_out_audit_event():
    email = "lockout-test@example.com"
    acct_id = _create_locked_account(email)

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "correct-horse"},
        )
        assert r.status_code == 423, r.text

    # Audit row landed.
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "login.locked_out")
            .where(AuditEvent.resource_id == str(acct_id))
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert evt.resource_type == "account"
    assert (evt.detail or {}).get("email") == email
    # locked_until timestamp round-trips in ISO.
    assert "locked_until" in (evt.detail or {})


def test_unlocked_account_does_not_emit_locked_out():
    """Sanity — a normal bad-password attempt stays `login.failed`
    territory; no `login.locked_out` spam for non-locked accounts."""
    from app.db import Account, AuditEvent, session_factory
    from app.auth import hash_password
    from sqlalchemy import select as _sel, func as _func

    email = "unlocked-test@example.com"
    with session_factory() as db:
        existing = db.scalar(_sel(Account).where(Account.email == email))
        if existing is None:
            existing = Account(
                email=email,
                password_hash=hash_password("correct-horse"),
                role="user",
            )
            db.add(existing)
        # Explicitly unlock.
        existing.locked_until = None
        existing.failed_login_count = 0
        db.commit()

    with session_factory() as db:
        before = int(
            db.scalar(
                _sel(_func.count()).select_from(AuditEvent).where(
                    AuditEvent.action == "login.locked_out"
                )
            ) or 0
        )

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong-password"},
        )
        assert r.status_code == 401  # plain failed, not locked

    with session_factory() as db:
        after = int(
            db.scalar(
                _sel(_func.count()).select_from(AuditEvent).where(
                    AuditEvent.action == "login.locked_out"
                )
            ) or 0
        )
    assert after == before


def test_locked_out_on_security_allowlist():
    """Sanity — the new action is on the metric allowlist so it rides
    the v0.41.0 Prometheus counter automatically."""
    from app.observability import SECURITY_ACTION_ALLOWLIST
    assert "login.locked_out" in SECURITY_ACTION_ALLOWLIST


def test_lockout_armed_audit_event_on_threshold_hit():
    """v0.44.0 — the transition moment (threshold fires, lockout arms)
    deserves its own audit row so ops can alert on *new* lockouts,
    not just repeated bounces against already-locked accounts."""
    from app.db import Account, AuditEvent, session_factory
    from app.auth import hash_password
    from sqlalchemy import select as _sel

    email = "lockout-arming@example.com"
    with session_factory() as db:
        existing = db.scalar(_sel(Account).where(Account.email == email))
        if existing is None:
            existing = Account(
                email=email,
                password_hash=hash_password("correct-horse"),
                role="user",
            )
            db.add(existing)
        existing.locked_until = None
        existing.failed_login_count = 4  # one below the 5-fails threshold
        db.commit()
        acct_id = existing.id

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong-password"},
        )
        assert r.status_code == 401  # plain failed, but lockout armed

    from app.db import session_factory as _sf
    with _sf() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "login.lockout_armed")
            .where(AuditEvent.resource_id == str(acct_id))
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert evt.resource_type == "account"
    assert (evt.detail or {}).get("email") == email
    assert (evt.detail or {}).get("lock_minutes") == 1
    assert (evt.detail or {}).get("failed_login_count") == 5


def test_no_lockout_armed_below_threshold():
    """Sanity — bad-password attempts below the 5-fails threshold must
    NOT emit login.lockout_armed. Only the transition moment counts."""
    from app.db import Account, AuditEvent, session_factory
    from app.auth import hash_password
    from sqlalchemy import select as _sel, func as _func

    email = "below-threshold@example.com"
    with session_factory() as db:
        existing = db.scalar(_sel(Account).where(Account.email == email))
        if existing is None:
            existing = Account(
                email=email,
                password_hash=hash_password("correct-horse"),
                role="user",
            )
            db.add(existing)
        existing.locked_until = None
        existing.failed_login_count = 0  # well below threshold
        db.commit()

    with session_factory() as db:
        before = int(
            db.scalar(
                _sel(_func.count()).select_from(AuditEvent).where(
                    AuditEvent.action == "login.lockout_armed"
                )
            ) or 0
        )

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong-password"},
        )
        assert r.status_code == 401

    with session_factory() as db:
        after = int(
            db.scalar(
                _sel(_func.count()).select_from(AuditEvent).where(
                    AuditEvent.action == "login.lockout_armed"
                )
            ) or 0
        )
    assert after == before


def test_lockout_armed_on_security_allowlist():
    from app.observability import SECURITY_ACTION_ALLOWLIST
    assert "login.lockout_armed" in SECURITY_ACTION_ALLOWLIST
