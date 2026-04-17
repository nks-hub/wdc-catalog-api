"""Account-lockout regression tests.

Five consecutive bad passwords must lock the account; a valid password
afterwards must be rejected with 423 until the lock expires. Successful
auth resets the counter.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import Account, session_factory
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _make_account(client: TestClient, email: str, password: str) -> None:
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.text


def test_five_failed_logins_lock_account(client: TestClient) -> None:
    email = "lockout-target@example.com"
    _make_account(client, email, "correct-horse-battery")

    for _ in range(5):
        r = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
        )
        assert r.status_code == 401, r.text

    # Even the correct password is rejected while locked.
    r = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert r.status_code == 423, r.text


def test_successful_login_clears_counter(client: TestClient) -> None:
    email = "lockout-reset@example.com"
    _make_account(client, email, "correct-horse-battery")

    # Two failed attempts — under the 5-fail threshold.
    for _ in range(2):
        client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
        )

    # Success should clear the counter.
    r = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert r.status_code == 200, r.text

    with session_factory() as db:
        acct = db.scalar(select(Account).where(Account.email == email))
        assert acct is not None
        assert acct.failed_login_count == 0
        assert acct.locked_until is None


def test_admin_can_clear_lockout(client: TestClient) -> None:
    """The /unlock admin route resets counter + locked_until, so an
    honest user stuck in a 30-min cooldown can retry immediately."""
    email = "lockout-admin-clear@example.com"
    _make_account(client, email, "correct-horse-battery")

    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
        )

    # Blocked right now.
    r = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert r.status_code == 423

    # Sign in as admin + clear the lockout via the admin UI endpoint.
    with session_factory() as db:
        acct = db.scalar(select(Account).where(Account.email == email))
        assert acct is not None
        acct_id = acct.id

    client.get("/login")
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        f"/admin/users/{acct_id}/unlock",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    # Valid password now works.
    r = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert r.status_code == 200


def test_lockout_expires(client: TestClient) -> None:
    """Directly rewind ``locked_until`` to simulate the lock elapsing."""
    email = "lockout-expire@example.com"
    _make_account(client, email, "correct-horse-battery")

    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong"},
        )

    with session_factory() as db:
        acct = db.scalar(select(Account).where(Account.email == email))
        assert acct is not None
        acct.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()

    r = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert r.status_code == 200, r.text
