"""PAT read-only flag — enforcement and API surface tests.

Tests 1-5 (Task 1): core enforcement via direct DB mint.
Tests 6-7 (Task 2): admin UI + JSON API surface.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.main import app


# ── Helpers ─────────────────────────────────────────────────────────────


def _register_and_jwt(c: TestClient) -> tuple[str, int]:
    """Register a fresh account, return (jwt, account_id)."""
    email = f"ro-{uuid.uuid4().hex[:8]}@example.com"
    r = c.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passphrase-5678!"},
    )
    assert r.status_code == 200, r.text
    jwt_token = r.json()["token"]
    r2 = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {jwt_token}"})
    assert r2.status_code == 200
    return jwt_token, r2.json()["id"]


def _mint_pat_direct(account_id: int, *, read_only: bool) -> str:
    """Mint a PAT directly via DB — no dependency on Task 2's API surface."""
    from app.db import session_factory
    from app import pats

    with session_factory() as db:
        _, plaintext = pats.issue(
            db, account_id=account_id, name="test-ro", read_only=read_only
        )
        db.commit()
    return plaintext


# ── Task 1 tests (tests 1-5) ─────────────────────────────────────────────


def test_rw_pat_allows_post() -> None:
    """A read-write PAT must be accepted on POST endpoints."""
    with TestClient(app) as c:
        jwt_token, account_id = _register_and_jwt(c)
        rw_pat = _mint_pat_direct(account_id, read_only=False)

        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "spawned-by-rw"},
            headers={"Authorization": f"Bearer {rw_pat}"},
        )
        assert r.status_code == 201, r.text


def test_ro_pat_allows_get() -> None:
    """A read-only PAT must succeed on GET requests."""
    with TestClient(app) as c:
        _, account_id = _register_and_jwt(c)
        ro_pat = _mint_pat_direct(account_id, read_only=True)

        r = c.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {ro_pat}"},
        )
        assert r.status_code == 200, r.text


def test_ro_pat_rejects_post_with_403() -> None:
    """A read-only PAT must get HTTP 403 on POST, not 401."""
    with TestClient(app) as c:
        _, account_id = _register_and_jwt(c)
        ro_pat = _mint_pat_direct(account_id, read_only=True)

        r = c.post(
            "/api/v1/auth/tokens",
            json={"name": "should-fail"},
            headers={"Authorization": f"Bearer {ro_pat}"},
        )
        assert r.status_code == 403, r.text
        assert "read-only" in r.text.lower() or "Read-only" in r.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("PUT", "/api/v1/devices/nonexistent-device", {"name": "x"}),
        ("DELETE", "/api/v1/devices/nonexistent-device", None),
        ("POST", "/api/v1/auth/tokens", {"name": "x"}),
    ],
)
def test_ro_pat_rejects_write_methods(method: str, path: str, body) -> None:
    """PUT, DELETE, and POST all return 403 for a read-only PAT."""
    with TestClient(app) as c:
        _, account_id = _register_and_jwt(c)
        ro_pat = _mint_pat_direct(account_id, read_only=True)
        headers = {"Authorization": f"Bearer {ro_pat}"}

        if method == "PUT":
            r = c.put(path, json=body, headers=headers)
        elif method == "DELETE":
            r = c.delete(path, headers=headers)
        else:
            r = c.post(path, json=body, headers=headers)

        assert r.status_code == 403, f"{method} {path} returned {r.status_code}"


def test_invalid_pat_still_401_not_403() -> None:
    """A garbage bearer token starting with nks_pat_ returns 401, not 403."""
    with TestClient(app) as c:
        r = c.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": "Bearer nks_pat_totallyinvalidtoken00000000000000000000"
            },
        )
        assert r.status_code == 401, r.text


# ── Task 2 tests (tests 6-7) ─────────────────────────────────────────────


@pytest.fixture()
def admin_client() -> TestClient:
    """Logged-in admin UI client (session cookie)."""
    with TestClient(app) as c:
        from app.db import Account, session_factory

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


def test_admin_ui_mint_creates_ro_token(admin_client: TestClient) -> None:
    """POST /admin/account/tokens with read_only=1 creates a read_only=True row."""
    from app.db import Account, PersonalAccessToken, session_factory

    admin_client.get("/admin/account")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/account/tokens",
        data={"_csrf": csrf, "name": "ro-admin-pat", "read_only": "1"},
    )
    assert r.status_code == 200, r.text

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        row = db.scalar(
            _sel(PersonalAccessToken)
            .where(PersonalAccessToken.account_id == acct.id)
            .where(PersonalAccessToken.name == "ro-admin-pat")
            .order_by(PersonalAccessToken.id.desc())
        )
    assert row is not None
    assert row.read_only is True


def test_account_page_shows_read_only_pill(admin_client: TestClient) -> None:
    """Account page renders 'read-only' pill for an RO token."""
    from app.db import Account, session_factory
    from app import pats

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        pats.issue(db, account_id=acct.id, name="pill-test-ro", read_only=True)
        db.commit()

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "read-only" in r.text
