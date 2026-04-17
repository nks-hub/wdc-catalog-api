"""Regression tests for the role + suspension guards."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.db import Account, get_session
from app.devices import router as devices_router
from app.permissions import require_role
from app.roles import Role


@pytest.fixture(scope="module")
def perm_app() -> FastAPI:
    """Minimal app exposing the real auth router + a gated test route."""
    # Ensure schema exists — main app's lifespan does this but this module
    # runs an isolated FastAPI instance.
    from app.db import create_all

    create_all()

    app = FastAPI()
    app.include_router(devices_router)

    @app.get("/admin-only")
    def admin_only(account: Account = Depends(require_role(Role.admin))):
        return {"email": account.email, "role": account.role}

    @app.get("/operator-plus")
    def operator_plus(account: Account = Depends(require_role(Role.operator))):
        return {"ok": True}

    return app


@pytest.fixture(scope="module")
def perm_client(perm_app: FastAPI) -> TestClient:
    with TestClient(perm_app) as c:
        yield c


@pytest.fixture
def user_token(perm_client: TestClient) -> str:
    email = f"user-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = perm_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    assert r.status_code == 200
    return r.json()["token"]


def _make_role_token(perm_client: TestClient, role: Role) -> str:
    """Register a user then elevate its role directly via the ORM."""
    email = f"{role.value}-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    perm_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    # Elevate via fresh session (TestClient uses the shared engine).
    db = next(get_session())
    try:
        account = db.query(Account).filter(Account.email == email).one()
        account.role = role.value
        db.commit()
    finally:
        db.close()
    login = perm_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "pass12345678"},
    )
    return login.json()["token"]


def test_user_role_rejected_from_admin_route(perm_client: TestClient, user_token: str):
    r = perm_client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert r.status_code == 403


def test_admin_role_allowed(perm_client: TestClient):
    token = _make_role_token(perm_client, Role.admin)
    r = perm_client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_owner_passes_admin_gate(perm_client: TestClient):
    token = _make_role_token(perm_client, Role.owner)
    r = perm_client.get(
        "/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200


def test_support_role_rejected_from_operator_route(perm_client: TestClient):
    token = _make_role_token(perm_client, Role.support)
    r = perm_client.get(
        "/operator-plus",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403


def test_suspended_account_blocked(perm_client: TestClient):
    email = f"susp-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    perm_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    db = next(get_session())
    try:
        acc = db.query(Account).filter(Account.email == email).one()
        acc.suspended_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
    # Suspended account cannot even log in
    login = perm_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "pass12345678"},
    )
    assert login.status_code == 403
