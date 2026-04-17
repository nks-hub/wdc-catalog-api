"""Smoke tests for the catalog-api FastAPI service.

Uses FastAPI's TestClient to run the app in-process — no separate uvicorn
server, no port collisions. Covers the public JSON contract the C# daemon
depends on (schema, app keys, snake_case fields) so a schema drift breaks
CI before it breaks the daemon.
"""

from __future__ import annotations

import os

import pytest

# State dir set by conftest.py — no need to set again here.
os.environ["NKS_WDC_CATALOG_DEV"] = "1"  # bootstrap admin/admin

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    # TestClient's __enter__ runs the FastAPI lifespan so the SQLite
    # schema is created and seed JSONs imported.
    with TestClient(app) as c:
        yield c


def test_healthz_returns_ok(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["service"] == "nks-wdc-catalog-api"


def test_catalog_contains_seeded_apps(client: TestClient) -> None:
    r = client.get("/api/v1/catalog")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "1"
    # Every seed JSON under app/data/apps/ should round-trip into the db.
    expected = {
        "apache",
        "caddy",
        "cloudflared",
        "mailpit",
        "mariadb",
        "mkcert",
        "mysql",
        "nginx",
        "php",
        "redis",
    }
    assert expected.issubset(set(body["apps"].keys())), (
        f"missing apps: {expected - set(body['apps'].keys())}"
    )


def test_catalog_app_shape_matches_csharp_contract(client: TestClient) -> None:
    """Every AppDoc must serialize as snake_case fields the CatalogClient
    C# DTOs expect — catching Pydantic alias regressions early."""
    r = client.get("/api/v1/catalog/cloudflared")
    assert r.status_code == 200
    doc = r.json()
    assert doc["name"] == "cloudflared"
    assert "display_name" in doc
    assert "category" in doc
    assert "releases" in doc and isinstance(doc["releases"], list)
    if doc["releases"]:
        rel = doc["releases"][0]
        assert "version" in rel
        assert "major_minor" in rel
        assert "downloads" in rel
        for dl in rel["downloads"]:
            # Fields CatalogClient.cs reads
            assert "url" in dl
            assert "os" in dl
            assert "arch" in dl
            assert "archive_type" in dl
            assert "source" in dl


def test_unknown_app_returns_404(client: TestClient) -> None:
    r = client.get("/api/v1/catalog/definitely-not-an-app")
    assert r.status_code == 404


def _csrf_pair(client: TestClient) -> tuple[str, str]:
    """GET /login so the middleware drops a CSRF cookie, then hand it
    back together with the form-field spelling the tests need."""
    r = client.get("/login")
    assert r.status_code == 200
    token = r.cookies.get("nks_wdc_csrf")
    assert token
    return token, "_csrf"


def test_login_rejects_bad_credentials(client: TestClient) -> None:
    token, field = _csrf_pair(client)
    r = client.post(
        "/login",
        data={"username": "admin", "password": "wrong", field: token},
        follow_redirects=False,
    )
    assert r.status_code == 401


def test_admin_requires_auth(client: TestClient) -> None:
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_login_accepts_dev_admin(client: TestClient) -> None:
    token, field = _csrf_pair(client)
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", field: token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "nks_wdc_catalog_session" in r.cookies
    # Cookie must be HttpOnly + SameSite=Strict so the admin panel survives
    # CSRF + XSS token-exfiltration attempts (F-03, F-04 hardening).
    set_cookie = r.headers.get("set-cookie", "").lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie


def test_catalog_etag_round_trip(client: TestClient) -> None:
    """Catalog endpoint must emit ETag + Cache-Control and honor If-None-Match."""
    r = client.get("/api/v1/catalog")
    assert r.status_code == 200
    etag = r.headers.get("etag")
    assert etag is not None
    cache_control = r.headers.get("cache-control")
    assert cache_control is not None
    assert "max-age" in cache_control

    # Round-trip with If-None-Match → 304
    r2 = client.get("/api/v1/catalog", headers={"If-None-Match": etag})
    assert r2.status_code == 304


def test_healthz_reports_db_up(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["db"] == "up"


def test_payload_size_limit_rejects_oversized(client: TestClient) -> None:
    """Content-Length > 1 MiB must be rejected with 413 before routing."""
    # 2 MB synthetic body — don't actually ship, just set the header.
    big_body = "x" * (2 * 1024 * 1024)
    r = client.post(
        "/api/v1/sync/config",
        content=big_body,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413


@pytest.fixture
def smoke_token(client: TestClient) -> str:
    """Register a throw-away account and return a JWT for smoke tests."""
    import uuid

    email = f"smoke-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "smokepass12345"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_config_sync_round_trip(client: TestClient, smoke_token: str) -> None:
    device_id = "test-device-12345"
    payload = {"sites": [{"domain": "blog.loc"}], "version": 1}
    auth = {"Authorization": f"Bearer {smoke_token}"}

    # Upsert (authenticated — anonymous would be rejected per F-11)
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": device_id, "payload": payload},
        headers=auth,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["device_id"] == device_id
    assert body["payload"] == payload

    # Fetch back (auth required per F-12)
    r = client.get(f"/api/v1/sync/config/{device_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["payload"] == payload

    # Exists probe
    r = client.get(f"/api/v1/sync/config/{device_id}/exists", headers=auth)
    assert r.status_code == 200
    assert r.json()["has_config"] is True

    # Delete
    r = client.delete(f"/api/v1/sync/config/{device_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["removed"] is True

    # Post-delete fetch returns 404
    r = client.get(f"/api/v1/sync/config/{device_id}", headers=auth)
    assert r.status_code == 404


def test_config_sync_rejects_invalid_device_id_on_upsert(client: TestClient) -> None:
    """Device IDs that don't match the strict shape must fail with 400,
    not silently store garbage rows the admin UI can't interpret."""
    # Empty
    r = client.post("/api/v1/sync/config", json={"device_id": "", "payload": {}})
    assert r.status_code == 400

    # Uppercase (we lowercase, but "A!" has a shell metachar)
    r = client.post("/api/v1/sync/config", json={"device_id": "A!", "payload": {}})
    assert r.status_code == 400

    # Path traversal attempt
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": "../etc/passwd", "payload": {}},
    )
    assert r.status_code == 400

    # Too short (< 3 chars)
    r = client.post("/api/v1/sync/config", json={"device_id": "ab", "payload": {}})
    assert r.status_code == 400

    # Too long (> 64 chars)
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": "a" * 65, "payload": {}},
    )
    assert r.status_code == 400

    # Whitespace-only
    r = client.post("/api/v1/sync/config", json={"device_id": "   ", "payload": {}})
    assert r.status_code == 400


def test_config_sync_rejects_invalid_device_id_on_get(
    client: TestClient, smoke_token: str
) -> None:
    """GET endpoints also validate so a malformed URL returns 400, not 404.
    Now authenticated because anonymous access is rejected since F-12."""
    auth = {"Authorization": f"Bearer {smoke_token}"}
    r = client.get("/api/v1/sync/config/A!", headers=auth)
    assert r.status_code == 400

    r = client.get("/api/v1/sync/config/ab", headers=auth)
    assert r.status_code == 400

    r = client.get("/api/v1/sync/config/-foo", headers=auth)
    assert r.status_code == 400


def test_config_sync_device_id_normalized_to_lowercase(
    client: TestClient, smoke_token: str
) -> None:
    """Clients can upload with mixed case — it gets stored lowercased."""
    auth = {"Authorization": f"Bearer {smoke_token}"}
    r = client.post(
        "/api/v1/sync/config",
        json={"device_id": "MixedCase-DEVICE", "payload": {"marker": True}},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["device_id"] == "mixedcase-device"

    r = client.get("/api/v1/sync/config/MixedCase-DEVICE", headers=auth)
    assert r.status_code == 200
    assert r.json()["payload"]["marker"] is True

    client.delete("/api/v1/sync/config/mixedcase-device", headers=auth)
