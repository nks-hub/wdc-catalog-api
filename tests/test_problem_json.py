"""RFC 7807 problem+json error format tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_404_returns_problem_json(client: TestClient):
    r = client.get("/api/v1/catalog/nonexistent-app-xyz")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 404
    assert body["title"] == "Not Found"
    assert body["type"].endswith("/404")
    assert body["instance"] == "/api/v1/catalog/nonexistent-app-xyz"
    # Legacy compatibility — clients still read ``detail``
    assert "detail" in body


def test_401_carries_problem_format(client: TestClient):
    r = client.get("/api/v1/devices")  # no auth header
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 401
    assert body["title"] == "Unauthorized"


def test_422_validation_error_lists_errors(client: TestClient):
    r = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "short"},
    )
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert "errors" in body and isinstance(body["errors"], list)
    # Pydantic should have flagged both fields
    fields = {"".join(str(x) for x in err.get("loc", [])) for err in body["errors"]}
    assert any("email" in f for f in fields)


def test_request_id_propagated_into_problem(client: TestClient):
    r = client.get(
        "/api/v1/catalog/nonexistent-xyz",
        headers={"X-Request-ID": "problem-test-42"},
    )
    assert r.json().get("request_id") == "problem-test-42"
