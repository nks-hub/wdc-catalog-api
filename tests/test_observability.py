"""Tests for observability — request-id middleware + /metrics endpoint."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_request_id_is_round_tripped(client: TestClient):
    rid = f"test-{uuid.uuid4().hex[:8]}"
    r = client.get("/healthz", headers={"X-Request-ID": rid})
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == rid


def test_request_id_generated_when_absent(client: TestClient):
    r = client.get("/healthz")
    assert r.status_code == 200
    rid = r.headers.get("x-request-id")
    assert rid
    assert len(rid) >= 8


def test_metrics_endpoint_prometheus_format(client: TestClient):
    for _ in range(3):
        client.get("/healthz")
    r = client.get("/metrics")
    assert r.status_code == 200
    ctype = r.headers.get("content-type", "")
    assert "text/plain" in ctype
    body = r.text
    assert "nks_wdc_http_requests_total" in body
    assert "nks_wdc_http_request_duration_seconds" in body


def test_snapshot_created_counter_increments(client: TestClient):
    email = f"obs-{uuid.uuid4().hex[:8]}@nks-wdc.dev"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "pass12345678"},
    )
    token = r.json()["token"]
    client.post(
        "/api/v1/sync/config",
        json={"device_id": "obs-dev-1", "payload": {"x": 1}},
        headers={"Authorization": f"Bearer {token}"},
    )
    metrics = client.get("/metrics").text
    assert 'nks_wdc_snapshot_created_total{kind="auto"}' in metrics
