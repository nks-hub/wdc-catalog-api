"""Tests that audit.emit() publishes each flushed row to the event bus."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app import audit, event_bus
from app.db import Account, session_factory
from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def _make_account(db) -> Account:
    acc = Account(
        email=f"bus-test-{id(db)}@example.com",
        password_hash="x" * 64,
        role="user",
    )
    db.add(acc)
    db.flush()
    return acc


@pytest.mark.asyncio
async def test_emit_publishes_to_bus(client: TestClient) -> None:
    """audit.emit() must broadcast the flushed row to event_bus subscribers."""
    assert client.get("/healthz").status_code == 200

    async with event_bus.subscribe() as stream:
        with session_factory() as db:
            acc = _make_account(db)
            audit.emit(
                db,
                actor=acc,
                action="test.emit_hook",
                resource_type="test",
                resource_id="42",
            )
            db.commit()

        evt = await asyncio.wait_for(anext(stream), timeout=2)

    assert evt["action"] == "test.emit_hook"
    assert evt["resource_id"] == "42"


def test_bus_failure_does_not_break_emit(monkeypatch, client: TestClient) -> None:
    """A publish error must be swallowed — the DB row must still be written."""
    assert client.get("/healthz").status_code == 200

    monkeypatch.setattr(
        event_bus, "publish", lambda _: (_ for _ in ()).throw(RuntimeError("bus down"))
    )

    with session_factory() as db:
        acc = _make_account(db)
        row = audit.emit(
            db,
            actor=acc,
            action="test.bus_failure",
            resource_type="test",
            resource_id="99",
        )
        db.commit()
        assert row.id is not None
        assert row.action == "test.bus_failure"
