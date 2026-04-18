"""Tests for outbound webhook dispatcher (app/webhooks.py)."""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading

import pytest
from fastapi.testclient import TestClient

from app import audit
from app.db import AuditEvent, GlobalPolicy, session_factory
from app.main import app


# ---------------------------------------------------------------------------
# Bootstrap — ensure tables exist before any test in this module runs
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    with TestClient(app):
        pass


# ---------------------------------------------------------------------------
# Mock HTTP server
# ---------------------------------------------------------------------------


class _CapturingHandler(http.server.BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        type(self).received.append(json.loads(body.decode("utf-8")))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_webhook(url: str | None, prefixes: str | None = None) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.webhook_url = url
        if prefixes is not None:
            p.webhook_event_prefixes = prefixes
        db.commit()


def _emit(action: str) -> AuditEvent:
    with session_factory() as db:
        row = audit.emit(db, actor=None, action=action, request=None)
        db.commit()
        db.refresh(row)
        return row


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_webhook():
    """Spin up a capturing HTTP server and configure GlobalPolicy to point at it."""
    from app.webhooks import drain as _drain, _reset_pool_for_tests

    os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)
    _CapturingHandler.received = []

    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _CapturingHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    url = f"http://127.0.0.1:{port}/hook"
    _set_webhook(url)

    yield url

    server.shutdown()
    server.server_close()
    _drain(timeout=3)
    _reset_pool_for_tests()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_webhook_fires_on_matching_event(mock_webhook):
    """permission.denied is in the default prefix list — a POST must arrive."""
    _emit("permission.denied")

    from app.webhooks import drain as _drain
    _drain(timeout=3)

    from app.webhooks import _reset_pool_for_tests
    _reset_pool_for_tests()

    assert len(_CapturingHandler.received) == 1
    assert _CapturingHandler.received[0]["event"]["action"] == "permission.denied"


def test_webhook_skipped_on_non_matching_action(mock_webhook):
    """snapshot.created is not in the default prefixes — no POST expected."""
    _emit("snapshot.created")

    from app.webhooks import drain as _drain
    _drain(timeout=3)

    from app.webhooks import _reset_pool_for_tests
    _reset_pool_for_tests()

    assert _CapturingHandler.received == []


def test_webhook_disabled_when_url_blank(mock_webhook):
    """Clearing webhook_url must suppress delivery even for matching actions."""
    _set_webhook(None)

    _emit("permission.denied")

    from app.webhooks import drain as _drain
    _drain(timeout=3)

    from app.webhooks import _reset_pool_for_tests
    _reset_pool_for_tests()

    assert _CapturingHandler.received == []


def test_webhook_failure_does_not_break_audit_emit():
    """Pointing the URL at an unreachable port must not prevent the audit row write."""
    from app.webhooks import drain as _drain, _reset_pool_for_tests

    os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)

    dead_port = _free_port()  # port is free but nothing is listening
    _set_webhook(f"http://127.0.0.1:{dead_port}/hook")

    row = _emit("permission.denied")

    # fire() returns immediately (fire-and-forget); the DB row must exist now
    assert row.id is not None
    assert row.action == "permission.denied"

    with session_factory() as db:
        assert db.get(AuditEvent, row.id) is not None

    # Let the background thread exhaust its (failed) connect attempt
    _drain(timeout=8)
    _reset_pool_for_tests()

    # Restore clean state
    _set_webhook(None)


def test_prefix_match_wildcard(mock_webhook):
    """A trailing-dot prefix matches all children but not non-children."""
    _set_webhook(mock_webhook, prefixes="session.")

    _emit("session.killed")
    _emit("session.killed_others")
    _emit("login.ok")

    from app.webhooks import drain as _drain
    _drain(timeout=3)

    from app.webhooks import _reset_pool_for_tests
    _reset_pool_for_tests()

    actions = [r["event"]["action"] for r in _CapturingHandler.received]
    assert len(_CapturingHandler.received) == 2
    assert "session.killed" in actions
    assert "session.killed_others" in actions
    assert "login.ok" not in actions
