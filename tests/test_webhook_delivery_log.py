"""Tests for the webhook delivery log (WebhookDelivery table + /admin/ops/webhooks)."""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading

import pytest
from fastapi.testclient import TestClient

from app import audit, webhooks
from app.db import GlobalPolicy, WebhookDelivery, session_factory
from app.main import app


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    with TestClient(app):
        pass


# ---------------------------------------------------------------------------
# Mock HTTP server helpers (copied from test_webhooks.py — fixtures aren't
# auto-shared across files without conftest)
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


class _ServerErrorHandler(http.server.BaseHTTPRequestHandler):
    """Returns 503 for every POST — used by test_delivery_recorded_on_5xx_response."""

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        self.send_response(503)
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
# DB helpers
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


def _emit(action: str):
    with session_factory() as db:
        row = audit.emit(db, actor=None, action=action, request=None)
        db.commit()
        db.refresh(row)
        return row


def _clear_deliveries() -> None:
    with session_factory() as db:
        db.query(WebhookDelivery).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Admin client fixture (mirrors test_webhooks.py)
# ---------------------------------------------------------------------------


def _set_2fa_required(value: bool) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from app.db import Account
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


@pytest.fixture()
def admin_client() -> TestClient:
    """Authenticated admin client with TOTP + 2FA gate reset."""
    with TestClient(app) as c:
        _reset_totp()
        _set_2fa_required(False)

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        c.get("/admin/account")

        yield c

        _set_2fa_required(False)
        _reset_totp()


# ---------------------------------------------------------------------------
# mock_webhook fixture (mirrors test_webhooks.py)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_webhook():
    """Spin up a capturing HTTP server and configure GlobalPolicy to point at it."""
    os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)
    _CapturingHandler.received = []
    _clear_deliveries()

    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _CapturingHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    url = f"http://127.0.0.1:{port}/hook"
    _set_webhook(url)

    yield url

    server.shutdown()
    server.server_close()
    webhooks.drain(timeout=3)
    webhooks._reset_pool_for_tests()
    _set_webhook(None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_delivery_recorded_on_success(mock_webhook):
    """Successful POST records a row with status_code=204 and error IS NULL."""
    _clear_deliveries()
    _emit("permission.denied")

    webhooks.drain(timeout=3)
    webhooks._reset_pool_for_tests()

    with session_factory() as db:
        rows = db.query(WebhookDelivery).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.event_action == "permission.denied"
    assert row.status_code == 204
    assert row.error is None


def test_delivery_recorded_on_connection_failure():
    """Connection-refused records a row with status_code IS NULL and an error string."""
    os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)
    _clear_deliveries()

    dead_port = _free_port()
    _set_webhook(f"http://127.0.0.1:{dead_port}/hook")

    _emit("permission.denied")

    webhooks.drain(timeout=8)
    webhooks._reset_pool_for_tests()

    _set_webhook(None)

    with session_factory() as db:
        rows = db.query(WebhookDelivery).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status_code is None
    assert row.error is not None
    assert (
        "URLError" in row.error
        or "Connection" in row.error
        or "refused" in row.error.lower()
    )


def test_delivery_recorded_on_5xx_response():
    """A 503 response records status_code=503 and error='HTTP 503'."""
    os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)
    _clear_deliveries()

    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _ServerErrorHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    url = f"http://127.0.0.1:{port}/hook"
    _set_webhook(url)

    _emit("permission.denied")

    webhooks.drain(timeout=3)
    webhooks._reset_pool_for_tests()

    server.shutdown()
    server.server_close()
    _set_webhook(None)

    with session_factory() as db:
        rows = db.query(WebhookDelivery).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status_code == 503
    assert row.error == "HTTP 503"


def test_history_page_renders_rows(admin_client):
    """History page shows all seeded delivery rows with correct pills."""
    _clear_deliveries()

    with session_factory() as db:
        db.add(
            WebhookDelivery(
                url="http://a.test/hook",
                event_action="login.failed",
                status_code=204,
                duration_ms=12,
                error=None,
            )
        )
        db.add(
            WebhookDelivery(
                url="http://b.test/hook",
                event_action="session.killed",
                status_code=200,
                duration_ms=8,
                error=None,
            )
        )
        db.add(
            WebhookDelivery(
                url="http://c.test/hook",
                event_action="permission.denied",
                status_code=None,
                duration_ms=5001,
                error="URLError: <urlopen error [Errno 111] Connection refused>",
            )
        )
        db.commit()

    r = admin_client.get("/admin/ops/webhooks")
    assert r.status_code == 200
    body = r.text
    assert "Webhook deliveries (3)" in body
    assert body.count("pill-ok") == 2
    assert body.count("pill-suspended") == 1


def test_history_page_filter_failed(admin_client):
    """Status filter=failed returns only failed rows."""
    _clear_deliveries()

    with session_factory() as db:
        db.add(
            WebhookDelivery(
                url="http://ok.test/hook",
                event_action="login.failed",
                status_code=204,
                duration_ms=10,
                error=None,
            )
        )
        db.add(
            WebhookDelivery(
                url="http://fail.test/hook",
                event_action="permission.denied",
                status_code=None,
                duration_ms=5000,
                error="URLError: connection refused",
            )
        )
        db.commit()

    r = admin_client.get("/admin/ops/webhooks?status_filter=failed")
    assert r.status_code == 200
    body = r.text
    assert "Webhook deliveries (1)" in body
    assert "pill-suspended" in body
    assert "pill-ok" not in body


def test_ops_page_links_to_webhook_history(admin_client):
    """Ops page contains a link to /admin/ops/webhooks."""
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert 'href="/admin/ops/webhooks"' in r.text
