"""Tests for GET /admin/audit/export.jsonl.gz — gzip-compressed NDJSON bulk export."""

from __future__ import annotations

import gzip
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select as _sel

from app.main import app


def _set_2fa_required(value: bool) -> None:
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    from app.db import Account, session_factory

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


def _seed_jsonl_events() -> None:
    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        for i in range(3):
            db.add(
                AuditEvent(
                    action="test.jsonl-export",
                    resource_type="account",
                    resource_id=str(i + 1),
                )
            )
        db.commit()


def test_jsonl_export_returns_gzip_with_correct_disposition(
    admin_client: TestClient,
) -> None:
    r = admin_client.get("/admin/audit/export.jsonl.gz")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"
    assert 'attachment; filename="audit.jsonl.gz"' in r.headers["content-disposition"]
    # Body is gzip-compressed — magic bytes 0x1f 0x8b.
    assert r.content[:2] == b"\x1f\x8b"


def test_jsonl_export_decompresses_to_ndjson(admin_client: TestClient) -> None:
    _seed_jsonl_events()

    r = admin_client.get("/admin/audit/export.jsonl.gz?action=test.jsonl-export")
    assert r.status_code == 200

    decoded = gzip.decompress(r.content).decode("utf-8")
    lines = [json.loads(line) for line in decoded.strip().splitlines()]
    assert len(lines) >= 3
    for obj in lines:
        assert "id" in obj
        assert "action" in obj
        assert "created_at" in obj


def test_jsonl_export_honors_filter(admin_client: TestClient) -> None:
    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        db.add(
            AuditEvent(
                action="test.jsonl-filter-a", resource_type="account", resource_id="10"
            )
        )
        db.add(
            AuditEvent(
                action="test.jsonl-filter-b", resource_type="account", resource_id="11"
            )
        )
        db.commit()

    r = admin_client.get("/admin/audit/export.jsonl.gz?action=test.jsonl-filter-a")
    assert r.status_code == 200

    decoded = gzip.decompress(r.content).decode("utf-8")
    lines = [json.loads(line) for line in decoded.strip().splitlines()]
    assert len(lines) >= 1
    for obj in lines:
        assert obj["action"] == "test.jsonl-filter-a"


def test_jsonl_export_requires_auth() -> None:
    with TestClient(app) as c:
        r = c.get("/admin/audit/export.jsonl.gz", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers["location"]
