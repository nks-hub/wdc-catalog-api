"""Tests for GET /admin/backup/export.zip — full-state archive."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.db import Account, App, AuditEvent, session_factory
from app.main import app


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist and seed non-empty data before any test runs."""
    with TestClient(app):
        pass

    from app.auth import hash_password

    with session_factory() as db:
        if not db.get(App, "backup-test-app-1"):
            db.add(App(id="backup-test-app-1", display_name="Backup Test App 1", category="utility"))
        if not db.get(App, "backup-test-app-2"):
            db.add(App(id="backup-test-app-2", display_name="Backup Test App 2", category="dev"))

        existing = db.scalar(
            __import__("sqlalchemy", fromlist=["select"]).select(Account).where(Account.email == "backup-seed@admin.local")
        )
        if existing is None:
            db.add(Account(
                email="backup-seed@admin.local",
                password_hash=hash_password("seed-pass"),
                role="user",
            ))
        db.commit()

    yield


def _set_2fa_required(value: bool) -> None:
    from app.db import GlobalPolicy

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.require_2fa_for_admins = value
        db.commit()


def _reset_totp() -> None:
    with session_factory() as db:
        from sqlalchemy import select as _sel

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


def test_zip_endpoint_returns_correct_headers_and_magic(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/backup/export.zip")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert 'attachment; filename="nks-wdc-backup-' in r.headers["content-disposition"]
    assert r.content[:4] == b"PK\x03\x04"  # ZIP magic bytes


def test_zip_contains_expected_entries(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/backup/export.zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {
        "manifest.json",
        "apps.json",
        "releases.json",
        "downloads.json",
        "accounts.json",
        "users.json",
        "invites_consumed.json",
        "scheduler_runs.json",
        "settings.json",
        "audit.jsonl.gz",
    } <= names


def test_manifest_sha256_matches_file_bytes(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/backup/export.zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    manifest = json.loads(z.read("manifest.json"))
    for entry in manifest["files"]:
        data = z.read(entry["name"])
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert len(data) == entry["size"]


def test_accounts_json_excludes_secrets(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/backup/export.zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    for row in json.loads(z.read("accounts.json")):
        assert "password_hash" not in row
        assert "totp_secret" not in row
        assert "totp_recovery_hashes" not in row


def test_export_emits_backup_exported_audit_event(admin_client: TestClient) -> None:
    admin_client.get("/admin/backup/export.zip")

    from sqlalchemy import select as _sel

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "backup.exported")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert "bytes" in (evt.detail or {})


def test_unauth_gets_login_redirect() -> None:
    with TestClient(app) as c:
        r = c.get("/admin/backup/export.zip", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers["location"]
