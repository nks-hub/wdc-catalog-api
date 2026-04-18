"""Tests for app/backup.py module + POST /admin/backup/run-now-to-disk."""

from __future__ import annotations

import glob
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.db import Account, App, AuditEvent, GlobalPolicy, session_factory
from app.main import app


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist and seed non-empty data before any test runs."""
    with TestClient(app):
        pass

    from app.auth import hash_password

    with session_factory() as db:
        if not db.get(App, "disk-backup-test-app-1"):
            db.add(
                App(
                    id="disk-backup-test-app-1",
                    display_name="Disk Backup Test App",
                    category="utility",
                )
            )

        existing = db.scalar(
            __import__("sqlalchemy", fromlist=["select"])
            .select(Account)
            .where(Account.email == "diskbackup-seed@admin.local")
        )
        if existing is None:
            db.add(
                Account(
                    email="diskbackup-seed@admin.local",
                    password_hash=hash_password("seed-pass"),
                    role="user",
                )
            )
        db.commit()

    yield


def _set_2fa_required(value: bool) -> None:
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


def _set_backup_directory(path: str | None) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        p.backup_directory = path
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
        _set_backup_directory(None)


def test_generate_backup_bytes_returns_same_shape_as_endpoint() -> None:
    from app import backup

    with session_factory() as db:
        zip_bytes, filename, manifest = backup.generate_backup_bytes(
            db, actor_email="x@admin.local"
        )

    assert isinstance(zip_bytes, bytes)
    assert zip_bytes[:4] == b"PK\x03\x04", "ZIP magic bytes not found"
    assert filename.startswith("nks-wdc-backup-")
    assert filename.endswith(".zip")

    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = set(z.namelist())
    assert "manifest.json" in names
    assert "apps.json" in names
    assert "audit.jsonl.gz" in names

    assert "counts" in manifest
    assert "files" in manifest


def test_run_to_disk_writes_file(admin_client: TestClient, tmp_path) -> None:
    _set_backup_directory(str(tmp_path))

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/backup/run-now-to-disk",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/admin/ops" in r.headers["location"]

    written = glob.glob(str(tmp_path / "nks-wdc-backup-*.zip"))
    assert len(written) == 1, f"Expected 1 backup file, found: {written}"

    with open(written[0], "rb") as fh:
        magic = fh.read(4)
    assert magic == b"PK\x03\x04", "Written file is not a valid ZIP"


def test_run_to_disk_no_directory_configured_errors(admin_client: TestClient) -> None:
    _set_backup_directory(None)

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/backup/run-now-to-disk",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/admin/ops" in r.headers["location"]

    r2 = admin_client.get("/admin/ops")
    assert r2.status_code == 200
    assert "No backup directory configured" in r2.text


def test_run_to_disk_emits_audit_event(admin_client: TestClient, tmp_path) -> None:
    _set_backup_directory(str(tmp_path))

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    admin_client.post(
        "/admin/backup/run-now-to-disk",
        data={"_csrf": csrf},
        follow_redirects=False,
    )

    from sqlalchemy import select as _sel

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "backup.saved_to_disk")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )

    assert evt is not None, "backup.saved_to_disk audit event not found"
    detail = evt.detail or {}
    assert "path" in detail
    assert "bytes" in detail
    assert "counts" in detail
