"""Tests for /admin/ops/backups — list, prune-now, delete handlers."""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, session_factory
from app.main import app


# ── shared helpers ────────────────────────────────────────────────────────


def _set_policy(**kwargs) -> None:
    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        if p is None:
            p = GlobalPolicy(id=1)
            db.add(p)
        for k, v in kwargs.items():
            setattr(p, k, v)
        db.commit()


def _reset_totp() -> None:
    with session_factory() as db:
        from sqlalchemy import select as _sel
        from app.db import Account

        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    with TestClient(app):
        pass
    yield


@pytest.fixture(autouse=True)
def _reset_policy():
    yield
    _set_policy(backup_directory=None, backup_retention_count=7)


@pytest.fixture()
def admin_client() -> TestClient:
    with TestClient(app) as c:
        _reset_totp()
        _set_policy(require_2fa_for_admins=False)

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

        _set_policy(require_2fa_for_admins=False)
        _reset_totp()


# ── tests ─────────────────────────────────────────────────────────────────


def test_list_empty_when_no_directory(admin_client: TestClient) -> None:
    _set_policy(backup_directory=None)
    r = admin_client.get("/admin/ops/backups")
    assert r.status_code == 200
    assert "No backup directory configured" in r.text


def test_list_shows_files(admin_client: TestClient, tmp_path) -> None:
    fname = "nks-wdc-backup-20260101T120000Z.zip"
    (tmp_path / fname).write_bytes(b"x")
    _set_policy(backup_directory=str(tmp_path))

    r = admin_client.get("/admin/ops/backups")
    assert r.status_code == 200
    assert fname in r.text


def test_prune_now_removes_old_files(admin_client: TestClient, tmp_path) -> None:
    _set_policy(backup_directory=str(tmp_path), backup_retention_count=2)

    now = time.time()
    for i in range(5):
        p = tmp_path / f"nks-wdc-backup-2026010{i}T120000Z.zip"
        p.write_bytes(b"x")
        t = now - i * 60
        os.utime(str(p), (t, t))

    admin_client.get("/admin/ops/backups")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/ops/backups/prune-now",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    remaining = list(tmp_path.glob("nks-wdc-backup-*.zip"))
    assert len(remaining) == 2

    from sqlalchemy import select as _sel
    from app.db import AuditEvent

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "backup.pruned")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert (evt.detail or {}).get("removed") == 3


def test_delete_one_file(admin_client: TestClient, tmp_path) -> None:
    fname1 = "nks-wdc-backup-20260101T120000Z.zip"
    fname2 = "nks-wdc-backup-20260102T120000Z.zip"
    (tmp_path / fname1).write_bytes(b"x")
    (tmp_path / fname2).write_bytes(b"x")
    _set_policy(backup_directory=str(tmp_path))

    admin_client.get("/admin/ops/backups")
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    r = admin_client.post(
        "/admin/ops/backups/delete",
        data={"_csrf": csrf, "filename": fname1},
        follow_redirects=False,
    )
    assert r.status_code == 303

    assert not (tmp_path / fname1).exists()
    assert (tmp_path / fname2).exists()

    from sqlalchemy import select as _sel
    from app.db import AuditEvent

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "backup.deleted")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    assert (evt.detail or {}).get("filename") == fname1


def test_delete_rejects_path_traversal(admin_client: TestClient, tmp_path) -> None:
    outside_file = tmp_path.parent / "nks-wdc-backup-outside.zip"
    outside_file.write_bytes(b"secret")
    _set_policy(backup_directory=str(tmp_path))

    try:
        admin_client.get("/admin/ops/backups")
        csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

        r = admin_client.post(
            "/admin/ops/backups/delete",
            data={"_csrf": csrf, "filename": "../nks-wdc-backup-outside.zip"},
            follow_redirects=False,
        )
        assert r.status_code == 303

        # The file outside the configured directory must still exist
        assert outside_file.exists(), (
            "Path traversal guard failed — outside file was deleted"
        )

        # Flash cookie should contain the rejection message
        flash_cookie = r.cookies.get("flash") or ""
        # Follow the redirect to get the rendered flash message
        r2 = admin_client.get("/admin/ops/backups")
        assert "Invalid filename" in r2.text or flash_cookie
    finally:
        if outside_file.exists():
            outside_file.unlink()


def test_ops_page_links_to_backups_when_configured(
    admin_client: TestClient, tmp_path
) -> None:
    _set_policy(backup_directory=str(tmp_path))

    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert 'href="/admin/ops/backups"' in r.text
