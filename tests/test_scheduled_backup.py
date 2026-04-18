"""Tests for scheduled backup runner + on-disk retention pruning."""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

from app.db import GlobalPolicy, SchedulerRun, session_factory
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


def _cleanup_scheduler_runs() -> None:
    with session_factory() as db:
        from sqlalchemy import delete as _del

        db.execute(_del(SchedulerRun).where(SchedulerRun.job == "backup"))
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
    _set_policy(backup_enabled=False, backup_directory=None, backup_retention_count=7)
    _cleanup_scheduler_runs()


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


def test_run_scheduled_backup_writes_file_when_enabled(tmp_path) -> None:
    from app import backup

    _set_policy(backup_enabled=True, backup_directory=str(tmp_path), backup_retention_count=7)

    result = backup.run_scheduled_backup()

    assert "path" in result
    assert "bytes" in result
    assert "counts" in result
    assert result["bytes"] > 0

    files = list(tmp_path.glob("nks-wdc-backup-*.zip"))
    assert len(files) == 1

    from sqlalchemy import select as _sel

    with session_factory() as db:
        row = db.scalar(
            _sel(SchedulerRun)
            .where(SchedulerRun.job == "backup")
            .order_by(SchedulerRun.started_at.desc())
            .limit(1)
        )
    assert row is not None
    assert row.error is None
    assert row.summary is not None
    assert "bytes" in row.summary


def test_run_scheduled_backup_skips_when_disabled(tmp_path) -> None:
    from app import backup

    _set_policy(backup_enabled=False, backup_directory=str(tmp_path))

    result = backup.run_scheduled_backup()

    assert result.get("skipped") is True
    assert result.get("reason") == "backup_disabled"

    files = list(tmp_path.glob("nks-wdc-backup-*.zip"))
    assert len(files) == 0

    from sqlalchemy import select as _sel

    with session_factory() as db:
        row = db.scalar(
            _sel(SchedulerRun)
            .where(SchedulerRun.job == "backup")
            .order_by(SchedulerRun.started_at.desc())
            .limit(1)
        )
    assert row is not None, "SchedulerRun row must be recorded even for skipped runs"
    assert row.error is None
    assert row.summary == {"skipped": True, "reason": "backup_disabled"}


def test_run_scheduled_backup_skips_when_no_directory() -> None:
    from app import backup

    _set_policy(backup_enabled=True, backup_directory=None)

    result = backup.run_scheduled_backup()

    assert result.get("skipped") is True
    assert result.get("reason") == "no_directory"

    from sqlalchemy import select as _sel

    with session_factory() as db:
        row = db.scalar(
            _sel(SchedulerRun)
            .where(SchedulerRun.job == "backup")
            .order_by(SchedulerRun.started_at.desc())
            .limit(1)
        )
    assert row is not None
    assert row.summary == {"skipped": True, "reason": "no_directory"}


def test_prune_keeps_last_n(tmp_path) -> None:
    from app import backup

    now = time.time()
    for i in range(10):
        p = tmp_path / f"nks-wdc-backup-2026010{i}T120000Z.zip"
        p.write_bytes(b"x")
        t = now - i * 60
        os.utime(str(p), (t, t))

    removed = backup._prune_disk_backups(str(tmp_path), 3)

    assert removed == 7
    remaining = list(tmp_path.glob("nks-wdc-backup-*.zip"))
    assert len(remaining) == 3


def test_settings_save_persists_backup_fields(admin_client: TestClient) -> None:
    c = admin_client
    c.get("/admin/settings")
    csrf = c.cookies.get("nks_wdc_csrf") or ""

    r = c.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "backup_enabled": "1",
            "backup_retention_count": "14",
            "snapshot_keep_last_n": "30",
            "snapshot_retain_days": "90",
            "audit_retention_days": "365",
            "scheduler_run_retention_days": "90",
            "webhook_delivery_retention_days": "30",
            "default_role": "user",
            "webhook_event_prefixes": (
                "permission.denied,login.failed,session.killed,"
                "user.suspended,user.deleted,totp.login_failed"
            ),
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    with session_factory() as db:
        p = db.get(GlobalPolicy, 1)
        assert p is not None
        assert p.backup_enabled is True
        assert p.backup_retention_count == 14

    from sqlalchemy import select as _sel
    from app.db import AuditEvent

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    changed = (evt.detail or {}).get("changed", {})
    assert "backup_enabled" in changed or "backup_retention_count" in changed
