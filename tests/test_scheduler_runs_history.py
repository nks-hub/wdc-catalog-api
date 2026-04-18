"""Tests for the scheduler runs history page at /admin/ops/scheduler."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select as _sel

from app.db import SchedulerRun, session_factory
from app.main import app


@pytest.fixture(scope="module", autouse=True)
def _bootstrap_db():
    """Ensure tables exist before any test in this module runs."""
    with TestClient(app):
        pass


def _clear_scheduler_runs() -> None:
    with session_factory() as db:
        db.execute(delete(SchedulerRun))
        db.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
    from app.db import Account

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


def _make_run(job: str, ok: bool = True, duration_ms: int = 100) -> SchedulerRun:
    return SchedulerRun(
        job=job,
        started_at=_now(),
        finished_at=_now(),
        duration_ms=duration_ms,
        summary={"deleted": 1, "accounts": 0, "idempotency_purged": 0,
                 "revoked_tokens_purged": 0, "audit_events_purged": 0},
        error=None if ok else "Traceback: something went wrong",
    )


def test_history_page_renders_with_rows(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        db.add(_make_run("retention", ok=True))
        db.add(_make_run("retention", ok=True))
        db.add(_make_run("retention", ok=False))
        db.commit()

    r = admin_client.get("/admin/ops/scheduler")
    assert r.status_code == 200
    body = r.text
    assert "Scheduler runs (3)" in body
    assert body.count("pill pill-ok") == 2
    assert body.count("pill pill-suspended") == 1


def test_history_empty_state(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    r = admin_client.get("/admin/ops/scheduler")
    assert r.status_code == 200
    assert "No scheduler runs recorded yet" in r.text


def test_history_job_filter(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        db.add(_make_run("retention"))
        db.add(_make_run("blob-cleanup"))
        db.commit()

    r = admin_client.get("/admin/ops/scheduler?job=retention")
    assert r.status_code == 200
    body = r.text
    assert "Scheduler runs (1)" in body
    assert "<code>retention</code>" in body
    assert "<code>blob-cleanup</code>" not in body


def test_history_status_filter_failed(admin_client: TestClient) -> None:
    _clear_scheduler_runs()

    with session_factory() as db:
        db.add(_make_run("retention", ok=True))
        db.add(_make_run("retention", ok=False))
        db.commit()

    r = admin_client.get("/admin/ops/scheduler?status_filter=failed")
    assert r.status_code == 200
    body = r.text
    assert body.count("pill pill-suspended") == 1
    assert "pill pill-ok" not in body


def test_ops_page_links_to_scheduler_history(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/ops")
    assert r.status_code == 200
    assert 'href="/admin/ops/scheduler?job=retention"' in r.text
