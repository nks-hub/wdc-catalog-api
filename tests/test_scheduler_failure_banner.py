"""Scheduler-failure banner on every admin page.

When the most-recent `SchedulerRun(job=*)` within 48h has a non-null
`error`, base.html renders a red banner at the top of every admin page
so operators can't miss a broken retention/backup job.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    with TestClient(app) as c:
        from app.db import Account, GlobalPolicy, session_factory
        from sqlalchemy import select as _sel

        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                acct.totp_enabled = False
                acct.totp_secret = None
                acct.totp_recovery_hashes = None
                acct.totp_enabled_at = None
            policy = db.get(GlobalPolicy, 1)
            if policy is not None:
                policy.require_2fa_for_admins = False
                policy.admin_ip_allowlist = None
            db.commit()

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


def _reset_scheduler_runs() -> None:
    from app.db import SchedulerRun, session_factory
    from sqlalchemy import delete as _delete

    with session_factory() as db:
        db.execute(_delete(SchedulerRun))
        db.commit()


def _seed_run(*, job: str, hours_ago: float, error: str | None) -> None:
    from app.db import SchedulerRun, session_factory

    when = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours_ago)
    with session_factory() as db:
        db.add(
            SchedulerRun(
                job=job,
                started_at=when,
                finished_at=when + timedelta(seconds=1),
                duration_ms=1000,
                summary=None if error else {"deleted": 0},
                error=error,
            )
        )
        db.commit()


def test_no_failures_no_banner(admin_client: TestClient) -> None:
    _reset_scheduler_runs()
    _seed_run(job="retention", hours_ago=3, error=None)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "banner-error" not in r.text
    assert "job failed" not in r.text.lower()


def test_recent_failure_shows_banner(admin_client: TestClient) -> None:
    _reset_scheduler_runs()
    _seed_run(job="retention", hours_ago=2, error="IntegrityError: broken schema")
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "banner-error" in r.text
    assert "retention" in r.text
    assert "IntegrityError" in r.text
    # investigate link points into the filtered scheduler history
    assert "/admin/ops/scheduler?status_filter=failed" in r.text


def test_old_failure_outside_48h_no_banner(admin_client: TestClient) -> None:
    _reset_scheduler_runs()
    _seed_run(job="retention", hours_ago=60, error="ancient problem")
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "banner-error" not in r.text


def test_failure_superseded_by_later_success_no_banner(
    admin_client: TestClient,
) -> None:
    """If a job failed but a later run of the SAME job succeeded, the
    banner should NOT render — the operator already has a green run."""
    _reset_scheduler_runs()
    _seed_run(job="retention", hours_ago=5, error="transient error")
    _seed_run(job="retention", hours_ago=2, error=None)
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert "banner-error" not in r.text


def test_banner_on_every_admin_page(admin_client: TestClient) -> None:
    """The banner ships via base_context → every admin template sees it."""
    _reset_scheduler_runs()
    _seed_run(job="backup", hours_ago=1, error="ConnectionRefusedError")

    for path in ["/admin", "/admin/audit", "/admin/users", "/admin/ops"]:
        r = admin_client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"
        assert "banner-error" in r.text, f"no banner on {path}"
        assert "backup" in r.text
