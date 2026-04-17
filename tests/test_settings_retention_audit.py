"""Regression tests — admin settings + retention mutations must audit.

Before this suite, an admin could rewrite instance-wide policy (default
role for new accounts, banner text, snapshot retention days) with zero
audit trail. Equally, toggling the retention policy or adding a device
override emitted nothing. Each of those paths now emits a named event;
this file locks that in.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    with TestClient(app) as c:
        from app.db import Account, session_factory
        from sqlalchemy import select as _sel

        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                acct.totp_enabled = False
                acct.totp_secret = None
                acct.totp_recovery_hashes = None
                acct.totp_enabled_at = None
                db.commit()

        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        c.get("/admin/account")  # provisions the paired Account row
        yield c


def _latest_event(action: str):
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        return db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )


def test_settings_update_audits_diff(admin_client: TestClient) -> None:
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "42",  # changed to an unusual value
            "snapshot_retain_days": "60",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "",
        },
    )
    assert r.status_code in (200, 303)

    evt = _latest_event("settings.updated")
    assert evt is not None
    assert evt.resource_type == "global_policy"
    assert evt.resource_id == "1"
    changed = (evt.detail or {}).get("changed", {})
    # The ``snapshot_keep_last_n`` diff must carry the to-value we posted.
    assert "snapshot_keep_last_n" in changed
    assert changed["snapshot_keep_last_n"]["to"] == 42


def test_settings_no_change_skips_audit(admin_client: TestClient) -> None:
    """Re-saving identical values shouldn't produce noise events."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    # Pin a known state.
    admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "30",
            "snapshot_retain_days": "90",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "",
        },
    )
    before = _latest_event("settings.updated")
    assert before is not None
    before_id = before.id

    # Re-submit the same values.
    admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "30",
            "snapshot_retain_days": "90",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "",
        },
    )
    after = _latest_event("settings.updated")
    # No new row — the id didn't advance.
    assert after is not None and after.id == before_id


def test_retention_policy_save_audits(admin_client: TestClient) -> None:
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/retention/policy",
        data={
            "_csrf": csrf,
            "keep_last_n_auto": "17",
            "auto_expire_days": "45",
            "keep_labeled_forever": "1",
        },
    )
    assert r.status_code in (200, 303)

    evt = _latest_event("retention.policy_saved")
    assert evt is not None
    after = (evt.detail or {}).get("after", {})
    assert after.get("keep_last_n_auto") == 17
    assert after.get("auto_expire_days") == 45
    assert after.get("keep_labeled_forever") is True


def test_retention_manual_run_audits(admin_client: TestClient) -> None:
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post("/admin/retention/run-now", data={"_csrf": csrf})
    assert r.status_code in (200, 303)

    evt = _latest_event("retention.manual_run")
    assert evt is not None
    assert evt.resource_type == "retention_policy"
    assert "summary" in (evt.detail or {})
    summary = evt.detail["summary"]
    assert isinstance(summary.get("accounts", 0), int)


def test_retention_device_override_add_and_remove_audit(admin_client: TestClient) -> None:
    """Exercise the add + delete paths on a fresh device we provision
    directly in the DB. Both actions must produce audit rows."""
    from app.db import Account, DeviceConfig, session_factory
    from sqlalchemy import select as _sel

    dev_id = "retention-audit-test-device-42"
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        # Wipe any prior device + override from a previous failed run.
        existing_dev = db.get(DeviceConfig, dev_id)
        if existing_dev is not None:
            db.delete(existing_dev)
        dev = DeviceConfig(
            device_id=dev_id,
            user_id=acct.id,
            name="retention-audit",
            payload={},
        )
        db.add(dev)
        db.commit()

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/retention/device",
        data={
            "_csrf": csrf,
            "device_id": dev_id,
            "keep_last_n_auto": "12",
            "auto_expire_days": "",
            "keep_labeled_forever": "1",
        },
    )
    assert r.status_code in (200, 303)
    add_evt = _latest_event("retention.device_override_added")
    assert add_evt is not None
    assert add_evt.resource_id == dev_id
    assert (add_evt.detail or {}).get("keep_last_n_auto") == 12

    r2 = admin_client.post(
        f"/admin/retention/device/{dev_id}/delete",
        data={"_csrf": csrf},
    )
    assert r2.status_code in (200, 303)
    rm_evt = _latest_event("retention.device_override_removed")
    assert rm_evt is not None
    assert rm_evt.resource_id == dev_id
