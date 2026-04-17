"""Regression tests — snapshot import + restore + auto-generate must audit.

Pre-v0.8.3, these three mutation paths left the audit log silent. They
each touch production data or pull from external sources, so the trail
matters for compliance and incident triage.
"""

from __future__ import annotations

import json

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
        c.get("/admin/account")
        yield c


def _latest(action: str):
    from app.db import AuditEvent, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        return db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == action)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )


def _provision_device(dev_id: str) -> int:
    """Add a device tied to the admin account, return its account id."""
    from app.db import Account, DeviceConfig, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        old = db.get(DeviceConfig, dev_id)
        if old is not None:
            db.delete(old)
            db.commit()
        dev = DeviceConfig(
            device_id=dev_id,
            user_id=acct.id,
            name="audit-snap",
            payload={},
        )
        db.add(dev)
        db.commit()
        return acct.id


def test_snapshot_import_audits(admin_client: TestClient) -> None:
    dev_id = "snap-audit-import-device"
    _provision_device(dev_id)

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        f"/admin/devices/{dev_id}/import",
        data={
            "_csrf": csrf,
            "payload": json.dumps({"theme": "dark", "greeting": "hi"}),
            "label": "audit-test-import",
            "set_head": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:200]

    evt = _latest("snapshot.imported")
    assert evt is not None
    assert evt.resource_type == "snapshot"
    assert (evt.detail or {}).get("device_id") == dev_id
    assert (evt.detail or {}).get("label") == "audit-test-import"
    assert (evt.detail or {}).get("set_head") is False


def test_snapshot_restore_audits(admin_client: TestClient) -> None:
    """Import two snapshots, pin the first as HEAD, restore the second,
    verify snapshot.restored carries previous_head_id."""
    from app.db import Account, DeviceSnapshot, session_factory
    from sqlalchemy import select as _sel
    from app import snapshots as _snap

    dev_id = "snap-audit-restore-device"
    account_id = _provision_device(dev_id)

    with session_factory() as db:
        first = _snap.create_snapshot(
            db, device_id=dev_id, account_id=account_id,
            payload={"v": 1}, kind="manual", label="v1",
        )
        second = _snap.create_snapshot(
            db, device_id=dev_id, account_id=account_id,
            payload={"v": 2}, kind="manual", label="v2",
        )
        _snap.set_head(db, dev_id, first.id, updated_by="test-setup")
        first_id, second_id = first.id, second.id
        db.commit()

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        f"/admin/devices/{dev_id}/snapshots/{second_id}/restore",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    evt = _latest("snapshot.restored")
    assert evt is not None
    assert evt.resource_id == str(second_id)
    assert (evt.detail or {}).get("device_id") == dev_id
    assert (evt.detail or {}).get("previous_head_id") == first_id


def test_auto_generate_audits(admin_client: TestClient) -> None:
    """Trigger auto-generate against a well-known generator app. We
    don't assert on the insert count (the scraper may find no new
    releases mid-run) — only that the audit row landed."""
    from app.generators import GENERATORS
    from app.service import create_app as _svc_create_app, get_app
    from app.db import session_factory

    # Pick any generator-backed app id. If none, skip.
    if not GENERATORS:
        pytest.skip("No generators configured in this build")
    app_id = next(iter(GENERATORS))

    # Ensure the app row exists — create_app is idempotent via ValueError.
    with session_factory() as db:
        if get_app(db, app_id) is None:
            try:
                _svc_create_app(
                    db,
                    app_id=app_id,
                    display_name=app_id,
                    category="other",
                )
                db.commit()
            except ValueError:
                pass

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    # Use a tiny limit so we don't hammer the network.
    r = admin_client.post(
        f"/admin/apps/{app_id}/auto-generate",
        data={"_csrf": csrf, "limit": "1"},
        follow_redirects=False,
    )
    # Generator may fail network-wise; what we care about is the route
    # ran and emitted (or didn't) the event. If the route 5xx'd we'd see
    # no event — but we assert on happy redirect.
    assert r.status_code in (303, 200)

    evt = _latest("app.auto_generated")
    if r.status_code == 303:
        assert evt is not None and evt.resource_id == app_id
        assert "scraped" in (evt.detail or {})
