"""Regression tests — every catalog mutation must audit.

Before this suite, someone with admin-UI access could create, edit, or
delete apps / releases / downloads and leave zero trace in the audit
log. Each path now emits a named event; this file locks that in.
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


def test_app_create_edit_delete_audits(admin_client: TestClient) -> None:
    """Full create → edit → delete lifecycle, three audit events."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    app_id = "audit-test-app"

    r = admin_client.post(
        "/admin/new",
        data={
            "_csrf": csrf,
            "id": app_id,
            "display_name": "Audit Test App",
            "category": "other",
            "description": "seed",
            "homepage": "",
            "license": "",
        },
    )
    assert r.status_code in (200, 303)
    evt = _latest("app.created")
    assert evt is not None and evt.resource_id == app_id
    assert (evt.detail or {}).get("display_name") == "Audit Test App"

    # Edit (changes display_name + description).
    r = admin_client.post(
        f"/admin/apps/{app_id}/edit",
        data={
            "_csrf": csrf,
            "display_name": "Audit Test App v2",
            "category": "other",
            "description": "edited",
            "homepage": "",
            "license": "",
        },
    )
    assert r.status_code in (200, 303)
    evt2 = _latest("app.updated")
    assert evt2 is not None and evt2.resource_id == app_id
    changed = (evt2.detail or {}).get("changed", {})
    assert "display_name" in changed
    assert changed["display_name"]["to"] == "Audit Test App v2"

    # Delete.
    r = admin_client.post(f"/admin/apps/{app_id}/delete", data={"_csrf": csrf})
    assert r.status_code in (200, 303)
    evt3 = _latest("app.deleted")
    assert evt3 is not None and evt3.resource_id == app_id


def test_release_and_download_audits(admin_client: TestClient) -> None:
    """release.created + download.added + download.deleted + release.deleted."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    app_id = "audit-rel-app"

    # Seed an app to hang releases off.
    admin_client.post(
        "/admin/new",
        data={
            "_csrf": csrf,
            "id": app_id,
            "display_name": "Rel App",
            "category": "other",
        },
    )
    r = admin_client.post(
        f"/admin/apps/{app_id}/releases",
        data={"_csrf": csrf, "version": "1.2.3", "channel": "stable"},
    )
    assert r.status_code in (200, 303)
    evt = _latest("release.created")
    assert evt is not None
    release_id = int(evt.resource_id)
    assert (evt.detail or {}).get("version") == "1.2.3"

    # Add a download against the release we just minted.
    r = admin_client.post(
        f"/admin/releases/{release_id}/downloads",
        data={
            "_csrf": csrf,
            "url": "https://example.com/app-1.2.3-x64.zip",
            "os": "windows",
            "arch": "x64",
            "archive_type": "zip",
            "source": "manual",
        },
    )
    assert r.status_code in (200, 303)
    dl_evt = _latest("download.added")
    assert dl_evt is not None
    dl_id = int(dl_evt.resource_id)

    # Delete download.
    r = admin_client.post(f"/admin/downloads/{dl_id}/delete", data={"_csrf": csrf})
    assert r.status_code in (200, 303)
    rm_dl = _latest("download.deleted")
    assert rm_dl is not None and rm_dl.resource_id == str(dl_id)

    # Delete release.
    r = admin_client.post(f"/admin/releases/{release_id}/delete", data={"_csrf": csrf})
    assert r.status_code in (200, 303)
    rm_rel = _latest("release.deleted")
    assert rm_rel is not None and rm_rel.resource_id == str(release_id)

    # Clean up.
    admin_client.post(f"/admin/apps/{app_id}/delete", data={"_csrf": csrf})


def test_password_change_audit(admin_client: TestClient) -> None:
    """Both the happy path and the bad-current-password path audit."""
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""

    # Wrong current password → change_failed.
    r = admin_client.post(
        "/admin/account/password",
        data={
            "_csrf": csrf,
            "current_password": "definitely-wrong",
            "new_password": "super-strong-password-12345",
            "new_password_confirm": "super-strong-password-12345",
        },
    )
    assert r.status_code in (200, 303)
    evt = _latest("password.change_failed")
    assert evt is not None

    # Correct current password → changed (and we flip it back to 'admin'
    # so the fixture keeps working in later tests).
    from app.db import User, session_factory
    from sqlalchemy import select as _sel
    from app.auth import hash_password

    r = admin_client.post(
        "/admin/account/password",
        data={
            "_csrf": csrf,
            "current_password": "admin",
            "new_password": "super-strong-password-12345",
            "new_password_confirm": "super-strong-password-12345",
        },
    )
    assert r.status_code in (200, 303)
    evt2 = _latest("password.changed")
    assert evt2 is not None

    # Flip back so DEV admin/admin fixture still works next run.
    with session_factory() as db:
        u = db.scalar(_sel(User).where(User.username == "admin"))
        if u is not None:
            u.password_hash = hash_password("admin")
            db.commit()


def test_device_delete_audits(admin_client: TestClient) -> None:
    """Provision a device directly, then delete via the admin UI."""
    from app.db import Account, DeviceConfig, session_factory
    from sqlalchemy import select as _sel

    dev_id = "audit-delete-device-test-id"
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        # Wipe any prior.
        old = db.get(DeviceConfig, dev_id)
        if old is not None:
            db.delete(old)
            db.commit()
        dev = DeviceConfig(
            device_id=dev_id,
            user_id=acct.id,
            name="audit-delete",
            payload={},
        )
        db.add(dev)
        db.commit()

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(f"/admin/devices/{dev_id}/delete", data={"_csrf": csrf})
    assert r.status_code in (200, 303)
    evt = _latest("device.deleted")
    assert evt is not None and evt.resource_id == dev_id
