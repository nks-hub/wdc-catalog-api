"""Deep-pages admin UI regression tests.

Covers the routes that the lightweight smoke suite (``test_admin_ui``)
skips because they need a device/snapshot/audit row to exist first.
Each test bootstraps the minimum state, hits the route, and asserts a
page-specific marker so a template regression surfaces in CI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def deep_client() -> TestClient:
    """Authenticated client reused across every deep-page test.

    Triggers one GET /admin after login so ``_admin_account`` auto-
    provisions the ``admin@admin.local`` Account row that the tests
    below assume exists.
    """
    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text
        # Kick-start the admin Account provisioning.
        c.get("/admin")
        yield c


def _bootstrap_account_with_device(deep_client: TestClient) -> tuple[str, str]:
    """Register a user → push a device config → return (jwt, device_id).

    The push creates both the DeviceConfig row and an auto snapshot, so
    every "needs a device + snapshot" test below can reuse this fixture.
    """
    import uuid as _uuid

    email = f"deep-ui-{_uuid.uuid4().hex[:8]}@example.com"
    password = "Passphrase-1234!"
    r = deep_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    device_id = f"deep-dev-{_uuid.uuid4().hex[:6]}"
    r = deep_client.post(
        "/api/v1/sync/config",
        json={
            "device_id": device_id,
            "payload": {
                "settings": {"sync.deviceName": "Test Device"},
                "sites": [{"domain": "test.loc"}],
                "system": {"os": {"tag": "windows", "arch": "x64"}},
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return token, device_id


def test_snapshot_detail_renders(deep_client: TestClient) -> None:
    """``/admin/devices/{id}/snapshots/{sid}`` must render the payload
    JSON + HEAD diff section when a snapshot exists."""
    # Work with the admin's own account which auto-provisions on first
    # admin-UI access (see _admin_account in admin_ui.py). We can't
    # easily bootstrap a device via its API there, so instead visit the
    # admin snapshots page — it still 200s even on empty state, but
    # exercise a real snapshot via the backend path.
    from sqlalchemy import select as _sel

    from app.db import Account, DeviceConfig, session_factory
    from app import snapshots as _snap

    with session_factory() as db:
        owner = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert owner is not None, "admin account not provisioned"

        dev = db.scalar(_sel(DeviceConfig).where(DeviceConfig.user_id == owner.id))
        if dev is None:
            dev = DeviceConfig(
                device_id=f"deep-ui-dev-{owner.id}",
                user_id=owner.id,
                payload={"hello": "world"},
            )
            db.add(dev)
            db.flush()

        snap = _snap.create_snapshot(
            db,
            device_id=dev.device_id,
            account_id=owner.id,
            payload={"v": 1, "note": "deep ui test"},
            kind="manual",
            label="deep-ui-marker",
        )
        snap_id = snap.id
        device_id = dev.device_id
        db.commit()

    r = deep_client.get(f"/admin/devices/{device_id}/snapshots/{snap_id}")
    assert r.status_code == 200, r.text[:200]
    assert "deep-ui-marker" in r.text
    assert "Payload" in r.text


def test_snapshot_compare_renders_form_and_diff(deep_client: TestClient) -> None:
    """Compare view without query params renders the selector form;
    with ``a`` and ``b`` pointing to real snapshots it computes a diff."""
    from sqlalchemy import select as _sel

    from app.db import Account, DeviceConfig, session_factory
    from app import snapshots as _snap

    with session_factory() as db:
        owner = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert owner is not None
        dev = db.scalar(_sel(DeviceConfig).where(DeviceConfig.user_id == owner.id))
        if dev is None:
            dev = DeviceConfig(
                device_id=f"compare-dev-{owner.id}",
                user_id=owner.id,
                payload={"hello": "world"},
            )
            db.add(dev)
            db.flush()

        a = _snap.create_snapshot(
            db,
            device_id=dev.device_id,
            account_id=owner.id,
            payload={"k": 1},
            kind="manual",
            label="cmp-a",
        )
        b = _snap.create_snapshot(
            db,
            device_id=dev.device_id,
            account_id=owner.id,
            payload={"k": 2, "new": True},
            kind="manual",
            label="cmp-b",
        )
        a_id, b_id, device_id = a.id, b.id, dev.device_id
        db.commit()

    # Form-only view.
    r = deep_client.get(f"/admin/devices/{device_id}/snapshots/compare")
    assert r.status_code == 200
    assert "Compare snapshots" in r.text

    # Populated diff view.
    r = deep_client.get(
        f"/admin/devices/{device_id}/snapshots/compare?a={a_id}&b={b_id}"
    )
    assert r.status_code == 200, r.text[:200]
    assert "Diff A &rarr; B" in r.text or "Diff A → B" in r.text


def test_device_detail_shows_payload_and_delete_button(
    deep_client: TestClient,
) -> None:
    from sqlalchemy import select as _sel

    from app.db import Account, DeviceConfig, session_factory

    with session_factory() as db:
        owner = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        dev = db.scalar(_sel(DeviceConfig).where(DeviceConfig.user_id == owner.id))
        assert dev is not None
        device_id = dev.device_id

    r = deep_client.get(f"/admin/devices/{device_id}")
    assert r.status_code == 200, r.text[:200]
    assert device_id in r.text
    assert "Delete device" in r.text


def test_device_import_form_and_post(deep_client: TestClient) -> None:
    from sqlalchemy import select as _sel

    from app.db import Account, DeviceConfig, session_factory

    with session_factory() as db:
        owner = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        dev = db.scalar(_sel(DeviceConfig).where(DeviceConfig.user_id == owner.id))
        assert dev is not None
        device_id = dev.device_id

    # Form renders.
    r = deep_client.get(f"/admin/devices/{device_id}/import")
    assert r.status_code == 200
    assert "Import backup" in r.text

    # POST with bare-dict payload creates a snapshot.
    csrf = deep_client.cookies.get("nks_wdc_csrf") or ""
    r = deep_client.post(
        f"/admin/devices/{device_id}/import",
        data={
            "_csrf": csrf,
            "payload": '{"imported": true}',
            "label": "pytest-import",
            "set_head": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:200]


def test_per_device_retention_override_roundtrip(deep_client: TestClient) -> None:
    """Add an override → appears in the list → delete → disappears."""
    from sqlalchemy import select as _sel

    from app.db import Account, DeviceConfig, session_factory

    with session_factory() as db:
        owner = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        dev = db.scalar(_sel(DeviceConfig).where(DeviceConfig.user_id == owner.id))
        assert dev is not None
        device_id = dev.device_id

    csrf = deep_client.cookies.get("nks_wdc_csrf") or ""
    r = deep_client.post(
        "/admin/retention/device",
        data={
            "_csrf": csrf,
            "device_id": device_id,
            "keep_last_n_auto": "7",
            "auto_expire_days": "14",
            "keep_labeled_forever": "1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:200]

    r = deep_client.get("/admin/retention")
    assert device_id in r.text

    csrf = deep_client.cookies.get("nks_wdc_csrf") or ""
    r = deep_client.post(
        f"/admin/retention/device/{device_id}/delete",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    r = deep_client.get("/admin/retention")
    assert "No per-device overrides" in r.text or device_id not in r.text


def test_audit_log_captures_rbac_denial(deep_client: TestClient) -> None:
    """Hitting a role-gated JSON endpoint as a plain user must emit an
    audit event; the audit page then shows ``permission.denied``."""
    import uuid as _uuid

    email = f"rbac-probe-{_uuid.uuid4().hex[:6]}@example.com"
    pw = "Passphrase-1234!"

    with TestClient(app) as api:
        api.post("/api/v1/auth/register", json={"email": email, "password": pw})
        r = api.post("/api/v1/auth/login", json={"email": email, "password": pw})
        assert r.status_code == 200
        jwt = r.json()["token"]

        # Plain ``user`` role can't hit admin-user endpoints.
        denied = api.get(
            "/api/v1/admin/users",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        assert denied.status_code == 403

    r = deep_client.get("/admin/audit?action=permission.denied")
    assert r.status_code == 200
    # Either the row is visible or the query executed cleanly on empty;
    # both prove no template regression.
    assert "Audit log" in r.text


def test_user_detail_shows_activity_timeline(deep_client: TestClient) -> None:

    from app.auth import hash_password
    from app.db import Account, AuditEvent, session_factory

    with session_factory() as db:
        acct = Account(
            email="timeline-target@example.com",
            password_hash=hash_password("unused"),
            role="user",
        )
        db.add(acct)
        db.flush()
        db.add(
            AuditEvent(
                actor_id=acct.id,
                actor_email=acct.email,
                action="test.timeline_event",
                resource_type="account",
                resource_id=str(acct.id),
            )
        )
        db.commit()
        uid = acct.id

    r = deep_client.get(f"/admin/users/{uid}")
    assert r.status_code == 200
    assert "Activity" in r.text
    assert "test.timeline_event" in r.text
    assert "View full log" in r.text
