"""End-to-end tests for the saved-audit-query CRUD + sidebar render."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    """Fresh admin session + clear saved queries so tests are isolated."""
    with TestClient(app) as c:
        # App startup has run create_all by now, so DB helpers are safe.
        from app.db import Account, SavedAuditQuery, session_factory
        from sqlalchemy import select as _sel

        # Strip any TOTP state first so the login path doesn't detour.
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

        # Wipe any pre-existing saved queries so test ordering doesn't matter.
        with session_factory() as db:
            acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
            if acct is not None:
                for row in db.scalars(
                    _sel(SavedAuditQuery).where(SavedAuditQuery.account_id == acct.id)
                ).all():
                    db.delete(row)
                db.commit()

        yield c


def _csrf(client: TestClient) -> str:
    client.get("/admin/audit")
    return client.cookies.get("nks_wdc_csrf") or ""


def test_save_filter_persists(admin_client: TestClient) -> None:
    csrf = _csrf(admin_client)
    r = admin_client.post(
        "/admin/audit/save",
        data={
            "_csrf": csrf,
            "name": "Suspensions",
            "action": "user.suspended",
            "resource_type": "",
            "resource_id": "",
            "actor_id": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Redirect back to the filtered view.
    assert "action=user.suspended" in r.headers["location"]

    # Sidebar now renders the saved row.
    r2 = admin_client.get("/admin/audit")
    assert "Suspensions" in r2.text
    assert 'class="saved-query' in r2.text


def test_save_requires_name(admin_client: TestClient) -> None:
    csrf = _csrf(admin_client)
    r = admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "   ", "action": "user.suspended"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/audit"
    r2 = admin_client.get("/admin/audit")
    assert "Name is required" in r2.text


def test_save_rejects_non_numeric_actor(admin_client: TestClient) -> None:
    csrf = _csrf(admin_client)
    r = admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "Bad", "actor_id": "abc"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    r2 = admin_client.get("/admin/audit")
    assert "Actor ID must be a number" in r2.text


def test_save_upserts_on_same_name(admin_client: TestClient) -> None:
    from app.db import Account, SavedAuditQuery, session_factory
    from sqlalchemy import select as _sel

    csrf = _csrf(admin_client)
    admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "Restores", "action": "backup.restored"},
    )
    # Second save with same name but different filter overwrites.
    admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "Restores", "action": "snapshot.restored"},
    )
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        rows = db.scalars(
            _sel(SavedAuditQuery)
            .where(SavedAuditQuery.account_id == acct.id)
            .where(SavedAuditQuery.name == "Restores")
        ).all()
    assert len(rows) == 1
    assert rows[0].action == "snapshot.restored"


def test_saved_query_active_class_when_url_matches(admin_client: TestClient) -> None:
    csrf = _csrf(admin_client)
    admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "RBAC", "action": "permission.denied"},
    )
    # Hit the same filter → sidebar row should carry saved-query-active.
    r = admin_client.get("/admin/audit?action=permission.denied")
    assert "saved-query-active" in r.text


def test_delete_saved_filter(admin_client: TestClient) -> None:
    from app.db import Account, SavedAuditQuery, session_factory
    from sqlalchemy import select as _sel

    csrf = _csrf(admin_client)
    admin_client.post(
        "/admin/audit/save",
        data={"_csrf": csrf, "name": "Temporary", "action": "permission.denied"},
    )
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        row = db.scalar(
            _sel(SavedAuditQuery).where(
                SavedAuditQuery.account_id == acct.id,
                SavedAuditQuery.name == "Temporary",
            )
        )
    assert row is not None

    r = admin_client.post(
        f"/admin/audit/saved/{row.id}/delete",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        row = db.scalar(
            _sel(SavedAuditQuery).where(
                SavedAuditQuery.account_id == acct.id,
                SavedAuditQuery.name == "Temporary",
            )
        )
    assert row is None


def test_delete_other_users_saved_filter_404s(admin_client: TestClient) -> None:
    """Account scoping — we can't delete another account's saved filter."""
    from app.db import Account, SavedAuditQuery, session_factory
    from app.auth import hash_password

    with session_factory() as db:
        other = Account(
            email="someone-else@admin.local",
            password_hash=hash_password("unused"),
            role="user",
        )
        db.add(other)
        db.flush()
        foreign = SavedAuditQuery(
            account_id=other.id,
            name="Not yours",
            action="user.suspended",
        )
        db.add(foreign)
        db.commit()
        foreign_id = foreign.id

    csrf = _csrf(admin_client)
    r = admin_client.post(
        f"/admin/audit/saved/{foreign_id}/delete",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Row must still exist.
    with session_factory() as db:
        still = db.get(SavedAuditQuery, foreign_id)
    assert still is not None


def test_sidebar_hidden_when_no_filter_and_no_saved(admin_client: TestClient) -> None:
    r = admin_client.get("/admin/audit")
    # Save-filter form only appears when a filter is active.
    assert "Save filter" not in r.text
    # Saved-filters block only appears when saved_queries non-empty.
    assert "Saved filters" not in r.text
