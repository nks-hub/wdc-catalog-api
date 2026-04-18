"""Tests for GlobalPolicy.admin_ip_allowlist — admin-UI IP gate (v0.32.0)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


# ── Helpers ──────────────────────────────────────────────────────────────


def _set_allowlist(value: list[str] | None) -> None:
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        policy = db.get(GlobalPolicy, 1)
        if policy is None:
            policy = GlobalPolicy(id=1)
            db.add(policy)
        policy.admin_ip_allowlist = value
        db.commit()


# ── Autouse teardown — CRITICAL ──────────────────────────────────────────
# Leaked allowlist would block every subsequent admin-UI test in the suite.


@pytest.fixture(autouse=True)
def _clear_allowlist():
    yield
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        policy = db.get(GlobalPolicy, 1)
        if policy is not None:
            policy.admin_ip_allowlist = None
            db.commit()


# ── Admin client fixture ─────────────────────────────────────────────────


@pytest.fixture()
def admin_client():
    """Authenticated admin TestClient (127.0.0.1 as client IP)."""
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


# ── Tests ────────────────────────────────────────────────────────────────


def test_no_allowlist_admin_can_reach_admin_pages(admin_client: TestClient) -> None:
    """None / unset allowlist → admin page returns 200."""
    _set_allowlist(None)
    r = admin_client.get("/admin", follow_redirects=False)
    assert r.status_code == 200


def test_matching_cidr_allows_admin_access(admin_client: TestClient) -> None:
    """127.0.0.1 is inside 127.0.0.0/8 → 200."""
    _set_allowlist(["127.0.0.0/8"])
    r = admin_client.get("/admin", follow_redirects=False)
    assert r.status_code == 200


def test_non_matching_cidr_redirects_to_login() -> None:
    """10.0.0.0/8 does not contain 127.0.0.1 → 302 to /login."""
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        # Login before setting the non-matching allowlist.
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303

        _set_allowlist(["10.0.0.0/8"])
        r = c.get("/admin", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers.get("location", "")


def test_malformed_cidrs_all_fail_closed() -> None:
    """All-malformed CIDR list → no valid CIDR matches → 302."""
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303

        _set_allowlist(["bogus", "also-bad"])
        r = c.get("/admin", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers.get("location", "")


def test_settings_save_persists_allowlist(admin_client: TestClient) -> None:
    """POST /admin/settings with admin_ip_allowlist_raw persists the list + audits."""
    from app.db import AuditEvent, GlobalPolicy, session_factory
    from sqlalchemy import select as _sel

    # Ensure allowlist is None before save.
    _set_allowlist(None)

    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post(
        "/admin/settings",
        data={
            "_csrf": csrf,
            "snapshot_keep_last_n": "30",
            "snapshot_retain_days": "90",
            "max_bytes_per_user": "",
            "registration_enabled": "1",
            "default_role": "user",
            "banner_message": "",
            "require_2fa_for_admins": "",
            "admin_ip_allowlist_raw": "127.0.0.0/8\n10.0.0.0/8",
        },
        follow_redirects=False,
    )
    assert r.status_code in (200, 303)

    # Verify DB row — do NOT re-hit HTTP after the allowlist is set.
    with session_factory() as db:
        policy = db.get(GlobalPolicy, 1)
        assert policy is not None
        assert policy.admin_ip_allowlist == ["127.0.0.0/8", "10.0.0.0/8"]

    # Verify settings.updated audit diff contains admin_ip_allowlist.
    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "settings.updated")
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    changed = (evt.detail or {}).get("changed", {})
    assert "admin_ip_allowlist" in changed
    assert changed["admin_ip_allowlist"]["to"] == ["127.0.0.0/8", "10.0.0.0/8"]


def test_login_page_accessible_regardless_of_allowlist() -> None:
    """Non-matching allowlist does not block the /login route (outside admin router)."""
    _set_allowlist(["10.0.0.0/8"])
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        r = c.get("/login", follow_redirects=False)
        assert r.status_code == 200
