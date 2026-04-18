"""PAT hygiene indicator — stale-unused pill on /admin/account.

A PAT with no activity for 30+ days (either last_used_at missing and
created 30+ days ago, or last_used_at older than 30 days) renders an
amber `⚠ unused Nd` pill so operators see forgotten tokens at a glance.
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


def _reset_pats() -> int:
    """Wipe PAT rows, return the admin account id."""
    from app.db import Account, PersonalAccessToken, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct is not None
        for row in db.scalars(
            _sel(PersonalAccessToken).where(PersonalAccessToken.account_id == acct.id)
        ).all():
            db.delete(row)
        db.commit()
        return acct.id


def _insert_pat(
    *, account_id: int, created_days_ago: int, last_used_days_ago: int | None
):
    """Directly insert a PAT row with controlled timestamps (bypasses
    bcrypt to keep the test snappy)."""
    from app.db import PersonalAccessToken, session_factory

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with session_factory() as db:
        row = PersonalAccessToken(
            account_id=account_id,
            name=f"test-{created_days_ago}d",
            token_hash="$2b$04$not-a-real-hash-fine-for-test-fixtures--------------------",
            token_prefix="nks_pat_x",
            created_at=now - timedelta(days=created_days_ago),
            last_used_at=(
                now - timedelta(days=last_used_days_ago)
                if last_used_days_ago is not None
                else None
            ),
            expires_at=None,
            revoked_at=None,
        )
        db.add(row)
        db.commit()


def test_active_recently_used_pat_has_no_stale_pill(admin_client: TestClient) -> None:
    aid = _reset_pats()
    _insert_pat(account_id=aid, created_days_ago=60, last_used_days_ago=5)

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "⚠ unused" not in r.text


def test_never_used_old_pat_shows_stale_pill(admin_client: TestClient) -> None:
    aid = _reset_pats()
    _insert_pat(account_id=aid, created_days_ago=45, last_used_days_ago=None)

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "⚠ unused 45d" in r.text


def test_used_long_ago_pat_shows_stale_pill(admin_client: TestClient) -> None:
    aid = _reset_pats()
    _insert_pat(account_id=aid, created_days_ago=120, last_used_days_ago=90)

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "⚠ unused 90d" in r.text


def test_recently_created_never_used_is_not_stale(admin_client: TestClient) -> None:
    """A brand-new PAT (<30d since creation) with no usage yet isn't
    stale — we don't want to warn about tokens minted this morning."""
    aid = _reset_pats()
    _insert_pat(account_id=aid, created_days_ago=3, last_used_days_ago=None)

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    assert "⚠ unused" not in r.text


def test_revoked_pat_never_flagged_as_stale(admin_client: TestClient) -> None:
    """Revoked tokens shouldn't carry the stale pill — they're already
    effectively gone and the visual noise would distract from real issues."""
    from app.db import PersonalAccessToken, session_factory

    aid = _reset_pats()
    _insert_pat(account_id=aid, created_days_ago=200, last_used_days_ago=None)
    # Mark the row as revoked directly.
    with session_factory() as db:
        row = db.scalars(
            __import__("sqlalchemy")
            .select(PersonalAccessToken)
            .where(PersonalAccessToken.account_id == aid)
        ).first()
        row.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()

    r = admin_client.get("/admin/account")
    assert r.status_code == 200
    # The row rendered with "revoked" pill but NO stale warning.
    assert 'pill pill-suspended">revoked' in r.text
    assert "⚠ unused" not in r.text
