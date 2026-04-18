"""End-to-end tests for the admin-UI TOTP enable/confirm/disable flow."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def admin_client() -> TestClient:
    """Fresh-session admin client per test — TOTP state lives on the
    admin account row and each test either enables or leaves it
    disabled, so isolation matters.

    Resets the admin account's 2FA state BEFORE logging in so the login
    flow never lands on /login/2fa while the test is still setting up.
    """
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

    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


def _csrf(client: TestClient) -> str:
    # Pull a page first so the CSRF cookie exists.
    client.get("/admin/account")
    return client.cookies.get("nks_wdc_csrf") or ""


def _reset_2fa(client: TestClient) -> None:
    """Best-effort: if a prior test left 2FA on, knock it off via DB so
    we don't need a valid code to disable."""
    from app.db import Account, session_factory

    with session_factory() as db:
        from sqlalchemy import select as _sel

        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def test_setup_renders_pairing_block(admin_client: TestClient) -> None:
    _reset_2fa(admin_client)
    csrf = _csrf(admin_client)
    r = admin_client.post("/admin/account/totp/setup", data={"_csrf": csrf})
    assert r.status_code == 200
    assert "otpauth://totp/" in r.text
    assert "Confirm &amp; enable 2FA" in r.text
    # Secret should appear as a base32 string inside a code element.
    assert re.search(r"<code[^>]*>[A-Z2-7]{32}</code>", r.text)


def test_confirm_wrong_code_keeps_pending(admin_client: TestClient) -> None:
    _reset_2fa(admin_client)
    csrf = _csrf(admin_client)
    admin_client.post("/admin/account/totp/setup", data={"_csrf": csrf})

    r = admin_client.post(
        "/admin/account/totp/confirm",
        data={"_csrf": csrf, "code": "000000"},
    )
    assert r.status_code == 200
    assert "didn&#39;t match" in r.text or "didn't match" in r.text
    # Still shows the pairing block → user can retry.
    assert "otpauth://totp/" in r.text


def test_confirm_right_code_enables_and_renders_recovery(
    admin_client: TestClient,
) -> None:
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    _reset_2fa(admin_client)
    csrf = _csrf(admin_client)
    admin_client.post("/admin/account/totp/setup", data={"_csrf": csrf})

    # Pull the pending secret out of the DB and compute the live code.
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        secret = acct.totp_secret
        assert secret and not acct.totp_enabled

    import base64
    import hmac
    import hashlib
    import struct
    import time

    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int(time.time()) // 30
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    word = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    code = f"{word % 10**6:06d}"

    r = admin_client.post(
        "/admin/account/totp/confirm",
        data={"_csrf": csrf, "code": code},
    )
    assert r.status_code == 200
    assert "Recovery codes" in r.text
    # Eight recovery codes, each "xxxxx-xxxxx" from the confusable-free alphabet.
    codes = re.findall(r"\b[a-hjkmnp-z2-9]{5}-[a-hjkmnp-z2-9]{5}\b", r.text)
    assert len(codes) >= 8

    # Row now has enabled=True and hashes stored.
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct.totp_enabled is True
        assert acct.totp_enabled_at is not None
        assert acct.totp_recovery_hashes is not None
        assert len(acct.totp_recovery_hashes.splitlines()) == 8


def test_disable_requires_valid_code(admin_client: TestClient) -> None:
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    _reset_2fa(admin_client)
    csrf = _csrf(admin_client)

    # Manually set up enabled 2FA with a known secret.
    known_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # deterministic
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        acct.totp_secret = known_secret
        acct.totp_enabled = True
        acct.totp_recovery_hashes = ""
        db.commit()

    # Wrong code → stays enabled.
    r = admin_client.post(
        "/admin/account/totp/disable",
        data={"_csrf": csrf, "code": "000000"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct.totp_enabled is True

    # Right code → disabled.
    import base64
    import hmac
    import hashlib
    import struct
    import time

    key = base64.b32decode(known_secret + "=" * (-len(known_secret) % 8))
    counter = int(time.time()) // 30
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    word = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    code = f"{word % 10**6:06d}"

    r = admin_client.post(
        "/admin/account/totp/disable",
        data={"_csrf": csrf, "code": code},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct.totp_enabled is False
        assert acct.totp_secret is None


def test_setup_blocked_when_already_enabled(admin_client: TestClient) -> None:
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    _reset_2fa(admin_client)
    csrf = _csrf(admin_client)
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        acct.totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        acct.totp_enabled = True
        db.commit()

    r = admin_client.post(
        "/admin/account/totp/setup",
        data={"_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Flash carries the error → visible on the next page.
    r2 = admin_client.get("/admin/account")
    assert "already enabled" in r2.text.lower()
    _reset_2fa(admin_client)
