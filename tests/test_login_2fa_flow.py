"""End-to-end tests for the /login → /login/2fa password-then-code flow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


def _code_for(secret: str, at: float | None = None) -> str:
    """Compute the live 6-digit TOTP for a base32 secret."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((at if at is not None else time.time()) // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    word = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    return f"{word % 10**6:06d}"


@pytest.fixture()
def admin_account_with_totp():
    """Prepare the admin@admin.local account with 2FA enabled and a
    known secret. Teardown restores the clean state so later suites
    don't inherit an enabled factor."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    # Paired account only exists after the first admin_ui request; bootstrap
    # it via the admin-UI fixture login first, then flip 2FA on.
    with TestClient(app) as boot:
        boot.get("/login")
        csrf = boot.cookies.get("nks_wdc_csrf") or ""
        boot.post("/login", data={"username": "admin", "password": "admin", "_csrf": csrf})
        boot.get("/admin/account")  # triggers _admin_account provisioning

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert acct is not None
        acct.totp_secret = secret
        acct.totp_enabled = True
        acct.totp_recovery_hashes = ""
        db.commit()

    yield secret

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def test_password_alone_redirects_to_2fa(admin_account_with_totp: str) -> None:
    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        r = c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/login/2fa"
        # Pending cookie is set; session cookie is NOT.
        assert "nks_wdc_2fa_pending" in r.cookies
        # Starlette stores session under SESSION_COOKIE name; verify absent.
        from app.auth import SESSION_COOKIE
        assert SESSION_COOKIE not in r.cookies


def test_2fa_form_renders_when_pending_cookie_set(admin_account_with_totp: str) -> None:
    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        r = c.get("/login/2fa")
        assert r.status_code == 200
        assert "Enter your code" in r.text
        assert "<code>admin</code>" in r.text


def test_2fa_without_pending_cookie_bounces_to_login(admin_account_with_totp: str) -> None:
    with TestClient(app) as c:
        c.get("/login")
        r = c.get("/login/2fa", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"


def test_correct_code_mints_session_cookie(admin_account_with_totp: str) -> None:
    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        code = _code_for(admin_account_with_totp)
        r = c.post(
            "/login/2fa",
            data={"code": code, "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text[:200]
        assert r.headers["location"] == "/admin"
        from app.auth import SESSION_COOKIE
        assert SESSION_COOKIE in r.cookies

        # And the session actually works.
        r2 = c.get("/admin")
        assert r2.status_code == 200


def test_wrong_code_rejects_and_stays_on_2fa(admin_account_with_totp: str) -> None:
    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        r = c.post(
            "/login/2fa",
            data={"code": "000000", "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 401
        assert "Code didn&#39;t match" in r.text or "Code didn't match" in r.text
        from app.auth import SESSION_COOKIE
        assert SESSION_COOKIE not in r.cookies


def test_recovery_code_works_once(admin_account_with_totp: str) -> None:
    import bcrypt as _bcrypt

    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    # Provision a single recovery code so the test is deterministic.
    recovery = "abcde-fghij"
    from app import totp as _totp
    norm = _totp.normalize_recovery_code(recovery)
    hashed = _bcrypt.hashpw(norm.encode("utf-8"), _bcrypt.gensalt(rounds=4)).decode("ascii")
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        acct.totp_recovery_hashes = hashed
        db.commit()

    with TestClient(app) as c:
        c.get("/login")
        csrf = c.cookies.get("nks_wdc_csrf") or ""
        c.post(
            "/login",
            data={"username": "admin", "password": "admin", "_csrf": csrf},
            follow_redirects=False,
        )
        r = c.post(
            "/login/2fa",
            data={"code": recovery, "_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        from app.auth import SESSION_COOKIE
        assert SESSION_COOKIE in r.cookies

    # Recovery code was burned → hashes list is empty.
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        assert (acct.totp_recovery_hashes or "").strip() == ""


def test_password_right_but_account_has_no_totp_skips_2fa():
    """Baseline — accounts without 2FA go straight through like before."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    # Ensure admin has 2FA OFF (fixture for other tests may run in any order).
    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
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
        assert r.headers["location"] == "/admin"
        from app.auth import SESSION_COOKIE
        assert SESSION_COOKIE in r.cookies
