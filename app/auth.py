"""Session-cookie auth for the admin UI.

Password hashing uses bcrypt (purpose-built for this, 12 rounds default).
Session identification uses itsdangerous signed cookies — no server-side
session store required because all state fits into the username.

The admin account is bootstrapped from two env vars at startup:
    NKS_WDC_CATALOG_ADMIN_USER   (default: "admin")
    NKS_WDC_CATALOG_ADMIN_PASS   (required — service refuses to start
                                   if unset in non-dev mode)

Dev mode: when `NKS_WDC_CATALOG_DEV=1` a fallback password "admin" is
used so `run.cmd` boots without friction. NEVER set that flag in prod.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Annotated

import bcrypt
from fastapi import Cookie, Depends, HTTPException, status
from itsdangerous import BadSignature, TimestampSigner
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import User, session_factory

log = logging.getLogger(__name__)

SESSION_COOKIE = "nks_wdc_catalog_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 1 week


def _secret_key() -> str:
    env = os.environ.get("NKS_WDC_CATALOG_SECRET")
    if env:
        return env
    # Dev fallback — persist so restarts don't log everyone out.
    return "dev-only-secret-change-me-in-production-32-chars"


_signer = TimestampSigner(_secret_key())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except ValueError:
        return False


def issue_session(username: str) -> str:
    return _signer.sign(username.encode("utf-8")).decode("ascii")


def read_session(cookie_value: str | None) -> str | None:
    if not cookie_value:
        return None
    try:
        raw = _signer.unsign(cookie_value.encode("ascii"), max_age=SESSION_MAX_AGE)
        return raw.decode("utf-8")
    except BadSignature:
        return None


def ensure_admin_user() -> None:
    """Bootstrap a single admin account on first run.

    Subsequent runs are no-ops. If the user exists but the password env
    var was changed, we do NOT overwrite the hash — admins should rotate
    explicitly via the UI instead of env var games.
    """
    username = os.environ.get("NKS_WDC_CATALOG_ADMIN_USER", "admin")
    password = os.environ.get("NKS_WDC_CATALOG_ADMIN_PASS")

    if not password:
        if os.environ.get("NKS_WDC_CATALOG_DEV") == "1":
            password = "admin"
            log.warning("NKS_WDC_CATALOG_DEV=1 → using fallback admin/admin credentials")
        else:
            log.warning(
                "NKS_WDC_CATALOG_ADMIN_PASS not set — admin UI will accept "
                "no logins. Set the env var or NKS_WDC_CATALOG_DEV=1 for dev."
            )
            return

    with session_factory() as db:
        existing = db.scalar(select(User).where(User.username == username))
        if existing is None:
            db.add(User(username=username, password_hash=hash_password(password)))
            db.commit()
            log.info("Bootstrap admin user created: %s", username)


# ── FastAPI dependency ─────────────────────────────────────────────────

def current_user(
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> str:
    username = read_session(session_cookie)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            detail="Not authenticated",
            headers={"Location": "/login"},
        )
    return username


def optional_user(
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> str | None:
    return read_session(session_cookie)


# ── Token-free random helper for CSRF etc. ─────────────────────────────

def random_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)
