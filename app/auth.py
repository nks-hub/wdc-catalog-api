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
from fastapi import Cookie, HTTPException, status
from itsdangerous import BadSignature, TimestampSigner
from sqlalchemy import select

from .db import User, session_factory

log = logging.getLogger(__name__)

SESSION_COOKIE = "nks_wdc_catalog_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 1 week


_EPHEMERAL_DEV_KEY: str | None = None


def _secret_key() -> str:
    """Resolve the signer key, caching the DEV-mode ephemeral value.

    Callers that issue *and* verify signatures (session cookies, invite
    tokens) both read this — so returning a fresh random key each call
    would corrupt any signed artifact that outlives a single request.
    """
    global _EPHEMERAL_DEV_KEY
    env = os.environ.get("NKS_WDC_SESSION_SECRET") or os.environ.get(
        "NKS_WDC_CATALOG_SECRET"
    )
    if env:
        return env
    if os.environ.get("NKS_WDC_CATALOG_DEV") == "1":
        if _EPHEMERAL_DEV_KEY is None:
            import secrets as _secrets

            _EPHEMERAL_DEV_KEY = _secrets.token_urlsafe(32)
            log.warning(
                "NKS_WDC_CATALOG_DEV=1 → ephemeral session signer "
                "(cookies invalid after restart)"
            )
        return _EPHEMERAL_DEV_KEY
    raise RuntimeError(
        "NKS_WDC_SESSION_SECRET (or legacy NKS_WDC_CATALOG_SECRET) must be set in production. "
        "Set NKS_WDC_CATALOG_DEV=1 for local development."
    )


_signer = TimestampSigner(_secret_key())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode(
        "ascii"
    )


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time password check that never leaks exception details.

    Broad ``except Exception`` deliberately swallows every failure mode
    (malformed hash, encoding errors, upstream library changes) so a
    corrupted row always reads as an auth failure rather than 500.
    """
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except Exception:  # noqa: BLE001
        return False


# Pre-computed dummy hash used by ``verify_dummy_password`` so bcrypt work
# runs even when the account doesn't exist — eliminates the timing side
# channel that would otherwise let an attacker enumerate valid usernames
# by measuring response latency.
_DUMMY_HASH = bcrypt.hashpw(b"nks-wdc-dummy-value-00", bcrypt.gensalt(rounds=12)).decode(
    "ascii"
)


def verify_dummy_password(plain: str) -> bool:
    """Burn ~one bcrypt round so the unknown-user branch matches the
    timing of the real ``verify_password`` call. Always returns ``False``.
    """
    try:
        bcrypt.checkpw(plain.encode("utf-8"), _DUMMY_HASH.encode("ascii"))
    except Exception:  # noqa: BLE001
        pass
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
            log.warning(
                "NKS_WDC_CATALOG_DEV=1 → using fallback admin/admin credentials"
            )
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
