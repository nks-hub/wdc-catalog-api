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
# Reduced from 7 days → 24 hours. Admin sessions are interactive; a
# week-long cookie gives a stolen copy far too long to be useful.
# Operators who want shorter / longer windows can override via env.
SESSION_MAX_AGE = int(os.environ.get("NKS_WDC_SESSION_MAX_AGE", 60 * 60 * 24))
# Idle-timeout ceiling: when the cookie's signed timestamp shows the
# session hasn't been active for this long, treat it as expired even
# if the absolute ``max_age`` window hasn't elapsed. Re-signing on
# every request (see ``refresh_session``) keeps live sessions alive
# without extending the dormant ones.
SESSION_IDLE_TIMEOUT = int(os.environ.get("NKS_WDC_SESSION_IDLE_TIMEOUT", 60 * 60 * 2))


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


# Bcrypt work factor. 12 rounds ≈ 250 ms on a modern CPU and follows
# OWASP's 2024 baseline. Operators on beefier hardware can raise it via
# ``NKS_WDC_BCRYPT_ROUNDS`` — doubling cost for every +1. Clamp between
# 10 (a bit lax, but useful in tests) and 14 (≈ 2 s / hash, upper edge of
# interactive-tolerable).
BCRYPT_ROUNDS = max(10, min(14, int(os.environ.get("NKS_WDC_BCRYPT_ROUNDS", "12"))))


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")


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
# by measuring response latency. Must match the real cost factor so the
# timing alignment holds across ``NKS_WDC_BCRYPT_ROUNDS`` overrides.
_DUMMY_HASH = bcrypt.hashpw(
    b"nks-wdc-dummy-value-00", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
).decode("ascii")


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
    # Enforce the tighter of (absolute max-age, idle timeout). A fresh
    # cookie re-signed on each request keeps ``idle_timeout`` forgiving
    # for active users; forgotten tabs expire on the shorter window.
    effective = min(SESSION_MAX_AGE, SESSION_IDLE_TIMEOUT)
    try:
        raw = _signer.unsign(cookie_value.encode("ascii"), max_age=effective)
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
