"""CSRF protection for the admin UI — double-submit cookie pattern.

On every request from an authenticated admin user we set a cookie named
``nks_wdc_csrf`` containing a random 32-byte token. Every admin-panel
HTML form embeds this same value in a hidden ``_csrf`` input. The server
compares the two on every mutating POST; mismatch → 403.

The value is rotated per session boundary (or whenever the cookie is
absent / expired) via ``ensure_csrf_cookie``. Tests and API clients
that never render HTML forms are unaffected because the JSON endpoints
under ``/api/v1/*`` use their own JWT / session guards.
"""

from __future__ import annotations

import secrets
from typing import Annotated, Optional

from fastapi import Cookie, Form, HTTPException, Request, status
from fastapi.responses import Response


CSRF_COOKIE = "nks_wdc_csrf"
CSRF_FORM_FIELD = "_csrf"
CSRF_MAX_AGE = 60 * 60 * 12  # 12 hours


def ensure_csrf_cookie(response: Response, existing: Optional[str]) -> str:
    """Return the active CSRF token, issuing a fresh one when absent.

    Callers must pass the response object they're about to return so we
    can attach the Set-Cookie header. The token is not signed — it's an
    unguessable random string whose security comes from the same-origin
    cookie policy (browser won't send cross-site), not cryptography.
    """
    from .main import _cookie_secure  # late import avoids circular dep
    token = existing if existing and len(existing) >= 32 else secrets.token_urlsafe(32)
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        max_age=CSRF_MAX_AGE,
        httponly=False,  # templates read the cookie to populate form fields
        samesite="strict",
        secure=_cookie_secure(),
    )
    return token


def require_csrf(
    request: Request,
    token: Annotated[Optional[str], Form(alias=CSRF_FORM_FIELD)] = None,
    cookie: Annotated[Optional[str], Cookie(alias=CSRF_COOKIE)] = None,
) -> None:
    """FastAPI dependency — raises 403 unless form and cookie values match.

    Skips enforcement for non-mutating methods (GET/HEAD/OPTIONS) and when
    the request has no session cookie (the upstream auth layer already
    bounces anonymous callers). Safe to attach to every ``/admin/*``
    route regardless of HTTP verb.
    """
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return
    if not cookie or not token or not secrets.compare_digest(cookie, token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token invalid",
        )


__all__ = [
    "CSRF_COOKIE",
    "CSRF_FORM_FIELD",
    "CSRF_MAX_AGE",
    "ensure_csrf_cookie",
    "require_csrf",
]
