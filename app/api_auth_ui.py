"""Admin-UI auth endpoints — ``/``, ``/login``, ``/login/2fa``, ``/logout``.

The JSON auth flow (``/api/v1/auth/login`` etc.) lives in ``devices.py``;
this module handles only the cookie-session HTML entry points that the
admin panel relies on.
"""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    _secret_key,
    issue_session,
    optional_user,
    verify_dummy_password,
    verify_password,
)
from .cookies import cookie_secure
from .csrf import require_csrf
from .db import Account, User, get_session
from .ratelimit import limiter
from .templating import base_context, templates


router = APIRouter(include_in_schema=False)


# --- 2FA pending-login state --------------------------------------------
#
# After a correct password on a 2FA-enabled account we cannot yet mint
# the session cookie — the second factor is still outstanding. Instead
# we issue a short-lived signed cookie carrying the username so the
# subsequent ``/login/2fa`` POST can pair the code with the right
# account without accepting "which account is this code for" from the
# client. Signed so a stolen cookie can't be forged + time-limited so
# a walked-away browser doesn't leave a half-authenticated session
# waiting for someone to punch in a code.

_PENDING_COOKIE = "nks_wdc_2fa_pending"
_PENDING_MAX_AGE = 5 * 60  # 5 minutes — long enough to pull out a phone


def _pending_signer() -> TimestampSigner:
    return TimestampSigner(_secret_key(), salt="nks-wdc-2fa-pending-v1")


def _issue_pending(username: str) -> str:
    signed = _pending_signer().sign(username.encode("utf-8"))
    return base64.urlsafe_b64encode(signed).decode("ascii")


def _read_pending(cookie: str | None) -> str | None:
    if not cookie:
        return None
    try:
        padded = cookie + "=" * (-len(cookie) % 4)
        signed = base64.urlsafe_b64decode(padded.encode("ascii"))
        return _pending_signer().unsign(signed, max_age=_PENDING_MAX_AGE).decode("utf-8")
    except (BadSignature, SignatureExpired, ValueError, UnicodeDecodeError):
        return None


def _paired_account(db: Session, username: str) -> Account | None:
    """Return the Account row that backs this admin-UI username.

    The admin panel uses ``User`` for session identity and pairs each
    with an ``Account`` at ``{username}@admin.local``. We only need to
    *read* that row for 2FA status here — provisioning happens inside
    admin_ui._admin_account on first authenticated page visit.
    """
    return db.scalar(select(Account).where(Account.email == f"{username}@admin.local"))


# --- routes -------------------------------------------------------------


@router.get("/")
def root(user: Annotated[str | None, Depends(optional_user)] = None):
    return RedirectResponse("/admin" if user else "/login")


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "login.html", base_context(request, None)
    )


@router.post("/login", dependencies=[Depends(require_csrf)])
@limiter.limit("5/minute")
def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Session = Depends(get_session),
):
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None:
        # Burn the same CPU as the valid-account path so the unknown-user
        # branch doesn't leak membership via latency.
        verify_dummy_password(password)
        return templates.TemplateResponse(
            request,
            "login.html",
            base_context(request, None, error="Invalid username or password"),
            status_code=401,
        )
    if not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request,
            "login.html",
            base_context(request, None, error="Invalid username or password"),
            status_code=401,
        )

    # Password was right. If the paired account has 2FA enabled, defer
    # session issuance until the code is verified on /login/2fa.
    acct = _paired_account(db, user.username)
    if acct is not None and acct.totp_enabled and acct.totp_secret:
        pending = _issue_pending(user.username)
        response = RedirectResponse("/login/2fa", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=_PENDING_COOKIE,
            value=pending,
            max_age=_PENDING_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(),
        )
        return response

    token = issue_session(user.username, request=request, db=db)
    response = RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=cookie_secure(),
    )
    return response


@router.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_form(
    request: Request,
    pending: Annotated[str | None, Cookie(alias=_PENDING_COOKIE)] = None,
) -> HTMLResponse:
    username = _read_pending(pending)
    if username is None:
        # No pending login (expired / tampered) → back to the password
        # form. No information leaks here: the user either knows they
        # just typed a password or they don't.
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "login_2fa.html",
        base_context(request, None, pending_user=username),
    )


@router.post("/login/2fa", dependencies=[Depends(require_csrf)])
@limiter.limit("10/minute")
def login_2fa_submit(
    request: Request,
    code: Annotated[str, Form()],
    pending: Annotated[str | None, Cookie(alias=_PENDING_COOKIE)] = None,
    db: Session = Depends(get_session),
):
    import bcrypt as _bcrypt

    from . import audit as _audit
    from . import totp as _totp

    username = _read_pending(pending)
    if username is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    user = db.scalar(select(User).where(User.username == username))
    acct = _paired_account(db, username) if user else None
    if user is None or acct is None or not acct.totp_enabled or not acct.totp_secret:
        # Shouldn't happen via normal flow, but fail safe rather than
        # minting a session if the account state drifted.
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    code_clean = code.strip()
    ok = False
    used_recovery = False
    used_hash: str | None = None

    if code_clean.replace(" ", "").replace("-", "").isdigit() and len(
        code_clean.replace(" ", "").replace("-", "")
    ) == _totp.TOTP_DIGITS:
        ok = _totp.verify(acct.totp_secret, code_clean)
    else:
        norm = _totp.normalize_recovery_code(code_clean)
        for line in (acct.totp_recovery_hashes or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                if _bcrypt.checkpw(norm.encode("utf-8"), line.encode("ascii")):
                    ok = True
                    used_recovery = True
                    used_hash = line
                    break
            except ValueError:
                continue

    if not ok:
        _audit.emit(
            db,
            request=request,
            actor=acct,
            action="totp.login_failed",
            resource_type="account",
            resource_id=str(acct.id),
        )
        return templates.TemplateResponse(
            request,
            "login_2fa.html",
            base_context(
                request,
                None,
                pending_user=username,
                error="Code didn't match. Codes rotate every 30 s.",
            ),
            status_code=401,
        )

    # Burn the recovery code that just got used so it can't replay.
    if used_recovery and used_hash is not None:
        remaining = [
            line.strip()
            for line in (acct.totp_recovery_hashes or "").splitlines()
            if line.strip() and line.strip() != used_hash
        ]
        acct.totp_recovery_hashes = "\n".join(remaining)

    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="totp.login_ok",
        resource_type="account",
        resource_id=str(acct.id),
        detail={"used_recovery": True} if used_recovery else None,
    )

    token = issue_session(user.username, request=request, db=db)
    response = RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=cookie_secure(),
    )
    response.delete_cookie(_PENDING_COOKIE)
    return response


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


__all__ = ["router"]
