"""Admin-UI auth endpoints — ``/``, ``/login``, ``/login/2fa``, ``/logout``.

The JSON auth flow (``/api/v1/auth/login`` etc.) lives in ``devices.py``;
this module handles only the cookie-session HTML entry points that the
admin panel relies on.
"""

from __future__ import annotations

import base64
import urllib.parse
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
        return (
            _pending_signer().unsign(signed, max_age=_PENDING_MAX_AGE).decode("utf-8")
        )
    except (BadSignature, SignatureExpired, ValueError, UnicodeDecodeError):
        return None


def _paired_account(db: Session, username: str) -> Account | None:
    """Return the Account row that backs this admin-UI username.

    F91.17: mirrors ``admin_ui._admin_account`` lookup order. Prefers the
    SSO-provisioned real-email row over the legacy ``{username}@admin.local``
    placeholder so both admin-panel and WDC-desktop flows land on the
    same Account.
    """
    legacy_email = f"{username}@admin.local"
    acct = db.scalar(
        select(Account)
        .where(Account.email.like(f"{username}@%"))
        .where(Account.email != legacy_email)
    )
    if acct is not None:
        return acct
    return db.scalar(select(Account).where(Account.email == legacy_email))


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

    if (
        code_clean.replace(" ", "").replace("-", "").isdigit()
        and len(code_clean.replace(" ", "").replace("-", "")) == _totp.TOTP_DIGITS
    ):
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


# --- SSO (Authentik) ---------------------------------------------------
#
# OIDC authorization-code flow with PKCE. Enabled only when SSO env
# vars are set; see app/sso.py. The state cookie is the CSRF
# equivalent so these routes do NOT require ``require_csrf`` — doing so
# would break a cross-site redirect from the IdP.


@router.get("/auth/sso/login")
def auth_sso_login(request: Request, redirect_uri: str = "") -> RedirectResponse:
    """Kick off the SSO flow.

    An optional ``redirect_uri`` query parameter is accepted ONLY when it
    matches the WDC desktop deep-link (``wdc://auth-callback``). Anything
    else is ignored and the default ``/admin`` return target is used —
    this prevents the endpoint from being abused as an open redirector
    into arbitrary schemes.
    """
    from . import sso as _sso

    if not _sso.sso_enabled():
        # Feature flag off — return 404 rather than 501 so a probe
        # can't enumerate the endpoint's existence.
        from fastapi import HTTPException

        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    # F83: strict allowlist for external redirect targets. The WDC
    # desktop app registers wdc:// as a custom protocol and passes a
    # redirect_uri of exactly this string so catalog-api can hand the
    # session token back to the running desktop window at callback time.
    return_to = redirect_uri if redirect_uri == "wdc://auth-callback" else "/admin"

    response = RedirectResponse("about:blank", status_code=status.HTTP_302_FOUND)
    url = _sso.build_authorize_url(request, response, return_to=return_to)
    response.headers["Location"] = url
    return response


@router.get("/auth/sso/callback")
def auth_sso_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    sso_state: Annotated[str | None, Cookie(alias="nks_wdc_sso_state")] = None,
    db: Session = Depends(get_session),
):
    """IdP redirect handler — exchange code, upsert local User, mint
    session, redirect to /admin. Local TOTP is bypassed (SSO is
    MFA-backed upstream)."""
    from fastapi import HTTPException

    import bcrypt as _bcrypt
    import re as _re
    import secrets as _secrets

    from . import audit as _audit
    from . import sso as _sso

    if not _sso.sso_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    if error or not code or not state:
        # Authentik reported an error (consent denied, invalid request,
        # etc.) — redirect back to login with a generic flash rather
        # than leaking IdP-side detail to the user.
        return RedirectResponse(
            "/login?error=sso_failed", status_code=status.HTTP_303_SEE_OTHER
        )

    try:
        claims, return_to = _sso.exchange_code(request, code, state, sso_state)
    except _sso.SSOError:
        return RedirectResponse(
            "/login?error=sso_failed", status_code=status.HTTP_303_SEE_OTHER
        )

    # Map email → local username (lowercase, sanitized local-part).
    local = claims.email.split("@", 1)[0]
    username = _re.sub(r"[^a-zA-Z0-9_.-]+", "", local).lower() or "sso-user"

    # Upsert User. SSO users get an unusable bcrypt hash so local
    # password login is disabled for them.
    user = db.scalar(select(User).where(User.username == username))
    created = False
    if user is None:
        unusable = _bcrypt.hashpw(
            _secrets.token_urlsafe(32).encode(), _bcrypt.gensalt(rounds=4)
        ).decode("ascii")
        user = User(username=username, password_hash=unusable)
        db.add(user)
        db.flush()
        created = True

    # Mirror admin role on the paired Account so the admin-UI's
    # existing role gates work. If the paired account doesn't exist
    # yet, it'll be provisioned on first admin hit — we set the role
    # there, via the Account.role field.
    acct = _paired_account(db, username)
    role = "admin" if _sso.is_admin_group(claims.groups) else "readonly"
    if acct is not None and acct.role != role:
        acct.role = role

    # Audit — new action ``login.sso`` (on the security allowlist so
    # the Prometheus counter picks it up).
    try:
        _audit.emit(
            db,
            request=request,
            actor=None,
            action="login.sso",
            resource_type="user",
            resource_id=str(user.id),
            detail={
                "email": claims.email,
                "groups": claims.groups,
                "issuer": _sso.authority(),
                "created": created,
                "role": role,
            },
        )
    except Exception:  # noqa: BLE001 — audit failure must not block login
        pass

    db.commit()

    token = issue_session(user.username, request=request, db=db)

    # F83/F91.9/F91.13: desktop app callback — WDC stores the token and
    # calls /api/v1/auth/me + /api/v1/devices, both of which require a
    # JWT bound to an Account row. We provision the Account keyed by the
    # REAL SSO email (claims.email) — not the synthetic
    # `{username}@admin.local` the admin UI uses — so `/auth/me` returns
    # the user's actual identity and the UI can show
    # "Signed in as user@nks-hub.cz" instead of "user@admin.local".
    # Catalog is a redirector around Authentik; the Account is a thin
    # local projection of the SSO identity for /devices + /auth/me.
    if return_to == "wdc://auth-callback":
        import datetime as _dt
        import logging as _logging
        from .auth import hash_password as _hash_pw
        from .devices import create_token as _mint_jwt

        _log_wdc = _logging.getLogger("app.sso.wdc")

        sso_email = (claims.email or "").strip().lower()
        _log_wdc.info(
            "WDC SSO callback: claims.email=%r groups=%r return_to=%r",
            claims.email, claims.groups, return_to,
        )
        if not sso_email:
            _log_wdc.warning("WDC SSO: missing email claim — rejecting")
            return RedirectResponse(
                "/login?error=sso_failed", status_code=status.HTTP_303_SEE_OTHER
            )

        try:
            acct = db.scalar(select(Account).where(Account.email == sso_email))
            if acct is None:
                acct = Account(
                    email=sso_email,
                    password_hash=_hash_pw(_secrets.token_urlsafe(32)),
                    role=("admin" if _sso.is_admin_group(claims.groups) else "user"),
                )
                db.add(acct)
                db.flush()
                _log_wdc.info("WDC SSO: provisioned new Account id=%s email=%s", acct.id, acct.email)
            else:
                desired_role = (
                    "admin" if _sso.is_admin_group(claims.groups) else acct.role
                )
                if desired_role and acct.role != desired_role:
                    acct.role = desired_role
                _log_wdc.info("WDC SSO: reusing Account id=%s email=%s role=%s", acct.id, acct.email, acct.role)
            acct.last_login_at = _dt.datetime.now(_dt.timezone.utc)
            db.commit()

            wdc_jwt = _mint_jwt(
                acct.id,
                acct.email,
                token_version=getattr(acct, "token_version", 1) or 1,
            )
            _log_wdc.info("WDC SSO: minted JWT len=%d for account_id=%s", len(wdc_jwt), acct.id)
        except Exception as e:
            # Any DB / JWT failure would otherwise bubble as a 500 and WDC
            # sees no wdc:// redirect at all. Logging + fallback keeps the
            # failure visible instead of silent.
            _log_wdc.exception("WDC SSO: provision/mint failed: %s", e)
            return RedirectResponse(
                "/login?error=sso_failed", status_code=status.HTTP_303_SEE_OTHER
            )

        deep_link = (
            f"wdc://auth-callback?token={urllib.parse.quote(wdc_jwt, safe='')}"
        )
        _log_wdc.info("WDC SSO: redirecting to deep-link (token in URL, len=%d)", len(wdc_jwt))
        response = RedirectResponse(deep_link, status_code=status.HTTP_303_SEE_OTHER)
        _sso.clear_state_cookie(response, secure=request.url.scheme == "https")
        return response

    safe_return = return_to if return_to.startswith("/admin") else "/admin"
    response = RedirectResponse(safe_return, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=cookie_secure(),
    )
    _sso.clear_state_cookie(response, secure=request.url.scheme == "https")
    return response


__all__ = ["router"]
