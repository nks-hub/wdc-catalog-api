"""Admin-UI auth endpoints — ``/``, ``/login``, ``/logout``.

The JSON auth flow (``/api/v1/auth/login`` etc.) lives in ``devices.py``;
this module handles only the cookie-session HTML entry points that the
admin panel relies on.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    issue_session,
    optional_user,
    verify_dummy_password,
    verify_password,
)
from .cookies import cookie_secure
from .csrf import require_csrf
from .db import User, get_session
from .ratelimit import limiter
from .templating import base_context, templates


router = APIRouter(include_in_schema=False)


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
    token = issue_session(user.username)
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


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


__all__ = ["router"]
