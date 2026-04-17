"""HTML admin UI — catalog editing + release/download management.

Session-cookie authenticated (``/login`` flow, see ``api_auth_ui``).
Flash cookies are signed with the session secret so another cookie
writer can't inject messages into rendered pages.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Form,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from .auth import current_user
from .cookies import cookie_secure
from .csrf import require_csrf
from .db import get_session
from .generators import GENERATORS, run_generator
from .service import (
    add_download,
    add_release,
    apply_generated_releases,
    create_app as svc_create_app,
    delete_app as svc_delete_app,
    delete_download,
    delete_release,
    get_app,
    list_apps,
    update_app,
)
from .templating import base_context, templates


router = APIRouter(include_in_schema=False)


# ── Flash-cookie helpers ──────────────────────────────────────────────


def _flash_signer():
    """Reuse the session signer secret so flash cookies share a single
    rotation key. ``max_age`` on the caller side enforces the 15 s TTL.
    """
    from itsdangerous import TimestampSigner

    from .auth import _secret_key

    return TimestampSigner(_secret_key(), salt="nks-wdc-flash-v1")


def _redirect(
    url: str, flash_kind: str | None = None, flash_message: str | None = None
) -> RedirectResponse:
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    if flash_kind and flash_message:
        # Signed cookie — a MITM or another cookie writer (same-site
        # subdomain) can't inject messages that would render into the
        # admin HTML. HttpOnly still prevents JS tampering; the
        # signature prevents everything else.
        signed = _flash_signer().sign(f"{flash_kind}|{flash_message}".encode("utf-8"))
        response.set_cookie(
            "flash",
            signed.decode("ascii"),
            max_age=15,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(),
        )
    return response


def _pop_flash(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    from itsdangerous import BadSignature, SignatureExpired

    try:
        raw = _flash_signer().unsign(cookie.encode("ascii"), max_age=30).decode("utf-8")
    except (BadSignature, SignatureExpired, UnicodeDecodeError):
        # Legacy unsigned cookies written before the signing change —
        # accept once so the rollout doesn't eat flashes mid-deploy.
        if "|" in cookie:
            raw = cookie
        else:
            return None
    if "|" not in raw:
        return None
    kind, _, message = raw.partition("|")
    return {"kind": kind, "message": message}


def _clear_flash(response) -> None:
    response.delete_cookie("flash")


# ── Routes ────────────────────────────────────────────────────────────


@router.get("/admin/catalog", response_class=HTMLResponse)
def admin_catalog_index(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    apps = list_apps(db)
    response = templates.TemplateResponse(
        request,
        "apps_list.html",
        base_context(request, username, apps=apps, flash=_pop_flash(flash)),
    )
    _clear_flash(response)
    return response


@router.get("/admin/new", response_class=HTMLResponse)
def admin_new_app(
    request: Request,
    username: Annotated[str, Depends(current_user)],
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "app_form.html",
        base_context(request, username, app=None),
    )


@router.post("/admin/new", dependencies=[Depends(require_csrf)])
def admin_create_app(
    username: Annotated[str, Depends(current_user)],
    id: Annotated[str, Form()],
    display_name: Annotated[str, Form()] = "",
    category: Annotated[str, Form()] = "other",
    description: Annotated[str, Form()] = "",
    homepage: Annotated[str, Form()] = "",
    license: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    try:
        app_row = svc_create_app(
            db,
            app_id=id,
            display_name=display_name,
            category=category,
            description=description,
            homepage=homepage or None,
            license=license or None,
        )
    except ValueError as exc:
        return _redirect("/admin/new", "error", str(exc))
    return _redirect(f"/admin/apps/{app_row.id}", "success", f"Created {app_row.id}")


@router.get("/admin/apps/{app_id}", response_class=HTMLResponse)
def admin_app_detail(
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    app_row = get_app(db, app_id)
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    response = templates.TemplateResponse(
        request,
        "app_detail.html",
        base_context(
            request,
            username,
            app=app_row,
            has_generator=app_id.lower() in GENERATORS,
            flash=_pop_flash(flash),
        ),
    )
    _clear_flash(response)
    return response


@router.get("/admin/apps/{app_id}/edit", response_class=HTMLResponse)
def admin_edit_app(
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    app_row = get_app(db, app_id)
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    return templates.TemplateResponse(
        request,
        "app_form.html",
        base_context(request, username, app=app_row),
    )


@router.post("/admin/apps/{app_id}/edit", dependencies=[Depends(require_csrf)])
def admin_save_app(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    display_name: Annotated[str, Form()] = "",
    category: Annotated[str, Form()] = "other",
    description: Annotated[str, Form()] = "",
    homepage: Annotated[str, Form()] = "",
    license: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    app_row = update_app(
        db,
        app_id,
        display_name=display_name,
        category=category,
        description=description,
        homepage=homepage,
        license=license,
    )
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    return _redirect(f"/admin/apps/{app_row.id}", "success", "Saved")


@router.post("/admin/apps/{app_id}/delete", dependencies=[Depends(require_csrf)])
def admin_delete_app(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    svc_delete_app(db, app_id)
    return _redirect("/admin", "success", f"Deleted {app_id}")


@router.post("/admin/apps/{app_id}/releases", dependencies=[Depends(require_csrf)])
def admin_add_release(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    version: Annotated[str, Form()],
    channel: Annotated[str, Form()] = "stable",
    released_at: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    rel = add_release(
        db,
        app_id,
        version,
        channel=channel,
        released_at=released_at or None,
    )
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    return _redirect(f"/admin/apps/{app_id}", "success", f"Added {version}")


@router.post(
    "/admin/releases/{release_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_release(
    release_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Release as ReleaseModel

    rel = db.get(ReleaseModel, release_id)
    app_id = rel.app_id if rel else None
    delete_release(db, release_id)
    return _redirect(
        f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Release removed"
    )


@router.post(
    "/admin/releases/{release_id}/downloads", dependencies=[Depends(require_csrf)]
)
def admin_add_download(
    release_id: int,
    username: Annotated[str, Depends(current_user)],
    url: Annotated[str, Form()],
    os: Annotated[str, Form()] = "windows",
    arch: Annotated[str, Form()] = "x64",
    archive_type: Annotated[str, Form()] = "zip",
    source: Annotated[str, Form()] = "manual",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Release as ReleaseModel

    rel = db.get(ReleaseModel, release_id)
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown release")
    add_download(
        db,
        release_id,
        url=url,
        os=os,
        arch=arch,
        archive_type=archive_type,
        source=source,
    )
    return _redirect(f"/admin/apps/{rel.app_id}", "success", "Download added")


@router.post(
    "/admin/downloads/{download_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_download(
    download_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Download as DownloadModel, Release as ReleaseModel

    dl = db.get(DownloadModel, download_id)
    app_id = None
    if dl:
        rel = db.get(ReleaseModel, dl.release_id)
        app_id = rel.app_id if rel else None
    delete_download(db, download_id)
    return _redirect(
        f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Download removed"
    )


@router.post("/admin/apps/{app_id}/auto-generate", dependencies=[Depends(require_csrf)])
def admin_auto_generate(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    limit: Annotated[int, Form()] = 5,
    db: Session = Depends(get_session),
) -> RedirectResponse:
    app_row = get_app(db, app_id)
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    if app_id.lower() not in GENERATORS:
        return _redirect(
            f"/admin/apps/{app_id}", "error", f"No generator for '{app_id}'"
        )
    releases = run_generator(app_id, limit=limit)
    inserted = apply_generated_releases(db, app_id, releases)
    return _redirect(
        f"/admin/apps/{app_id}",
        "success" if inserted else "info",
        f"Auto-generated: {inserted} new release(s) from {len(releases)} scraped",
    )


# ── Dashboard + user management + audit + invites + retention + devices ──
# The HTML admin UI is session-cookie authenticated (``current_user``)
# while the corresponding JSON APIs are JWT + role-gated. To reuse the
# existing service layer without duplicating it, these routes resolve
# the session username back to an ``Account`` row and call the same
# helpers the JSON endpoints use.


def _admin_account(db: Session, username: str):
    """Resolve the admin's Account row (not just User) for role-gated ops.

    The session cookie carries the User.username (admin-UI bootstrap
    identity). For catalog/users/audit work we need a matching Account
    with a role — we auto-provision one on first admin login so the
    "admin" bootstrap user has an upgrade path into the role system.
    """
    from sqlalchemy import select as _sel

    from .db import Account
    from .auth import hash_password

    email = f"{username}@admin.local"
    acct = db.scalar(_sel(Account).where(Account.email == email))
    if acct is None:
        acct = Account(
            email=email,
            password_hash=hash_password("unused-session-only"),
            role="owner",
        )
        db.add(acct)
        db.flush()
    return acct


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Dashboard landing — pulls the same aggregate the /admin/stats JSON
    endpoint returns, rendered into a template."""
    from sqlalchemy import select as _sel

    from .admin_stats import build_overview
    from .db import AuditEvent

    _admin_account(db, username)
    stats = build_overview(db)  # reuses the cached aggregate

    # Recent audit events — 10 most recent, rendered compact under the
    # stats cards so operators spot admin ops without clicking through.
    recent_rows = db.scalars(
        _sel(AuditEvent)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(10)
    ).all()
    recent_events = [
        {
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "actor_id": r.actor_id,
            "actor_email": r.actor_email,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
        }
        for r in recent_rows
    ]
    ctx = base_context(
        request,
        username,
        stats=stats.model_dump(),
        recent_events=recent_events,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "dashboard.html", ctx)
    _clear_flash(response)
    return response


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users_list(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    q: str = "",
    role: str = "",
    suspended_only: int = 0,
    offset: int = 0,
    limit: int = 50,
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import Account, DeviceConfig, count_query
    from .roles import Role
    from sqlalchemy import func as _func

    stmt = _sel(Account)
    if q:
        stmt = stmt.where(Account.email.like(f"%{q.lower()}%"))
    if role:
        stmt = stmt.where(Account.role == role)
    if suspended_only:
        stmt = stmt.where(Account.suspended_at.is_not(None))
    total = count_query(db, stmt)
    rows = db.scalars(
        stmt.order_by(Account.created_at.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 200)))
    ).all()

    # Batch device-count lookup rather than N+1
    device_counts = dict(
        db.execute(
            _sel(DeviceConfig.user_id, _func.count(DeviceConfig.device_id))
            .where(DeviceConfig.user_id.in_([a.id for a in rows]) if rows else False)
            .group_by(DeviceConfig.user_id)
        ).all()
    )

    users = [
        {
            "id": a.id,
            "email": a.email,
            "role": a.role,
            "suspended": a.suspended_at is not None,
            "last_login_at": a.last_login_at.isoformat() if a.last_login_at else None,
            "device_count": device_counts.get(a.id, 0),
        }
        for a in rows
    ]

    ctx = base_context(
        request,
        username,
        users=users,
        total=total,
        q=q,
        role=role,
        suspended_only=bool(suspended_only),
        offset=offset,
        limit=limit,
        page_has_more=offset + len(rows) < total,
        roles=[r.value for r in Role],
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "users_list.html", ctx)
    _clear_flash(response)
    return response


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(
    request: Request,
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import func as _func, select as _sel

    from .db import Account, DeviceConfig, RevokedToken
    from .roles import Role

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    device_count = (
        db.scalar(
            _sel(_func.count(DeviceConfig.device_id)).where(
                DeviceConfig.user_id == acct.id
            )
        )
        or 0
    )

    # "sessions" here means revoked-token rows — active JWTs are stateless
    revoked = db.scalars(
        _sel(RevokedToken).where(RevokedToken.account_id == acct.id).limit(50)
    ).all()
    sessions = [
        {
            "jti": r.jti,
            "issued_at": None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "revoked": True,
        }
        for r in revoked
    ]

    ctx = base_context(
        request,
        username,
        user={
            "id": acct.id,
            "email": acct.email,
            "role": acct.role,
            "suspended": acct.suspended_at is not None,
            "token_version": acct.token_version,
            "failed_login_count": acct.failed_login_count or 0,
            "locked_until": acct.locked_until.isoformat()
            if acct.locked_until
            else None,
            "created_at": acct.created_at.isoformat() if acct.created_at else None,
            "last_login_at": acct.last_login_at.isoformat()
            if acct.last_login_at
            else None,
            "device_count": device_count,
        },
        sessions=sessions,
        new_password=None,
        roles=[r.value for r in Role],
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "user_detail.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/users/{user_id}/role", dependencies=[Depends(require_csrf)])
def admin_change_role(
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    role: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Account
    from .roles import Role

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    try:
        Role(role)
    except ValueError:
        return _redirect(f"/admin/users/{user_id}", "error", f"Unknown role: {role}")
    acct.role = role
    acct.token_version = (acct.token_version or 1) + 1
    from ._cache import invalidate_stats

    invalidate_stats()
    return _redirect(f"/admin/users/{user_id}", "success", f"Role → {role}")


@router.post("/admin/users/{user_id}/suspend", dependencies=[Depends(require_csrf)])
def admin_suspend(
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from datetime import datetime, timezone

    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    acct.suspended_at = datetime.now(timezone.utc)
    acct.token_version = (acct.token_version or 1) + 1
    from ._cache import invalidate_stats

    invalidate_stats()
    return _redirect(f"/admin/users/{user_id}", "success", "Account suspended")


@router.post("/admin/users/{user_id}/resume", dependencies=[Depends(require_csrf)])
def admin_resume(
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    acct.suspended_at = None
    acct.failed_login_count = 0
    acct.locked_until = None
    from ._cache import invalidate_stats

    invalidate_stats()
    return _redirect(f"/admin/users/{user_id}", "success", "Account resumed")


@router.post(
    "/admin/users/{user_id}/reset-password", dependencies=[Depends(require_csrf)]
)
def admin_reset_password(
    request: Request,
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    import secrets as _secrets

    from .auth import hash_password as _hash
    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    new_pw = _secrets.token_urlsafe(18)
    acct.password_hash = _hash(new_pw)
    acct.token_version = (acct.token_version or 1) + 1
    db.flush()
    # Render the detail page directly so the new password is shown once.
    from .roles import Role

    ctx = base_context(
        request,
        username,
        user={
            "id": acct.id,
            "email": acct.email,
            "role": acct.role,
            "suspended": acct.suspended_at is not None,
            "token_version": acct.token_version,
            "failed_login_count": acct.failed_login_count or 0,
            "locked_until": acct.locked_until.isoformat()
            if acct.locked_until
            else None,
            "created_at": acct.created_at.isoformat() if acct.created_at else None,
            "last_login_at": acct.last_login_at.isoformat()
            if acct.last_login_at
            else None,
            "device_count": 0,
        },
        sessions=[],
        new_password=new_pw,
        roles=[r.value for r in Role],
        flash={"kind": "success", "message": "Password reset"},
    )
    return templates.TemplateResponse(request, "user_detail.html", ctx)


@router.post(
    "/admin/users/{user_id}/revoke-tokens", dependencies=[Depends(require_csrf)]
)
def admin_revoke_tokens(
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    acct.token_version = (acct.token_version or 1) + 1
    return _redirect(
        f"/admin/users/{user_id}", "success", "All outstanding tokens invalidated"
    )


@router.post("/admin/users/{user_id}/delete", dependencies=[Depends(require_csrf)])
def admin_delete_user(
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    db.delete(acct)
    from ._cache import invalidate_stats

    invalidate_stats()
    return _redirect("/admin/users", "success", "Account deleted")


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    actor_id: int | None = None,
    offset: int = 0,
    limit: int = 50,
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import AuditEvent, count_query

    stmt = _sel(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)

    total = count_query(db, stmt)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    rows = db.scalars(
        stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    events = [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "actor_id": r.actor_id,
            "actor_email": r.actor_email,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "ip": r.ip,
            "detail": r.detail,
        }
        for r in rows
    ]

    qs_parts = []
    if action:
        qs_parts.append(f"action={action}")
    if resource_type:
        qs_parts.append(f"resource_type={resource_type}")
    if resource_id:
        qs_parts.append(f"resource_id={resource_id}")
    if actor_id:
        qs_parts.append(f"actor_id={actor_id}")
    qs = ("&".join(qs_parts) + "&") if qs_parts else ""

    ctx = base_context(
        request,
        username,
        events=events,
        total=total,
        offset=offset,
        limit=limit,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        qs=qs,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "audit.html", ctx)
    _clear_flash(response)
    return response


@router.get("/admin/invites", response_class=HTMLResponse)
def admin_invites_page(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
) -> HTMLResponse:
    from .roles import Role

    ctx = base_context(
        request,
        username,
        roles=[r.value for r in Role if r != Role.readonly],
        minted=None,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "invites.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/invites", dependencies=[Depends(require_csrf)])
def admin_mint_invite(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    email: Annotated[str, Form()],
    role: Annotated[str, Form()] = "user",
    ttl_hours: Annotated[int, Form()] = 48,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from datetime import datetime, timedelta, timezone
    import uuid as _uuid

    from sqlalchemy import select as _sel

    from .admin_invites import _serializer
    from .db import Account
    from .roles import Role

    try:
        role_enum = Role(role)
    except ValueError:
        ctx = base_context(
            request,
            username,
            roles=[r.value for r in Role if r != Role.readonly],
            minted=None,
            flash={"kind": "error", "message": f"Unknown role: {role}"},
        )
        return templates.TemplateResponse(request, "invites.html", ctx)

    email_n = email.strip().lower()
    if db.scalar(_sel(Account).where(Account.email == email_n)):
        ctx = base_context(
            request,
            username,
            roles=[r.value for r in Role if r != Role.readonly],
            minted=None,
            flash={"kind": "error", "message": "Account already exists"},
        )
        return templates.TemplateResponse(request, "invites.html", ctx)

    expires = datetime.now(timezone.utc) + timedelta(hours=max(1, min(ttl_hours, 168)))
    payload = {
        "email": email_n,
        "role": role_enum.value,
        "nonce": _uuid.uuid4().hex,
        "exp": int(expires.timestamp()),
    }
    token = _serializer().dumps(payload)
    ctx = base_context(
        request,
        username,
        roles=[r.value for r in Role if r != Role.readonly],
        minted={
            "email": email_n,
            "role": role_enum.value,
            "expires_at": expires.isoformat(),
            "token": token,
        },
        flash={"kind": "success", "message": "Invite minted — copy the token now"},
    )
    return templates.TemplateResponse(request, "invites.html", ctx)


@router.get("/admin/retention", response_class=HTMLResponse)
def admin_retention_page(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import DeviceConfig, SnapshotRetentionPolicy

    acct = _admin_account(db, username)
    row = db.scalar(
        _sel(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == acct.id,
            SnapshotRetentionPolicy.device_id.is_(None),
        )
    )
    policy = (
        {
            "keep_last_n_auto": row.keep_last_n_auto,
            "auto_expire_days": row.auto_expire_days,
            "keep_labeled_forever": row.keep_labeled_forever,
        }
        if row is not None
        else None
    )
    device_rows = db.scalars(
        _sel(SnapshotRetentionPolicy)
        .where(
            SnapshotRetentionPolicy.account_id == acct.id,
            SnapshotRetentionPolicy.device_id.is_not(None),
        )
        .order_by(SnapshotRetentionPolicy.device_id)
    ).all()
    device_policies = [
        {
            "device_id": p.device_id,
            "keep_last_n_auto": p.keep_last_n_auto,
            "auto_expire_days": p.auto_expire_days,
            "keep_labeled_forever": p.keep_labeled_forever,
        }
        for p in device_rows
    ]
    # Devices available for new overrides — exclude those already with a policy.
    taken = {p["device_id"] for p in device_policies}
    devices_rows = db.scalars(
        _sel(DeviceConfig)
        .where(DeviceConfig.user_id == acct.id)
        .order_by(DeviceConfig.device_id)
    ).all()
    devices = [
        {"device_id": d.device_id, "name": d.name}
        for d in devices_rows
        if d.device_id not in taken
    ]

    ctx = base_context(
        request,
        username,
        caller_email=acct.email,
        policy=policy,
        device_policies=device_policies,
        devices=devices,
        last_run=None,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "retention.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/retention/device", dependencies=[Depends(require_csrf)])
def admin_add_device_retention(
    username: Annotated[str, Depends(current_user)],
    device_id: Annotated[str, Form()],
    keep_last_n_auto: Annotated[int, Form()] = 30,
    auto_expire_days: Annotated[str, Form()] = "",
    keep_labeled_forever: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from .db import DeviceConfig, SnapshotRetentionPolicy
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        return _redirect(
            "/admin/retention", "error", "Device not found on your account"
        )

    existing = db.scalar(
        _sel(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == acct.id,
            SnapshotRetentionPolicy.device_id == dev_id,
        )
    )
    if existing is not None:
        return _redirect(
            "/admin/retention", "error", f"Override for {dev_id} already exists"
        )

    db.add(
        SnapshotRetentionPolicy(
            account_id=acct.id,
            device_id=dev_id,
            keep_last_n_auto=max(1, min(keep_last_n_auto, 500)),
            auto_expire_days=int(auto_expire_days)
            if auto_expire_days.strip()
            else None,
            keep_labeled_forever=bool(keep_labeled_forever),
        )
    )
    return _redirect("/admin/retention", "success", f"Added override for {dev_id}")


@router.post(
    "/admin/retention/device/{device_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_device_retention(
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from .db import SnapshotRetentionPolicy
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    row = db.scalar(
        _sel(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == acct.id,
            SnapshotRetentionPolicy.device_id == dev_id,
        )
    )
    if row is None:
        return _redirect("/admin/retention", "error", "Override not found")
    db.delete(row)
    return _redirect("/admin/retention", "success", f"Override for {dev_id} removed")


@router.post("/admin/retention/policy", dependencies=[Depends(require_csrf)])
def admin_set_retention_policy(
    username: Annotated[str, Depends(current_user)],
    keep_last_n_auto: Annotated[int, Form()] = 30,
    auto_expire_days: Annotated[str, Form()] = "",
    keep_labeled_forever: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from .db import SnapshotRetentionPolicy

    acct = _admin_account(db, username)
    row = db.scalar(
        _sel(SnapshotRetentionPolicy).where(
            SnapshotRetentionPolicy.account_id == acct.id,
            SnapshotRetentionPolicy.device_id.is_(None),
        )
    )
    expire_days = int(auto_expire_days) if auto_expire_days.strip() else None
    keep_labeled = bool(keep_labeled_forever)
    if row is None:
        row = SnapshotRetentionPolicy(
            account_id=acct.id,
            device_id=None,
            keep_last_n_auto=max(1, min(keep_last_n_auto, 500)),
            auto_expire_days=expire_days,
            keep_labeled_forever=keep_labeled,
        )
        db.add(row)
    else:
        row.keep_last_n_auto = max(1, min(keep_last_n_auto, 500))
        row.auto_expire_days = expire_days
        row.keep_labeled_forever = keep_labeled
    return _redirect("/admin/retention", "success", "Policy saved")


@router.post("/admin/retention/run-now", dependencies=[Depends(require_csrf)])
def admin_retention_run_now(
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import retention as _ret

    summary = _ret.run_retention(db)
    msg = (
        f"Retention run: accounts={summary.get('accounts', 0)}, "
        f"deleted={summary.get('deleted', 0)}, "
        f"idempotency_purged={summary.get('idempotency_purged', 0)}, "
        f"revoked_tokens_purged={summary.get('revoked_tokens_purged', 0)}"
    )
    return _redirect("/admin/retention", "success", msg)


@router.get("/admin/devices", response_class=HTMLResponse)
def admin_devices_list(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from datetime import datetime, timezone

    from sqlalchemy import select as _sel

    from .db import DeviceConfig, count_query

    acct = _admin_account(db, username)
    stmt = _sel(DeviceConfig).where(DeviceConfig.user_id == acct.id)
    total = count_query(db, stmt)
    rows = db.scalars(
        stmt.order_by(DeviceConfig.last_seen_at.desc().nullslast()).limit(200)
    ).all()

    now_utc = datetime.now(timezone.utc)

    def _online(dt):
        if dt is None:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now_utc - dt).total_seconds() < 300

    devices = [
        {
            "device_id": d.device_id,
            "name": d.name,
            "os": d.os,
            "arch": d.arch,
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            "site_count": d.site_count,
            "online": _online(d.last_seen_at),
        }
        for d in rows
    ]
    ctx = base_context(
        request,
        username,
        devices=devices,
        total=total,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "devices.html", ctx)
    _clear_flash(response)
    return response


@router.get("/admin/devices/{device_id}/snapshots", response_class=HTMLResponse)
def admin_device_snapshots(
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    kind: str = "",
    label_like: str = "",
    offset: int = 0,
    limit: int = 50,
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from . import snapshots as _snap
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    rows, total = _snap.list_snapshots(
        db,
        device_id=dev_id,
        account_id=acct.id,
        kind=kind or None,
        label_like=label_like or None,
        offset=offset,
        limit=limit,
    )
    head = _snap.get_head(db, dev_id)
    head_view = (
        {
            "id": head.id,
            "created_at": head.created_at.isoformat() if head.created_at else "",
        }
        if head
        else None
    )
    snapshots_view = [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "kind": r.kind,
            "label": r.label,
            "size_bytes": r.size_bytes,
            "checksum": r.checksum or "",
        }
        for r in rows
    ]
    ctx = base_context(
        request,
        username,
        device_id=dev_id,
        snapshots=snapshots_view,
        head=head_view,
        total=total,
        offset=offset,
        limit=limit,
        kind=kind,
        label_like=label_like,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "device_snapshots.html", ctx)
    _clear_flash(response)
    return response


@router.post(
    "/admin/devices/{device_id}/snapshots/{snapshot_id:int}/restore",
    dependencies=[Depends(require_csrf)],
)
def admin_restore_snapshot(
    device_id: str,
    snapshot_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import snapshots as _snap
    from .db import DeviceSnapshot
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    target = db.get(DeviceSnapshot, snapshot_id)
    if target is None or target.device_id != dev_id or target.account_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    current = _snap.get_head(db, dev_id)
    if current is not None and current.id != target.id:
        _snap.create_snapshot(
            db,
            device_id=dev_id,
            account_id=acct.id,
            payload=_snap.unpack_payload(current, db=db),
            kind="pre_restore",
            label=f"pre-restore-to-#{target.id}",
        )
    _snap.set_head(db, dev_id, target.id, updated_by="admin-ui")
    return _redirect(
        f"/admin/devices/{dev_id}/snapshots",
        "success",
        f"Restored #{snapshot_id} as HEAD",
    )


# ── Snapshot detail (payload + diff vs HEAD) ─────────────────────────


@router.get(
    "/admin/devices/{device_id}/snapshots/{snapshot_id:int}",
    response_class=HTMLResponse,
)
def admin_snapshot_detail(
    request: Request,
    device_id: str,
    snapshot_id: int,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    import json as _json

    from . import snapshots as _snap
    from .db import DeviceSnapshot
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    snap = db.get(DeviceSnapshot, snapshot_id)
    if snap is None or snap.device_id != dev_id or snap.account_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")

    head = _snap.get_head(db, dev_id)
    is_head = head is not None and head.id == snap.id

    payload_json = None
    payload_error = None
    diff_patch = None
    diff_patch_text = None
    try:
        payload = _snap.unpack_payload(snap, db=db)
        payload_json = _json.dumps(
            payload, indent=2, sort_keys=True, ensure_ascii=False
        )
        if head is not None and head.id != snap.id:
            try:
                diff_patch = _snap.diff(snap, head, db=db)
                diff_patch_text = _json.dumps(
                    diff_patch, indent=2, sort_keys=True, ensure_ascii=False
                )
            except Exception as exc:  # noqa: BLE001
                diff_patch = []
                diff_patch_text = f"diff failed: {exc}"
    except PermissionError as exc:
        payload_error = (
            f"Passphrase-encrypted; can't show payload ({exc}). "
            "Use the API with X-WDC-Passphrase to decrypt."
        )
    except Exception as exc:  # noqa: BLE001
        payload_error = f"Failed to unpack payload: {exc}"

    ctx = base_context(
        request,
        username,
        snapshot={
            "id": snap.id,
            "device_id": snap.device_id,
            "created_at": snap.created_at.isoformat() if snap.created_at else "",
            "kind": snap.kind,
            "label": snap.label,
            "size_bytes": snap.size_bytes,
            "checksum": snap.checksum or "",
            "compression": snap.compression,
            "encryption_kid": snap.encryption_kid,
            "parent_snapshot_id": snap.parent_snapshot_id,
        },
        is_head=is_head,
        payload_json=payload_json,
        payload_error=payload_error,
        diff_patch=diff_patch,
        diff_patch_text=diff_patch_text,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "snapshot_detail.html", ctx)
    _clear_flash(response)
    return response


# ── Global settings (GlobalPolicy singleton) ────────────────────────


@router.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from .db import GlobalPolicy
    from .roles import Role

    row = db.get(GlobalPolicy, 1)
    if row is None:
        # Seed the singleton so the form has something to render against.
        row = GlobalPolicy(id=1)
        db.add(row)
        db.flush()
    ctx = base_context(
        request,
        username,
        policy={
            "snapshot_keep_last_n": row.snapshot_keep_last_n,
            "snapshot_retain_days": row.snapshot_retain_days,
            "max_bytes_per_user": row.max_bytes_per_user,
            "registration_enabled": row.registration_enabled,
            "default_role": row.default_role,
            "banner_message": row.banner_message,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by_email": row.updated_by_email,
        },
        roles=[r.value for r in Role],
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "settings.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/settings", dependencies=[Depends(require_csrf)])
def admin_save_settings(
    username: Annotated[str, Depends(current_user)],
    snapshot_keep_last_n: Annotated[int, Form()] = 30,
    snapshot_retain_days: Annotated[int, Form()] = 90,
    max_bytes_per_user: Annotated[str, Form()] = "",
    registration_enabled: Annotated[str, Form()] = "",
    default_role: Annotated[str, Form()] = "user",
    banner_message: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import GlobalPolicy
    from .roles import Role

    try:
        Role(default_role)
    except ValueError:
        return _redirect("/admin/settings", "error", f"Unknown role: {default_role}")

    row = db.get(GlobalPolicy, 1)
    if row is None:
        row = GlobalPolicy(id=1)
        db.add(row)

    row.snapshot_keep_last_n = max(1, min(int(snapshot_keep_last_n), 500))
    row.snapshot_retain_days = max(1, min(int(snapshot_retain_days), 3650))
    row.max_bytes_per_user = (
        int(max_bytes_per_user) if max_bytes_per_user.strip() else None
    )
    row.registration_enabled = bool(registration_enabled)
    row.default_role = default_role
    row.banner_message = banner_message.strip() or None
    row.updated_by_email = f"{username}@admin.local"

    return _redirect("/admin/settings", "success", "Settings saved")


# ── Invite history (consumed) ────────────────────────────────────────


@router.get("/admin/invites/history", response_class=HTMLResponse)
def admin_invites_history(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import ConsumedInvite, count_query

    stmt = _sel(ConsumedInvite)
    total = count_query(db, stmt)
    rows = db.scalars(stmt.order_by(ConsumedInvite.consumed_at.desc()).limit(200)).all()
    consumed = [
        {
            "nonce": r.nonce,
            "email": r.email,
            "consumed_at": r.consumed_at.isoformat() if r.consumed_at else "",
            "account_id": r.account_id,
        }
        for r in rows
    ]
    ctx = base_context(
        request,
        username,
        consumed=consumed,
        total=total,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "invites_history.html", ctx)
    _clear_flash(response)
    return response


# ── Backup import (paste-JSON → create snapshot) ─────────────────────


@router.get("/admin/devices/{device_id}/import", response_class=HTMLResponse)
def admin_device_import_form(
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    # Ensure the device belongs to the admin's account — otherwise 404.
    from .db import DeviceConfig

    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    ctx = base_context(request, username, device_id=dev_id, flash=_pop_flash(flash))
    response = templates.TemplateResponse(request, "device_import.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/devices/{device_id}/import", dependencies=[Depends(require_csrf)])
def admin_device_import(
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    payload: Annotated[str, Form()],
    label: Annotated[str, Form()] = "",
    set_head: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    import json as _json

    from . import snapshots as _snap
    from .db import DeviceConfig
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")

    try:
        raw = _json.loads(payload)
    except _json.JSONDecodeError as exc:
        return _redirect(
            f"/admin/devices/{dev_id}/import", "error", f"Invalid JSON: {exc}"
        )

    # Accept either a bare config dict or the wrapped envelope shape
    # produced by the download endpoint.
    if isinstance(raw, dict) and raw.get("schema") == "nks-wdc-snapshot-v1":
        config = raw.get("payload", {})
        default_label = (
            label.strip()
            or f"imported-from-{raw.get('device_id', 'unknown')}-#{raw.get('id', '?')}"
        )
    else:
        config = raw
        default_label = label.strip() or "imported-snapshot"

    if not isinstance(config, dict):
        return _redirect(
            f"/admin/devices/{dev_id}/import",
            "error",
            "Payload must be a JSON object.",
        )

    try:
        snap = _snap.create_snapshot(
            db,
            device_id=dev_id,
            account_id=acct.id,
            payload=config,
            kind="import",
            label=default_label,
        )
    except _snap.PayloadTooLarge as exc:
        return _redirect(f"/admin/devices/{dev_id}/import", "error", str(exc))

    if set_head:
        _snap.set_head(db, dev_id, snap.id, updated_by="admin-ui-import")

    return _redirect(
        f"/admin/devices/{dev_id}/snapshots",
        "success",
        f"Imported #{snap.id} ({default_label})",
    )


# ── Snapshot compare (diff between any two) ─────────────────────────


@router.get("/admin/devices/{device_id}/snapshots/compare", response_class=HTMLResponse)
def admin_snapshot_compare(
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    a: int | None = None,
    b: int | None = None,
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Render a diff between any two snapshots on this device.

    Complements the single-snapshot view (which diffs against HEAD only)
    — use this to inspect what changed between e.g. snapshot #42 and
    snapshot #50 without bouncing HEAD around.
    """
    import json as _json

    from . import snapshots as _snap
    from .db import DeviceSnapshot
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)

    rows, _ = _snap.list_snapshots(
        db, device_id=dev_id, account_id=acct.id, offset=0, limit=200
    )
    choices = [
        {
            "id": s.id,
            "kind": s.kind,
            "label": s.label,
            "created_at": s.created_at.isoformat() if s.created_at else "",
        }
        for s in rows
    ]

    diff_text = None
    op_count = 0
    error = None
    if a and b:
        if a == b:
            error = "Pick two different snapshots."
        else:
            snap_a = db.get(DeviceSnapshot, a)
            snap_b = db.get(DeviceSnapshot, b)
            if (
                snap_a is None
                or snap_b is None
                or snap_a.device_id != dev_id
                or snap_b.device_id != dev_id
                or snap_a.account_id != acct.id
                or snap_b.account_id != acct.id
            ):
                error = "Snapshot not found on this device."
            else:
                try:
                    patch = _snap.diff(snap_a, snap_b, db=db)
                    op_count = len(patch)
                    diff_text = _json.dumps(
                        patch, indent=2, sort_keys=True, ensure_ascii=False
                    )
                except PermissionError:
                    error = "Can't diff — one of the snapshots is passphrase-encrypted."
                except Exception as exc:  # noqa: BLE001
                    error = f"Diff failed: {exc}"

    ctx = base_context(
        request,
        username,
        device_id=dev_id,
        choices=choices,
        a_id=a,
        b_id=b,
        diff_text=diff_text,
        op_count=op_count,
        error=error,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "snapshot_compare.html", ctx)
    _clear_flash(response)
    return response


# ── Revoked-tokens viewer ───────────────────────────────────────────


@router.get("/admin/revoked-tokens", response_class=HTMLResponse)
def admin_revoked_tokens(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    reason: str = "",
    account_id: int | None = None,
    offset: int = 0,
    limit: int = 50,
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Browse the JWT denylist.

    Operators hit this after a mass-revoke event (account suspend, admin
    panic button) to confirm the expected rows landed. Filters match the
    columns so ``reason=logout`` or ``account_id=7`` narrow by cause.
    """
    from sqlalchemy import select as _sel

    from .db import RevokedToken, count_query

    stmt = _sel(RevokedToken)
    if reason:
        stmt = stmt.where(RevokedToken.reason == reason)
    if account_id:
        stmt = stmt.where(RevokedToken.account_id == account_id)
    total = count_query(db, stmt)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    rows = db.scalars(
        stmt.order_by(RevokedToken.revoked_at.desc()).offset(offset).limit(limit)
    ).all()
    rows_view = [
        {
            "jti": r.jti,
            "account_id": r.account_id,
            "reason": r.reason,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else "",
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        }
        for r in rows
    ]
    qs_parts = []
    if reason:
        qs_parts.append(f"reason={reason}")
    if account_id:
        qs_parts.append(f"account_id={account_id}")
    qs = ("&".join(qs_parts) + "&") if qs_parts else ""

    ctx = base_context(
        request,
        username,
        rows=rows_view,
        total=total,
        offset=offset,
        limit=limit,
        reason=reason,
        account_id=account_id,
        qs=qs,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "revoked_tokens.html", ctx)
    _clear_flash(response)
    return response


# ── Device snapshot ZIP export ──────────────────────────────────────


@router.get("/admin/devices/{device_id}/snapshots/export.zip")
def admin_device_snapshots_export(
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
):
    """Bundle every snapshot for a device into a single ZIP download.

    Each snapshot lands as ``<id>-<kind>-<label>.json`` inside the archive
    with the same envelope shape used by ``GET /backups/{id}/download``
    so a re-import flows through ``/admin/devices/{id}/import`` cleanly.
    """
    import io
    import json as _json
    import zipfile

    from fastapi.responses import StreamingResponse

    from . import snapshots as _snap
    from .db import DeviceConfig
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")

    # Stream everything into an in-memory buffer. Per-device snapshot
    # counts are bounded by the retention policy so this is cheaper than
    # wiring a streaming ZIP generator for zero operator benefit.
    rows, _ = _snap.list_snapshots(
        db, device_id=dev_id, account_id=acct.id, offset=0, limit=10_000
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for s in rows:
            try:
                payload = _snap.unpack_payload(s, db=db)
            except PermissionError:
                # Variant-B encrypted without passphrase — skip rather
                # than failing the whole export.
                continue
            envelope = {
                "schema": "nks-wdc-snapshot-v1",
                "id": s.id,
                "device_id": s.device_id,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "label": s.label,
                "kind": s.kind,
                "checksum": s.checksum,
                "payload": payload,
            }
            safe_label = (s.label or "unlabeled").replace("/", "_")[:40]
            name = f"{s.id:06d}-{s.kind}-{safe_label}.json"
            zf.writestr(name, _json.dumps(envelope, indent=2, ensure_ascii=False))

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{dev_id}-snapshots.zip"'
        },
    )


# ── Audit CSV export ─────────────────────────────────────────────────


@router.get("/admin/audit.csv")
def admin_audit_csv(
    username: Annotated[str, Depends(current_user)],
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    actor_id: int | None = None,
    limit: int = 10000,
    db: Session = Depends(get_session),
):
    """Stream the filtered audit log as CSV.

    Matches the filter surface of the HTML view so the same query params
    copy-paste cleanly between URLs. Hard caps at 10k rows to keep
    ``StreamingResponse`` from holding the DB connection open past a
    reasonable export window — deeper exports should use the JSON API
    with pagination.
    """
    import csv
    import io

    from fastapi.responses import StreamingResponse
    from sqlalchemy import select as _sel

    from .db import AuditEvent

    stmt = _sel(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)

    rows = db.scalars(
        stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(
            max(1, min(limit, 10000))
        )
    ).all()

    def _iter():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "id",
                "created_at",
                "actor_id",
                "actor_email",
                "action",
                "resource_type",
                "resource_id",
                "ip",
                "user_agent",
                "detail",
            ]
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        import json as _json

        for r in rows:
            writer.writerow(
                [
                    r.id,
                    r.created_at.isoformat() if r.created_at else "",
                    r.actor_id or "",
                    r.actor_email or "",
                    r.action or "",
                    r.resource_type or "",
                    r.resource_id or "",
                    r.ip or "",
                    r.user_agent or "",
                    _json.dumps(r.detail, ensure_ascii=False) if r.detail else "",
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    filename = "audit.csv"
    return StreamingResponse(
        _iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Device detail view ──────────────────────────────────────────────


@router.get("/admin/devices/{device_id}", response_class=HTMLResponse)
def admin_device_detail(
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    import json as _json
    from datetime import datetime, timezone

    from . import snapshots as _snap
    from .db import DeviceConfig
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")

    now_utc = datetime.now(timezone.utc)
    last_seen = dev.last_seen_at
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    online = bool(last_seen and (now_utc - last_seen).total_seconds() < 300)

    head = _snap.get_head(db, dev_id)
    _, snap_total = _snap.list_snapshots(
        db, device_id=dev_id, account_id=acct.id, offset=0, limit=1
    )

    payload_pretty = (
        _json.dumps(dev.payload, indent=2, sort_keys=True, ensure_ascii=False)
        if dev.payload
        else None
    )

    ctx = base_context(
        request,
        username,
        device={
            "device_id": dev.device_id,
            "name": dev.name,
            "os": dev.os,
            "arch": dev.arch,
            "site_count": dev.site_count,
            "last_seen_at": dev.last_seen_at.isoformat() if dev.last_seen_at else None,
            "updated_at": dev.updated_at.isoformat() if dev.updated_at else None,
            "online": online,
        },
        payload_pretty=payload_pretty,
        head=(
            {
                "id": head.id,
                "created_at": head.created_at.isoformat() if head.created_at else "",
            }
            if head
            else None
        ),
        snapshot_count=snap_total,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "device_detail.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/devices/{device_id}/delete", dependencies=[Depends(require_csrf)])
def admin_device_delete(
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import DeviceConfig
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    db.delete(dev)
    return _redirect("/admin/devices", "success", f"Device {dev_id} deleted")


# ── Theme toggle (cookie, cycles auto→light→dark→auto) ──────────────


@router.post("/admin/theme", dependencies=[Depends(require_csrf)])
def admin_toggle_theme(
    username: Annotated[str, Depends(current_user)],
    next: Annotated[str, Form()] = "/admin",
    current_theme: Annotated[str | None, Cookie(alias="nks_wdc_theme")] = None,
) -> RedirectResponse:
    """Cycle between auto (no cookie) → light → dark → auto.

    Cookie-driven override of ``prefers-color-scheme`` so the choice
    sticks across reloads. Redirects back to ``next`` so the URL in the
    address bar doesn't change when the user hits the button.
    """
    next_target = next if next.startswith("/admin") or next == "/" else "/admin"
    response = RedirectResponse(next_target, status_code=status.HTTP_303_SEE_OTHER)
    if current_theme == "light":
        response.set_cookie(
            "nks_wdc_theme",
            "dark",
            max_age=60 * 60 * 24 * 365,
            httponly=False,
            samesite="lax",
            secure=cookie_secure(),
        )
    elif current_theme == "dark":
        response.delete_cookie("nks_wdc_theme")
    else:
        response.set_cookie(
            "nks_wdc_theme",
            "light",
            max_age=60 * 60 * 24 * 365,
            httponly=False,
            samesite="lax",
            secure=cookie_secure(),
        )
    return response


# ── Self-service account page ────────────────────────────────────────


@router.get("/admin/account", response_class=HTMLResponse)
def admin_account(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import User

    user = db.scalar(_sel(User).where(User.username == username))
    ctx = base_context(
        request,
        username,
        user_id=user.id if user else "—",
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "account.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/account/password", dependencies=[Depends(require_csrf)])
def admin_change_own_password(
    username: Annotated[str, Depends(current_user)],
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from .auth import hash_password as _hash
    from .auth import verify_password as _verify
    from .db import User

    user = db.scalar(_sel(User).where(User.username == username))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if not _verify(current_password, user.password_hash):
        return _redirect("/admin/account", "error", "Current password is wrong")
    if new_password != new_password_confirm:
        return _redirect("/admin/account", "error", "New passwords don't match")
    if len(new_password) < 12:
        return _redirect(
            "/admin/account", "error", "New password must be at least 12 characters"
        )
    user.password_hash = _hash(new_password)
    return _redirect("/admin/account", "success", "Password updated")


__all__ = ["router"]
