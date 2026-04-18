"""HTML admin UI — catalog editing + release/download management.

Session-cookie authenticated (``/login`` flow, see ``api_auth_ui``).
Flash cookies are signed with the session secret so another cookie
writer can't inject messages into rendered pages.
"""

from __future__ import annotations

import time
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
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from .auth import current_user
from .cookies import cookie_secure
from .csrf import require_csrf
from .db import _engine, get_session
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

_PROCESS_START = time.time()  # captured on first import — used for uptime


def _format_uptime(secs: float) -> str:
    d, rem = divmod(int(secs), 86400)
    h, rem = divmod(rem, 3600)
    m, _s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {_s}s"
    return f"{int(secs)}s"


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


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
        # Flash payloads may include UTF-8 arrows/em-dashes; base64
        # wrap the signed bytes so the cookie value is guaranteed ASCII
        # and no charset surprises leak into Starlette's header encoder.
        import base64 as _b64
        signed = _flash_signer().sign(f"{flash_kind}|{flash_message}".encode("utf-8"))
        response.set_cookie(
            "flash",
            _b64.urlsafe_b64encode(signed).decode("ascii"),
            max_age=15,
            httponly=True,
            samesite="strict",
            secure=cookie_secure(),
        )
    return response


def _pop_flash(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    import base64 as _b64

    from itsdangerous import BadSignature, SignatureExpired

    # Cookie is base64(signed-bytes). Older cookies (pre-b64 wrapping)
    # still round-trip because itsdangerous tolerates trailing = padding
    # and urlsafe alphabet overlaps its own signature alphabet — the
    # decode step just becomes a no-op if the value wasn't base64'd.
    try:
        padded = cookie + "=" * (-len(cookie) % 4)
        signed_bytes = _b64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        signed_bytes = cookie.encode("utf-8", errors="replace")

    try:
        raw = _flash_signer().unsign(signed_bytes, max_age=30).decode("utf-8")
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


def _parse_iso_date(raw: str):
    """Parse YYYY-MM-DD → aware UTC datetime at 00:00. Returns None on empty/invalid."""
    from datetime import datetime, timezone

    if not raw or not raw.strip():
        return None
    try:
        return datetime.strptime(raw.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _invites_history_stmt(stmt, email: str, since: str, until: str):
    """Apply email/date filters to a ConsumedInvite SELECT statement."""
    from datetime import datetime, time, timezone

    from sqlalchemy import select as _sel

    from .db import ConsumedInvite

    if email:
        stmt = stmt.where(ConsumedInvite.email.ilike(f"%{email.strip()}%"))
    since_dt = _parse_iso_date(since)
    if since_dt:
        stmt = stmt.where(ConsumedInvite.consumed_at >= since_dt)
    until_dt = _parse_iso_date(until)
    if until_dt:
        until_dt = datetime.combine(until_dt.date(), time.max).replace(tzinfo=timezone.utc)
        stmt = stmt.where(ConsumedInvite.consumed_at <= until_dt)
    return stmt


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
    request: Request,
    username: Annotated[str, Depends(current_user)],
    id: Annotated[str, Form()],
    display_name: Annotated[str, Form()] = "",
    category: Annotated[str, Form()] = "other",
    description: Annotated[str, Form()] = "",
    homepage: Annotated[str, Form()] = "",
    license: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit

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
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="app.created",
        resource_type="app",
        resource_id=app_row.id,
        detail={
            "display_name": app_row.display_name,
            "category": app_row.category,
        },
    )
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
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    display_name: Annotated[str, Form()] = "",
    category: Annotated[str, Form()] = "other",
    description: Annotated[str, Form()] = "",
    homepage: Annotated[str, Form()] = "",
    license: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit

    before = get_app(db, app_id)
    before_snapshot = (
        {
            "display_name": before.display_name,
            "category": before.category,
            "description": before.description,
            "homepage": before.homepage,
            "license": before.license,
        }
        if before is not None
        else None
    )
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

    after_snapshot = {
        "display_name": app_row.display_name,
        "category": app_row.category,
        "description": app_row.description,
        "homepage": app_row.homepage,
        "license": app_row.license,
    }
    changed = {
        k: {"from": (before_snapshot or {}).get(k), "to": after_snapshot[k]}
        for k in after_snapshot
        if (before_snapshot or {}).get(k) != after_snapshot[k]
    }
    if changed:
        acct = _admin_account(db, username)
        _audit.emit(
            db,
            request=request,
            actor=acct,
            action="app.updated",
            resource_type="app",
            resource_id=app_row.id,
            detail={"changed": changed},
        )
    return _redirect(f"/admin/apps/{app_row.id}", "success", "Saved")


@router.post("/admin/apps/{app_id}/delete", dependencies=[Depends(require_csrf)])
def admin_delete_app(
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit

    before = get_app(db, app_id)
    display_name = before.display_name if before is not None else None
    svc_delete_app(db, app_id)
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="app.deleted",
        resource_type="app",
        resource_id=app_id,
        detail={"display_name": display_name} if display_name else None,
    )
    return _redirect("/admin", "success", f"Deleted {app_id}")


@router.post("/admin/apps/{app_id}/releases", dependencies=[Depends(require_csrf)])
def admin_add_release(
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    version: Annotated[str, Form()],
    channel: Annotated[str, Form()] = "stable",
    released_at: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit

    rel = add_release(
        db,
        app_id,
        version,
        channel=channel,
        released_at=released_at or None,
    )
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="release.created",
        resource_type="release",
        resource_id=str(rel.id),
        detail={"app_id": app_id, "version": version, "channel": channel},
    )
    return _redirect(f"/admin/apps/{app_id}", "success", f"Added {version}")


@router.post(
    "/admin/releases/{release_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_release(
    request: Request,
    release_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from .db import Release as ReleaseModel

    rel = db.get(ReleaseModel, release_id)
    app_id = rel.app_id if rel else None
    version = rel.version if rel else None
    channel = rel.channel if rel else None
    delete_release(db, release_id)
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="release.deleted",
        resource_type="release",
        resource_id=str(release_id),
        detail={"app_id": app_id, "version": version, "channel": channel},
    )
    return _redirect(
        f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Release removed"
    )


@router.post(
    "/admin/releases/{release_id}/downloads", dependencies=[Depends(require_csrf)]
)
def admin_add_download(
    request: Request,
    release_id: int,
    username: Annotated[str, Depends(current_user)],
    url: Annotated[str, Form()],
    os: Annotated[str, Form()] = "windows",
    arch: Annotated[str, Form()] = "x64",
    archive_type: Annotated[str, Form()] = "zip",
    source: Annotated[str, Form()] = "manual",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from .db import Release as ReleaseModel

    rel = db.get(ReleaseModel, release_id)
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown release")
    dl = add_download(
        db,
        release_id,
        url=url,
        os=os,
        arch=arch,
        archive_type=archive_type,
        source=source,
    )
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="download.added",
        resource_type="download",
        resource_id=str(dl.id) if dl is not None else None,
        detail={
            "release_id": release_id,
            "app_id": rel.app_id,
            "version": rel.version,
            "os": os,
            "arch": arch,
            "url": url,
        },
    )
    return _redirect(f"/admin/apps/{rel.app_id}", "success", "Download added")


@router.post(
    "/admin/downloads/{download_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_download(
    request: Request,
    download_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from .db import Download as DownloadModel, Release as ReleaseModel

    dl = db.get(DownloadModel, download_id)
    app_id = None
    detail: dict | None = None
    if dl:
        rel = db.get(ReleaseModel, dl.release_id)
        app_id = rel.app_id if rel else None
        detail = {
            "release_id": dl.release_id,
            "app_id": app_id,
            "version": rel.version if rel else None,
            "os": dl.os,
            "arch": dl.arch,
            "url": dl.url,
        }
    delete_download(db, download_id)
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="download.deleted",
        resource_type="download",
        resource_id=str(download_id),
        detail=detail,
    )
    return _redirect(
        f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Download removed"
    )


@router.post("/admin/apps/{app_id}/auto-generate", dependencies=[Depends(require_csrf)])
def admin_auto_generate(
    request: Request,
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    limit: Annotated[int, Form()] = 5,
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit

    app_row = get_app(db, app_id)
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    if app_id.lower() not in GENERATORS:
        return _redirect(
            f"/admin/apps/{app_id}", "error", f"No generator for '{app_id}'"
        )
    releases = run_generator(app_id, limit=limit)
    inserted = apply_generated_releases(db, app_id, releases)

    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="app.auto_generated",
        resource_type="app",
        resource_id=app_id,
        detail={
            "limit": limit,
            "scraped": len(releases),
            "inserted": inserted,
        },
    )
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


def _audit_filter_stmt(stmt, *, action="", resource_type="", resource_id="", actor_id=None):
    """Apply audit-log filter params to *stmt* and return the modified statement.

    Shared by admin_audit (HTML), admin_audit_csv, and admin_audit_export_jsonl
    so the three handlers can never drift from each other.
    """
    from .db import AuditEvent

    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    return stmt


# Routes the user can reach even while the 2FA-enforcement gate is
# active — without these we'd deadlock a freshly-enrolled admin who
# hasn't paired an authenticator yet.
_TOTP_GATE_ALLOWLIST_PREFIXES = (
    "/admin/account/totp/",   # setup + confirm + disable POST paths
    "/admin/theme",           # theme toggle is pure cosmetics
    "/static/",               # JS + CSS
    "/logout",                # always let the user escape
)
_TOTP_GATE_ALLOWLIST_EXACT = {
    "/admin/account",         # the setup form lives on this page
}


def current_user_with_2fa_gate(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> str:
    """Wraps ``current_user`` with a policy check.

    When ``GlobalPolicy.require_2fa_for_admins`` is True and the
    authenticated admin has no TOTP configured, every request that is
    not on the setup allowlist is bounced to the account page so the
    admin is forced to pair an authenticator before continuing.
    """
    path = request.url.path
    if path in _TOTP_GATE_ALLOWLIST_EXACT:
        return username
    if any(path.startswith(p) for p in _TOTP_GATE_ALLOWLIST_PREFIXES):
        return username

    from .db import GlobalPolicy

    policy = db.get(GlobalPolicy, 1)
    if policy is None or not policy.require_2fa_for_admins:
        return username

    acct = _admin_account(db, username)
    if acct.totp_enabled and acct.totp_secret:
        return username

    raise HTTPException(
        status_code=status.HTTP_302_FOUND,
        detail="2FA required",
        headers={"Location": "/admin/account?flash=totp-required"},
    )


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Dashboard landing — pulls the same aggregate the /admin/stats JSON
    endpoint returns, rendered into a template."""
    from datetime import datetime, timedelta, timezone

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

    # Hourly sparkline of audit events over the last 24h — one bucket
    # per hour, zeros filled in so the SVG renders at constant width.
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    day_ago = now - timedelta(hours=23)
    hourly_rows = db.scalars(
        _sel(AuditEvent).where(AuditEvent.created_at >= day_ago.replace(tzinfo=None))
    ).all()
    buckets = {day_ago + timedelta(hours=i): 0 for i in range(24)}
    for r in hourly_rows:
        if r.created_at is None:
            continue
        dt = r.created_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        key = dt.replace(minute=0, second=0, microsecond=0)
        if key in buckets:
            buckets[key] += 1
    sparkline = [
        {"hour": k.strftime("%H:00"), "count": v} for k, v in sorted(buckets.items())
    ]
    sparkline_max = max((b["count"] for b in sparkline), default=0) or 1
    ctx = base_context(
        request,
        username,
        stats=stats.model_dump(),
        recent_events=recent_events,
        sparkline=sparkline,
        sparkline_max=sparkline_max,
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
    from sqlalchemy import func as _func, or_ as _or_, select as _sel

    from .db import Account, AuditEvent, DeviceConfig, RevokedToken
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

    _events_where = _or_(
        AuditEvent.actor_id == acct.id,
        (AuditEvent.resource_type == "account")
        & (AuditEvent.resource_id == str(acct.id)),
    )
    user_events_total = (
        db.scalar(_sel(_func.count(AuditEvent.id)).where(_events_where)) or 0
    )
    _events_rows = db.scalars(
        _sel(AuditEvent)
        .where(_events_where)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(20)
    ).all()
    user_events = [
        {
            "id": e.id,
            "created_at": e.created_at.isoformat() if e.created_at else "",
            "actor_id": e.actor_id,
            "actor_email": e.actor_email,
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "ip": e.ip,
            "detail": e.detail,
        }
        for e in _events_rows
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
        user_events=user_events,
        user_events_total=user_events_total,
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


@router.post("/admin/users/{user_id}/unlock", dependencies=[Depends(require_csrf)])
def admin_unlock(
    request: Request,
    user_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    """Clear the failed-login counter + lockout timestamp on an account.

    Distinct from ``/resume`` because that only applies to suspensions.
    Lockout is an automatic anti-bruteforce measure from the login path
    (5 failures → 1 min lock, 10 → 5 min, 15 → 30 min) and honest users
    who get stuck in it need an operator to short-circuit the cooldown.
    """
    from . import audit as _audit
    from .db import Account

    acct = db.get(Account, user_id)
    if acct is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    was_locked = acct.locked_until is not None or (acct.failed_login_count or 0) > 0
    acct.failed_login_count = 0
    acct.locked_until = None
    if was_locked:
        try:
            _audit.emit(
                db,
                actor=None,
                action="user.unlocked",
                request=request,
                resource_type="account",
                resource_id=str(acct.id),
                detail={"email": acct.email},
            )
        except Exception:  # noqa: BLE001
            pass
    return _redirect(f"/admin/users/{user_id}", "success", "Lockout cleared")


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


@router.get("/admin/search", response_class=HTMLResponse)
def admin_global_search(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    q: str = "",
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel, or_

    from .db import Account, App, AuditEvent

    q_clean = (q or "").strip()
    users: list[dict] = []
    apps: list[dict] = []
    events: list[dict] = []

    if q_clean:
        like = f"%{q_clean}%"

        user_rows = db.scalars(
            _sel(Account)
            .where(Account.email.ilike(like))
            .order_by(Account.id.asc())
            .limit(10)
        ).all()
        users = [
            {"id": u.id, "email": u.email, "role": u.role,
             "suspended": u.suspended_at is not None}
            for u in user_rows
        ]

        app_rows = db.scalars(
            _sel(App)
            .where(or_(App.id.ilike(like), App.display_name.ilike(like)))
            .order_by(App.id.asc())
            .limit(10)
        ).all()
        apps = [{"id": a.id, "display_name": a.display_name, "category": a.category}
                for a in app_rows]

        evt_rows = db.scalars(
            _sel(AuditEvent)
            .where(or_(
                AuditEvent.action.ilike(like),
                AuditEvent.resource_id.ilike(like),
                AuditEvent.actor_email.ilike(like),
            ))
            .order_by(AuditEvent.id.desc())
            .limit(10)
        ).all()
        events = [
            {
                "id": e.id,
                "created_at": e.created_at.isoformat() if e.created_at else "",
                "action": e.action,
                "actor_email": e.actor_email,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
            }
            for e in evt_rows
        ]

    ctx = base_context(
        request, username,
        q=q_clean,
        users=users,
        apps=apps,
        events=events,
        total=len(users) + len(apps) + len(events),
    )
    return templates.TemplateResponse(request, "search.html", ctx)


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

    stmt = _audit_filter_stmt(
        _sel(AuditEvent),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
    )

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

    # Per-account saved-filter sidebar. Each row renders as a link that
    # reapplies the named filter in a single click.
    from .db import SavedAuditQuery as _SavedQ

    acct = _admin_account(db, username)
    saved_rows = db.scalars(
        _sel(_SavedQ)
        .where(_SavedQ.account_id == acct.id)
        .order_by(_SavedQ.name.asc())
    ).all()

    def _saved_qs(row: _SavedQ) -> str:
        parts: list[str] = []
        if row.action:
            parts.append(f"action={row.action}")
        if row.resource_type:
            parts.append(f"resource_type={row.resource_type}")
        if row.resource_id:
            parts.append(f"resource_id={row.resource_id}")
        if row.actor_id:
            parts.append(f"actor_id={row.actor_id}")
        return "?" + "&".join(parts) if parts else ""

    # Flag the saved row whose params match the current request so the
    # sidebar highlights "you are on this filter right now".
    def _matches(row: _SavedQ) -> bool:
        return (
            (row.action or "") == (action or "")
            and (row.resource_type or "") == (resource_type or "")
            and (row.resource_id or "") == (resource_id or "")
            and (row.actor_id or None) == (actor_id or None)
        )

    saved_queries = [
        {
            "id": r.id,
            "name": r.name,
            "qs": _saved_qs(r),
            "active": _matches(r),
        }
        for r in saved_rows
    ]

    any_filter_active = bool(action or resource_type or resource_id or actor_id)

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
        saved_queries=saved_queries,
        any_filter_active=any_filter_active,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "audit.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/audit/save", dependencies=[Depends(require_csrf)])
def admin_audit_save(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    name: Annotated[str, Form()],
    action: Annotated[str, Form()] = "",
    resource_type: Annotated[str, Form()] = "",
    resource_id: Annotated[str, Form()] = "",
    actor_id: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    """Persist the current query params as a named preset."""
    from sqlalchemy import select as _sel

    from .db import SavedAuditQuery

    clean_name = (name or "").strip()[:64]
    if not clean_name:
        return _redirect("/admin/audit", "error", "Name is required")

    acct = _admin_account(db, username)
    try:
        actor_id_int: int | None = int(actor_id) if (actor_id or "").strip() else None
    except ValueError:
        return _redirect("/admin/audit", "error", "Actor ID must be a number")

    # Upsert on (account_id, name) so the user can tweak + re-save with
    # the same label without bumping into the unique-key constraint.
    existing = db.scalar(
        _sel(SavedAuditQuery).where(
            SavedAuditQuery.account_id == acct.id,
            SavedAuditQuery.name == clean_name,
        )
    )
    if existing is None:
        row = SavedAuditQuery(
            account_id=acct.id,
            name=clean_name,
            action=(action or "").strip() or None,
            resource_type=(resource_type or "").strip() or None,
            resource_id=(resource_id or "").strip() or None,
            actor_id=actor_id_int,
        )
        db.add(row)
    else:
        existing.action = (action or "").strip() or None
        existing.resource_type = (resource_type or "").strip() or None
        existing.resource_id = (resource_id or "").strip() or None
        existing.actor_id = actor_id_int

    # Preserve the filter params on the redirect so the user lands back
    # on the same view they just saved.
    qs_parts: list[str] = []
    if action:
        qs_parts.append(f"action={action}")
    if resource_type:
        qs_parts.append(f"resource_type={resource_type}")
    if resource_id:
        qs_parts.append(f"resource_id={resource_id}")
    if actor_id_int:
        qs_parts.append(f"actor_id={actor_id_int}")
    url = "/admin/audit" + ("?" + "&".join(qs_parts) if qs_parts else "")
    return _redirect(url, "success", f"Saved as '{clean_name}'")


@router.post(
    "/admin/audit/saved/{saved_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_audit_saved_delete(
    saved_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from .db import SavedAuditQuery

    acct = _admin_account(db, username)
    row = db.scalar(
        _sel(SavedAuditQuery).where(
            SavedAuditQuery.id == saved_id,
            SavedAuditQuery.account_id == acct.id,
        )
    )
    if row is None:
        return _redirect("/admin/audit", "error", "Saved filter not found")
    db.delete(row)
    return _redirect("/admin/audit", "success", "Saved filter removed")


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

    from .db import SchedulerRun

    last_run_row = db.scalar(
        _sel(SchedulerRun)
        .where(SchedulerRun.job == "retention")
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )
    last_run = None
    if last_run_row is not None:
        last_run = {
            "started_at": last_run_row.started_at.isoformat() if last_run_row.started_at else None,
            "finished_at": last_run_row.finished_at.isoformat() if last_run_row.finished_at else None,
            "duration_ms": last_run_row.duration_ms,
            "summary": last_run_row.summary,
            "error": last_run_row.error,
        }

    ctx = base_context(
        request,
        username,
        caller_email=acct.email,
        policy=policy,
        device_policies=device_policies,
        devices=devices,
        last_run=last_run,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "retention.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/retention/device", dependencies=[Depends(require_csrf)])
def admin_add_device_retention(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    device_id: Annotated[str, Form()],
    keep_last_n_auto: Annotated[int, Form()] = 30,
    auto_expire_days: Annotated[str, Form()] = "",
    keep_labeled_forever: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from . import audit as _audit
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

    policy_detail = {
        "keep_last_n_auto": max(1, min(keep_last_n_auto, 500)),
        "auto_expire_days": int(auto_expire_days) if auto_expire_days.strip() else None,
        "keep_labeled_forever": bool(keep_labeled_forever),
    }
    db.add(
        SnapshotRetentionPolicy(
            account_id=acct.id,
            device_id=dev_id,
            keep_last_n_auto=policy_detail["keep_last_n_auto"],
            auto_expire_days=policy_detail["auto_expire_days"],
            keep_labeled_forever=policy_detail["keep_labeled_forever"],
        )
    )
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="retention.device_override_added",
        resource_type="retention_policy",
        resource_id=dev_id,
        detail=policy_detail,
    )
    return _redirect("/admin/retention", "success", f"Added override for {dev_id}")


@router.post(
    "/admin/retention/device/{device_id}/delete", dependencies=[Depends(require_csrf)]
)
def admin_delete_device_retention(
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from . import audit as _audit
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
    removed = {
        "keep_last_n_auto": row.keep_last_n_auto,
        "auto_expire_days": row.auto_expire_days,
        "keep_labeled_forever": row.keep_labeled_forever,
    }
    db.delete(row)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="retention.device_override_removed",
        resource_type="retention_policy",
        resource_id=dev_id,
        detail=removed,
    )
    return _redirect("/admin/retention", "success", f"Override for {dev_id} removed")


@router.post("/admin/retention/policy", dependencies=[Depends(require_csrf)])
def admin_set_retention_policy(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    keep_last_n_auto: Annotated[int, Form()] = 30,
    auto_expire_days: Annotated[str, Form()] = "",
    keep_labeled_forever: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from . import audit as _audit
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
    before = (
        {
            "keep_last_n_auto": row.keep_last_n_auto,
            "auto_expire_days": row.auto_expire_days,
            "keep_labeled_forever": row.keep_labeled_forever,
        }
        if row is not None
        else None
    )
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

    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="retention.policy_saved",
        resource_type="retention_policy",
        resource_id=str(acct.id),
        detail={
            "before": before,
            "after": {
                "keep_last_n_auto": row.keep_last_n_auto,
                "auto_expire_days": row.auto_expire_days,
                "keep_labeled_forever": row.keep_labeled_forever,
            },
        },
    )
    return _redirect("/admin/retention", "success", "Policy saved")


@router.post("/admin/retention/run-now", dependencies=[Depends(require_csrf)])
def admin_retention_run_now(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from . import retention as _ret

    summary = _ret.run_retention(db)
    msg = (
        f"Retention run: accounts={summary.get('accounts', 0)}, "
        f"deleted={summary.get('deleted', 0)}, "
        f"idempotency_purged={summary.get('idempotency_purged', 0)}, "
        f"revoked_tokens_purged={summary.get('revoked_tokens_purged', 0)}, "
        f"audit_events_purged={summary.get('audit_events_purged', 0)}"
    )
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="retention.manual_run",
        resource_type="retention_policy",
        resource_id=None,
        detail={"summary": summary},
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
    request: Request,
    device_id: str,
    snapshot_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from . import snapshots as _snap
    from .db import DeviceSnapshot
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    target = db.get(DeviceSnapshot, snapshot_id)
    if target is None or target.device_id != dev_id or target.account_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Snapshot not found")
    current = _snap.get_head(db, dev_id)
    previous_head_id = current.id if current is not None else None
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
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="snapshot.restored",
        resource_type="snapshot",
        resource_id=str(target.id),
        detail={
            "device_id": dev_id,
            "previous_head_id": previous_head_id,
            "target_label": target.label,
        },
    )
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
            "require_2fa_for_admins": row.require_2fa_for_admins,
            "audit_retention_days": row.audit_retention_days,
            "webhook_url": row.webhook_url,
            "webhook_event_prefixes": row.webhook_event_prefixes,
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
    request: Request,
    username: Annotated[str, Depends(current_user)],
    snapshot_keep_last_n: Annotated[int, Form()] = 30,
    snapshot_retain_days: Annotated[int, Form()] = 90,
    max_bytes_per_user: Annotated[str, Form()] = "",
    registration_enabled: Annotated[str, Form()] = "",
    default_role: Annotated[str, Form()] = "user",
    banner_message: Annotated[str, Form()] = "",
    require_2fa_for_admins: Annotated[str, Form()] = "",
    audit_retention_days: Annotated[int, Form()] = 365,
    webhook_url: Annotated[str, Form()] = "",
    webhook_event_prefixes: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
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

    # Snapshot the before-state so the audit entry carries a diff of
    # exactly what the admin just changed. Missing row = defaults, so
    # an upsert reads as "created from defaults".
    before = {
        "snapshot_keep_last_n": row.snapshot_keep_last_n,
        "snapshot_retain_days": row.snapshot_retain_days,
        "max_bytes_per_user": row.max_bytes_per_user,
        "registration_enabled": row.registration_enabled,
        "default_role": row.default_role,
        "banner_message": row.banner_message,
        "require_2fa_for_admins": row.require_2fa_for_admins,
        "audit_retention_days": row.audit_retention_days,
        "webhook_url": row.webhook_url,
        "webhook_event_prefixes": row.webhook_event_prefixes,
    }

    row.snapshot_keep_last_n = max(1, min(int(snapshot_keep_last_n), 500))
    row.snapshot_retain_days = max(1, min(int(snapshot_retain_days), 3650))
    row.max_bytes_per_user = (
        int(max_bytes_per_user) if max_bytes_per_user.strip() else None
    )
    row.registration_enabled = bool(registration_enabled)
    row.default_role = default_role
    row.banner_message = banner_message.strip() or None
    row.require_2fa_for_admins = bool(require_2fa_for_admins)
    row.audit_retention_days = max(0, min(int(audit_retention_days), 3650))
    row.webhook_url = webhook_url.strip() or None
    row.webhook_event_prefixes = (
        webhook_event_prefixes.strip()
        or "permission.denied,login.failed,session.killed,user.suspended,user.deleted,totp.login_failed"
    )
    row.updated_by_email = f"{username}@admin.local"

    after = {
        "snapshot_keep_last_n": row.snapshot_keep_last_n,
        "snapshot_retain_days": row.snapshot_retain_days,
        "max_bytes_per_user": row.max_bytes_per_user,
        "registration_enabled": row.registration_enabled,
        "default_role": row.default_role,
        "banner_message": row.banner_message,
        "require_2fa_for_admins": row.require_2fa_for_admins,
        "audit_retention_days": row.audit_retention_days,
        "webhook_url": row.webhook_url,
        "webhook_event_prefixes": row.webhook_event_prefixes,
    }
    changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    if changed:
        acct = _admin_account(db, username)
        _audit.emit(
            db,
            request=request,
            actor=acct,
            action="settings.updated",
            resource_type="global_policy",
            resource_id="1",
            detail={"changed": changed},
        )

    return _redirect("/admin/settings", "success", "Settings saved")


@router.post("/admin/settings/webhook-test", dependencies=[Depends(require_csrf)])
def admin_settings_webhook_test(
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import webhooks as _webhooks

    url, _ = _webhooks._resolve_config(db)
    if not url:
        return _redirect("/admin/settings", "error", "No webhook URL configured")
    _webhooks._pool.submit(_webhooks._post, url, {
        "source": "nks-wdc-catalog-api",
        "test": True,
        "event": {"action": "webhook.test", "actor_email": f"{username}@admin.local"},
    })
    return _redirect("/admin/settings", "success", "Test webhook enqueued")


# ── Invite history (consumed) ────────────────────────────────────────


@router.get("/admin/invites/history", response_class=HTMLResponse)
def admin_invites_history(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    email: str = "",
    since: str = "",
    until: str = "",
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import ConsumedInvite, count_query

    stmt = _invites_history_stmt(_sel(ConsumedInvite), email, since, until)
    total = count_query(db, stmt)
    rows = db.scalars(stmt.order_by(ConsumedInvite.consumed_at.desc()).limit(500)).all()
    consumed = [
        {
            "nonce": r.nonce,
            "email": r.email,
            "consumed_at": r.consumed_at.isoformat() if r.consumed_at else "",
            "account_id": r.account_id,
        }
        for r in rows
    ]
    qs_parts = []
    if email:
        qs_parts.append(f"email={email}")
    if since:
        qs_parts.append(f"since={since}")
    if until:
        qs_parts.append(f"until={until}")
    qs = "&".join(qs_parts)

    ctx = base_context(
        request,
        username,
        consumed=consumed,
        total=total,
        email=email,
        since=since,
        until=until,
        qs=qs,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "invites_history.html", ctx)
    _clear_flash(response)
    return response


@router.get("/admin/invites/history.csv")
def admin_invites_history_csv(
    username: Annotated[str, Depends(current_user)],
    email: str = "",
    since: str = "",
    until: str = "",
    db: Session = Depends(get_session),
) -> Response:
    import csv
    import io

    from sqlalchemy import select as _sel

    from .db import ConsumedInvite

    stmt = _invites_history_stmt(_sel(ConsumedInvite), email, since, until)
    rows = db.scalars(stmt.order_by(ConsumedInvite.consumed_at.desc()).limit(10000)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["email", "consumed_at", "account_id", "nonce"])
    for r in rows:
        w.writerow([
            r.email or "",
            r.consumed_at.isoformat() if r.consumed_at else "",
            r.account_id if r.account_id is not None else "",
            r.nonce or "",
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="invite-history.csv"',
            "Cache-Control": "no-store",
        },
    )


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
    request: Request,
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

    from . import audit as _audit
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="snapshot.imported",
        resource_type="snapshot",
        resource_id=str(snap.id),
        detail={
            "device_id": dev_id,
            "label": default_label,
            "set_head": bool(set_head),
            "payload_bytes": len(payload or ""),
        },
    )
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

    stmt = _audit_filter_stmt(
        _sel(AuditEvent),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
    )

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


# ── Audit JSONL.gz bulk export ────────────────────────────────────────


@router.get("/admin/audit/export.jsonl.gz")
def admin_audit_export_jsonl(
    username: Annotated[str, Depends(current_user)],
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    actor_id: int | None = None,
    limit: int = 50000,
    db: Session = Depends(get_session),
):
    """Stream the filtered audit log as gzip-compressed NDJSON.

    Each line is a JSON object with the full audit event shape.  Honors
    the same filter params as the HTML audit page.  Default limit 50k,
    hard cap 200k.  Trivially ingestible:  curl … | gunzip | jq -c .
    """
    import gzip
    import io
    import json

    from fastapi.responses import StreamingResponse
    from sqlalchemy import select as _sel

    from .db import AuditEvent

    stmt = _audit_filter_stmt(
        _sel(AuditEvent),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
    ).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(
        max(1, min(limit, 200000))
    )

    rows = db.scalars(stmt).all()

    def generator():
        buf = io.BytesIO()
        gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6)
        batch_size = 1000
        for i, r in enumerate(rows, 1):
            line = json.dumps(
                {
                    "id": r.id,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "actor_id": r.actor_id,
                    "actor_email": r.actor_email,
                    "action": r.action,
                    "resource_type": r.resource_type,
                    "resource_id": r.resource_id,
                    "ip": r.ip,
                    "user_agent": r.user_agent,
                    "detail": r.detail,
                },
                default=str,
                ensure_ascii=False,
            ) + "\n"
            gz.write(line.encode("utf-8"))
            if i % batch_size == 0:
                gz.flush()
                data = buf.getvalue()
                buf.seek(0)
                buf.truncate()
                if data:
                    yield data
        gz.close()
        final = buf.getvalue()
        if final:
            yield final

    return StreamingResponse(
        generator(),
        media_type="application/gzip",
        headers={
            "Content-Disposition": 'attachment; filename="audit.jsonl.gz"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ── Audit SSE stream ─────────────────────────────────────────────────


@router.get("/admin/audit/stream")
async def admin_audit_stream(
    request: Request,
    username: Annotated[str, Depends(current_user)],
):
    """Stream audit events as Server-Sent Events.

    Yields ``event: connected`` on open, then ``event: audit`` for each
    published audit row, with a ``': ping'`` heartbeat comment every 15 s
    to keep proxies from closing an idle connection.
    """
    import asyncio
    import json

    from fastapi.responses import JSONResponse, StreamingResponse

    from . import event_bus

    # Check subscriber cap before committing to a streaming response.
    # _register raises RuntimeError("event bus saturated") at the cap.
    _probe_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=1)
    try:
        event_bus._bus._register(_probe_queue)
    except RuntimeError as exc:
        if "saturated" in str(exc):
            return JSONResponse({"error": "too many subscribers"}, status_code=503)
        raise
    event_bus._bus._unregister(_probe_queue)

    async def gen():
        yield "event: connected\ndata: {}\n\n"
        # Use a fresh queue registered directly so we can call queue.get()
        # with asyncio.wait_for — wrapping anext() on an async generator
        # with wait_for leaks StopAsyncIteration through task cancellation
        # in Python 3.12 and causes a RuntimeError in the streaming body.
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=128)
        event_bus._bus._register(queue)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield f"event: audit\ndata: {json.dumps(evt, default=str)}\n\n"
        finally:
            event_bus._bus._unregister(queue)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
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
    request: Request,
    device_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from .db import DeviceConfig
    from .device_ids import normalize_device_id

    acct = _admin_account(db, username)
    dev_id = normalize_device_id(device_id)
    dev = db.get(DeviceConfig, dev_id)
    if dev is None or dev.user_id != acct.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    dev_name = dev.name
    db.delete(dev)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="device.deleted",
        resource_type="device",
        resource_id=dev_id,
        detail={"name": dev_name} if dev_name else None,
    )
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


def _pat_view_rows(db: Session, account_id: int) -> list[dict]:
    """Shared render helper — tokens list with ``expired`` derived flag."""
    from datetime import datetime, timezone

    from . import pats as _pats

    rows = _pats.list_for(db, account_id=account_id)
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    return [
        {
            "id": r.id,
            "name": r.name,
            "prefix": r.token_prefix,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "expired": r.expires_at is not None and r.expires_at <= now_naive,
        }
        for r in rows
    ]


@router.post(
    "/admin/account/sessions/{session_id}/kill",
    dependencies=[Depends(require_csrf)],
)
def admin_kill_session(
    request: Request,
    session_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from datetime import datetime, timezone

    from sqlalchemy import select as _sel

    from . import audit as _audit
    from .db import AdminSession, User

    user = db.scalar(_sel(User).where(User.username == username))
    row = db.get(AdminSession, session_id)
    if row is None or row.user_id != (user.id if user else -1):
        return _redirect("/admin/account", "error", "Session not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="session.killed",
        resource_type="admin_session",
        resource_id=str(session_id),
        detail={"ip": row.ip, "user_agent": row.user_agent},
    )
    return _redirect("/admin/account", "success", "Session killed")


@router.post(
    "/admin/account/sessions/kill-others",
    dependencies=[Depends(require_csrf)],
)
def admin_kill_other_sessions(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from datetime import datetime, timezone

    from sqlalchemy import select as _sel
    from sqlalchemy import update as _upd

    from . import audit as _audit
    from .auth import SESSION_COOKIE, _fingerprint
    from .db import AdminSession, User

    user = db.scalar(_sel(User).where(User.username == username))
    current_fp = _fingerprint(request.cookies.get(SESSION_COOKIE, ""))
    q = _upd(AdminSession).where(
        AdminSession.user_id == (user.id if user else -1),
        AdminSession.revoked_at.is_(None),
        AdminSession.fingerprint != current_fp,
    ).values(revoked_at=datetime.now(timezone.utc))
    killed = db.execute(q).rowcount
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="session.killed_others",
        resource_type="admin_session",
        detail={"count": int(killed)},
    )
    return _redirect("/admin/account", "success", f"Killed {killed} other session(s)")


@router.get("/admin/account", response_class=HTMLResponse)
def admin_account(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import GlobalPolicy, User

    user = db.scalar(_sel(User).where(User.username == username))
    acct = _admin_account(db, username)
    policy = db.get(GlobalPolicy, 1)
    ctx = base_context(
        request,
        username,
        user_id=user.id if user else "—",
        tokens=_pat_view_rows(db, acct.id),
        minted_pat=None,
        pending_totp=None,
        new_recovery_codes=None,
        totp_enabled=bool(acct.totp_enabled),
        totp_enabled_at=acct.totp_enabled_at.isoformat() if acct.totp_enabled_at else None,
        sessions=_session_list(db, username, request),
        flash=_pop_flash(flash),
        totp_gate_active=bool(policy and policy.require_2fa_for_admins),
    )
    response = templates.TemplateResponse(request, "account.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/account/tokens", dependencies=[Depends(require_csrf)])
def admin_create_account_token(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    name: Annotated[str, Form()],
    ttl_days: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select as _sel

    from . import pats as _pats
    from .db import User

    acct = _admin_account(db, username)
    user = db.scalar(_sel(User).where(User.username == username))
    expires_at = None
    if ttl_days.strip():
        try:
            days = max(1, min(int(ttl_days), 365))
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except ValueError:
            return _redirect("/admin/account", "error", "TTL must be a number")

    row, plaintext = _pats.issue(
        db, account_id=acct.id, name=name, expires_at=expires_at
    )

    from . import audit as _audit
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="pat.created",
        resource_type="pat",
        resource_id=str(row.id),
        detail={
            "name": row.name,
            "prefix": row.token_prefix,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        },
    )

    # Render the account page inline so the one-time plaintext callout
    # renders with the freshly-minted row still at the top of the list.
    return _render_account(
        request,
        username,
        db,
        minted_pat={
            "name": row.name,
            "token": plaintext,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        },
        flash={"kind": "success", "message": f"Token '{row.name}' created"},
    )


@router.post(
    "/admin/account/tokens/{token_id}/revoke", dependencies=[Depends(require_csrf)]
)
def admin_revoke_account_token(
    request: Request,
    token_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from . import pats as _pats

    acct = _admin_account(db, username)
    ok = _pats.revoke(db, account_id=acct.id, token_id=token_id)
    if not ok:
        return _redirect("/admin/account", "error", "Token not found")
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="pat.revoked",
        resource_type="pat",
        resource_id=str(token_id),
    )
    return _redirect("/admin/account", "success", "Token revoked")


@router.post("/admin/account/password", dependencies=[Depends(require_csrf)])
def admin_change_own_password(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from sqlalchemy import select as _sel

    from . import audit as _audit
    from .auth import hash_password as _hash
    from .auth import verify_password as _verify
    from .db import User

    user = db.scalar(_sel(User).where(User.username == username))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if not _verify(current_password, user.password_hash):
        # Audit the failed attempt too — repeated failures from the same
        # account surface a compromised session cookie.
        acct_fail = _admin_account(db, username)
        _audit.emit(
            db,
            request=request,
            actor=acct_fail,
            action="password.change_failed",
            resource_type="account",
            resource_id=str(acct_fail.id),
            detail={"reason": "current_password_wrong"},
        )
        return _redirect("/admin/account", "error", "Current password is wrong")
    if new_password != new_password_confirm:
        return _redirect("/admin/account", "error", "New passwords don't match")
    if len(new_password) < 12:
        return _redirect(
            "/admin/account", "error", "New password must be at least 12 characters"
        )
    user.password_hash = _hash(new_password)
    acct = _admin_account(db, username)
    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="password.changed",
        resource_type="account",
        resource_id=str(acct.id),
    )
    return _redirect("/admin/account", "success", "Password updated")


# ── Two-factor auth (TOTP) ──────────────────────────────────────────
#
# The bootstrap ``User`` (admin-UI session identity) owns the 2FA state
# on its paired ``Account`` row — we reuse the account resolver so the
# audit trail stays consistent with the rest of the admin surface.


def _account_for_user(db: Session, username: str):
    """Return the Account row that backs this admin-UI username."""
    return _admin_account(db, username)


def _session_list(db: Session, username: str, request: Request) -> list[dict]:
    """Return the current user's non-revoked AdminSession rows for the account page."""
    from sqlalchemy import select as _sel

    from .auth import SESSION_COOKIE, _fingerprint
    from .db import AdminSession, User

    user = db.scalar(_sel(User).where(User.username == username))
    if user is None:
        return []
    current_fp = _fingerprint(request.cookies.get(SESSION_COOKIE, ""))
    rows = db.scalars(
        _sel(AdminSession)
        .where(AdminSession.user_id == user.id)
        .where(AdminSession.revoked_at.is_(None))
        .order_by(AdminSession.last_seen_at.desc())
    ).all()
    return [
        {
            "id": r.id,
            "ip": r.ip,
            "user_agent": r.user_agent,
            "created_at": r.created_at.isoformat() if r.created_at else "",
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else "",
            "is_current": r.fingerprint == current_fp,
        }
        for r in rows
    ]


def _render_account(
    request: Request,
    username: str,
    db: Session,
    *,
    minted_pat=None,
    pending_totp=None,
    new_recovery_codes=None,
    flash=None,
) -> HTMLResponse:
    from sqlalchemy import select as _sel

    from .db import GlobalPolicy, User

    user = db.scalar(_sel(User).where(User.username == username))
    acct = _admin_account(db, username)
    policy = db.get(GlobalPolicy, 1)
    ctx = base_context(
        request,
        username,
        user_id=user.id if user else "—",
        tokens=_pat_view_rows(db, acct.id),
        minted_pat=minted_pat,
        pending_totp=pending_totp,
        new_recovery_codes=new_recovery_codes,
        totp_enabled=bool(acct.totp_enabled),
        totp_enabled_at=acct.totp_enabled_at.isoformat() if acct.totp_enabled_at else None,
        sessions=_session_list(db, username, request),
        flash=flash,
        totp_gate_active=bool(policy and policy.require_2fa_for_admins),
    )
    response = templates.TemplateResponse(request, "account.html", ctx)
    if flash is None:
        _clear_flash(response)
    return response


@router.post("/admin/account/totp/setup", dependencies=[Depends(require_csrf)])
def admin_totp_setup(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Generate a fresh TOTP secret and show the pairing block.

    The secret is persisted unconfirmed (``totp_enabled`` stays False)
    so the subsequent confirm call can validate the first 6-digit code
    against it without juggling signed cookies. If the user walks away,
    a later setup call overwrites it — no orphaned secrets accumulate
    because there is only ever one per account.
    """
    from . import audit as _audit
    from . import totp as _totp

    acct = _account_for_user(db, username)
    if acct.totp_enabled:
        return _redirect("/admin/account", "error", "2FA is already enabled. Disable it first to re-pair.")

    secret = _totp.new_secret()
    acct.totp_secret = secret
    acct.totp_enabled = False
    acct.totp_recovery_hashes = None
    db.flush()

    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="totp.setup_started",
        resource_type="account",
        resource_id=str(acct.id),
    )

    return _render_account(
        request,
        username,
        db,
        pending_totp={
            "secret": secret,
            "otpauth_uri": _totp.otpauth_uri(secret, account=acct.email, issuer="NKS WDC"),
        },
        flash={"kind": "info", "message": "Scan or paste the secret into your authenticator, then enter the code below."},
    )


@router.post("/admin/account/totp/confirm", dependencies=[Depends(require_csrf)])
def admin_totp_confirm(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    code: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    """Validate the first TOTP code + flip ``totp_enabled`` on. Returns
    the one-time recovery codes; they're never shown again afterwards."""
    import bcrypt as _bcrypt
    from datetime import datetime, timezone

    from . import audit as _audit
    from . import totp as _totp

    acct = _account_for_user(db, username)
    if acct.totp_enabled:
        return _redirect("/admin/account", "error", "2FA is already enabled.")
    if not acct.totp_secret:
        return _redirect("/admin/account", "error", "No pending 2FA setup — start over.")

    if not _totp.verify(acct.totp_secret, code):
        return _render_account(
            request,
            username,
            db,
            pending_totp={
                "secret": acct.totp_secret,
                "otpauth_uri": _totp.otpauth_uri(
                    acct.totp_secret, account=acct.email, issuer="NKS WDC"
                ),
            },
            flash={"kind": "error", "message": "Code didn't match — check your clock and try again."},
        )

    # Success — bake the enablement and mint recovery codes.
    codes = _totp.generate_recovery_codes()
    hashes = "\n".join(
        _bcrypt.hashpw(c.encode("utf-8"), _bcrypt.gensalt(rounds=10)).decode("ascii")
        for c in codes
    )
    acct.totp_enabled = True
    acct.totp_enabled_at = datetime.now(timezone.utc)
    acct.totp_recovery_hashes = hashes

    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="totp.enabled",
        resource_type="account",
        resource_id=str(acct.id),
    )

    return _render_account(
        request,
        username,
        db,
        new_recovery_codes=codes,
        flash={"kind": "success", "message": "2FA enabled. Save these recovery codes now — they're shown only once."},
    )


@router.post("/admin/account/totp/disable", dependencies=[Depends(require_csrf)])
def admin_totp_disable(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    code: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    """Turn off 2FA. Requires a current code (or recovery code) so a
    stolen session cookie alone can't weaken the account's auth."""
    import bcrypt as _bcrypt

    from . import audit as _audit
    from . import totp as _totp

    acct = _account_for_user(db, username)
    if not acct.totp_enabled or not acct.totp_secret:
        return _redirect("/admin/account", "error", "2FA is not enabled.")

    code_clean = code.strip()
    ok = False
    used_recovery = False
    if code_clean.isdigit() and len(code_clean.replace(" ", "").replace("-", "")) == 6:
        ok = _totp.verify(acct.totp_secret, code_clean)
    else:
        norm = _totp.normalize_recovery_code(code_clean)
        for line in (acct.totp_recovery_hashes or "").splitlines():
            if not line.strip():
                continue
            try:
                if _bcrypt.checkpw(norm.encode("utf-8"), line.strip().encode("ascii")):
                    ok = True
                    used_recovery = True
                    break
            except ValueError:
                continue

    if not ok:
        return _redirect("/admin/account", "error", "Code didn't match - 2FA stays on.")

    acct.totp_enabled = False
    acct.totp_secret = None
    acct.totp_recovery_hashes = None
    acct.totp_enabled_at = None

    _audit.emit(
        db,
        request=request,
        actor=acct,
        action="totp.disabled",
        resource_type="account",
        resource_id=str(acct.id),
        detail={"used_recovery": used_recovery} if used_recovery else None,
    )

    return _redirect("/admin/account", "success", "2FA disabled.")


@router.get("/admin/ops", response_class=HTMLResponse)
def admin_ops(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> HTMLResponse:
    import os as _os
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select as _sel, func

    from .db import Account, AdminSession, AuditEvent, User, GlobalPolicy
    from . import __version__

    # --- version + uptime ---
    uptime_s = max(0.0, time.time() - _PROCESS_START)
    uptime_str = _format_uptime(uptime_s)

    # --- sessions ---
    active_sessions = db.scalar(
        _sel(func.count()).select_from(AdminSession).where(
            AdminSession.revoked_at.is_(None)
        )
    ) or 0

    # --- accounts ---
    accounts_total = db.scalar(_sel(func.count()).select_from(Account)) or 0
    admin_users = db.scalar(_sel(func.count()).select_from(User)) or 0

    # --- audit ---
    events_total = db.scalar(_sel(func.count()).select_from(AuditEvent)) or 0
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    events_24h = db.scalar(
        _sel(func.count()).select_from(AuditEvent).where(
            AuditEvent.created_at >= cutoff
        )
    ) or 0

    # --- DB size (sqlite only; postgres shows "—") ---
    db_backend = "sqlite" if "sqlite" in str(_engine.url) else "postgres"
    db_size_bytes: int | None = None
    if db_backend == "sqlite":
        db_file = str(_engine.url).replace("sqlite:///", "", 1)
        try:
            db_size_bytes = _os.path.getsize(db_file)
        except OSError:
            db_size_bytes = None

    # --- scheduler ---
    scheduler_on = _os.environ.get("NKS_WDC_DISABLE_SCHEDULER") != "1"
    retention_cron = _os.environ.get("NKS_WDC_RETENTION_CRON", "0 3 * * *")

    # --- webhooks ---
    policy = db.get(GlobalPolicy, 1)
    webhook_enabled = bool(policy and (policy.webhook_url or "").strip())

    # --- retention last run ---
    from .db import SchedulerRun

    rr = db.scalar(
        _sel(SchedulerRun)
        .where(SchedulerRun.job == "retention")
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )
    retention_last_run = None
    if rr is not None:
        from datetime import datetime, timezone

        age_s = None
        if rr.started_at is not None:
            age_s = (datetime.now(timezone.utc).replace(tzinfo=None) - rr.started_at).total_seconds()
        retention_last_run = {
            "age": _format_uptime(age_s) + " ago" if age_s is not None else "—",
            "ok": rr.error is None,
            "deleted": (rr.summary or {}).get("deleted", 0),
            "audit_purged": (rr.summary or {}).get("audit_events_purged", 0),
        }

    ctx = base_context(
        request,
        username,
        version=__version__,
        uptime=uptime_str,
        active_sessions=active_sessions,
        accounts_total=accounts_total,
        admin_users=admin_users,
        events_total=events_total,
        events_24h=events_24h,
        db_backend=db_backend,
        db_size_bytes=db_size_bytes,
        db_size_human=_human_bytes(db_size_bytes) if db_size_bytes is not None else "—",
        scheduler_on=scheduler_on,
        retention_cron=retention_cron,
        webhook_enabled=webhook_enabled,
        retention_last_run=retention_last_run,
    )
    return templates.TemplateResponse(request, "ops.html", ctx)


@router.get("/admin/ops/scheduler", response_class=HTMLResponse)
def admin_scheduler_runs(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    job: str = "",
    status_filter: str = "",  # "" | "ok" | "failed"
    offset: int = 0,
    limit: int = 50,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from sqlalchemy import func as _func
    from sqlalchemy import select as _sel

    from .db import SchedulerRun

    stmt = _sel(SchedulerRun)
    if job:
        stmt = stmt.where(SchedulerRun.job == job)
    if status_filter == "ok":
        stmt = stmt.where(SchedulerRun.error.is_(None))
    elif status_filter == "failed":
        stmt = stmt.where(SchedulerRun.error.is_not(None))

    total = db.scalar(
        _sel(_func.count()).select_from(stmt.subquery())
    ) or 0
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    rows = db.scalars(
        stmt.order_by(SchedulerRun.started_at.desc(), SchedulerRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()

    runs = [
        {
            "id": r.id,
            "job": r.job,
            "started_at": r.started_at.isoformat() if r.started_at else "",
            "finished_at": r.finished_at.isoformat() if r.finished_at else "",
            "duration_ms": r.duration_ms,
            "summary": r.summary,
            "error": r.error,
            "ok": r.error is None,
        }
        for r in rows
    ]

    qs_parts = []
    if job:
        qs_parts.append(f"job={job}")
    if status_filter:
        qs_parts.append(f"status_filter={status_filter}")
    qs = ("&".join(qs_parts) + "&") if qs_parts else ""

    job_names = db.scalars(
        _sel(SchedulerRun.job).distinct().order_by(SchedulerRun.job.asc())
    ).all()

    ctx = base_context(
        request,
        username,
        runs=runs,
        total=total,
        offset=offset,
        limit=limit,
        job=job,
        status_filter=status_filter,
        qs=qs,
        job_names=list(job_names),
    )
    return templates.TemplateResponse(request, "scheduler_runs.html", ctx)


__all__ = ["router"]
