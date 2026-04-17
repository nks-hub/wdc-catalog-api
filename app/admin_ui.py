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


@router.get("/admin", response_class=HTMLResponse)
def admin_index(
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


__all__ = ["router"]
