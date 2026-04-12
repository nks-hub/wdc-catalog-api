"""FastAPI entrypoint for the NKS WDC catalog + config sync service.

Two front-ends:

1. Public JSON API consumed by the C# daemon's `CatalogClient`:
     GET /api/v1/catalog            full catalog
     GET /api/v1/catalog/{app}      single app
     POST /api/v1/sync/config       upsert device snapshot
     GET  /api/v1/sync/config/{id}  fetch device snapshot

2. HTML admin UI behind a bcrypt session login (`/login`, `/admin/*`).
   Backed by SQLite through SQLAlchemy. URL auto-generators scrape
   upstream release pages so admins don't hand-type download URLs.

Environment
-----------
DATABASE_URL                 — override SQLite default (postgres etc.)
NKS_WDC_CATALOG_STATE_DIR    — dir for `catalog.db` + runtime state
NKS_WDC_CATALOG_ADMIN_USER   — bootstrap admin username (default "admin")
NKS_WDC_CATALOG_ADMIN_PASS   — bootstrap admin password (required unless dev)
NKS_WDC_CATALOG_DEV          — set to "1" to allow admin/admin fallback
NKS_WDC_CATALOG_SECRET       — itsdangerous signer key (set in prod!)
NKS_WDC_CATALOG_ALLOW_CORS   — "1" to enable permissive CORS
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Iterator

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__
from .auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    current_user,
    ensure_admin_user,
    hash_password,
    issue_session,
    optional_user,
    verify_password,
)
from .db import Account, DeviceConfig, User, create_all, get_session, session_factory
from .devices import router as devices_router, optional_account
from .generators import GENERATORS, run_generator
from .schemas import (
    AppDoc,
    CatalogDocument,
    ConfigSyncEntry,
    ConfigSyncListResponse,
    ConfigSyncUploadRequest,
)
from .service import (
    add_download,
    add_release,
    apply_generated_releases,
    build_catalog_document,
    create_app as svc_create_app,
    delete_app as svc_delete_app,
    delete_download,
    delete_release,
    get_app,
    get_app_document,
    list_apps,
    seed_from_json,
    update_app,
)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("nks-wdc-catalog")

_APP_DIR = Path(__file__).parent
_SEED_DIR = _APP_DIR / "data" / "apps"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> Iterator[None]:
    create_all()
    ensure_admin_user()
    with session_factory() as db:
        count = seed_from_json(db, _SEED_DIR)
        if count:
            log.info("Seeded %d apps from %s", count, _SEED_DIR)
    yield


app = FastAPI(
    title="NKS WDC Catalog API",
    version=__version__,
    description=(
        "Cloud-hosted binary catalog + per-device config sync for NKS "
        "WebDev Console. Ships an admin UI for managing catalog entries "
        "and auto-generators that scrape upstream release pages so you "
        "never hand-type download URLs."
    ),
    lifespan=lifespan,
)

if os.environ.get("NKS_WDC_CATALOG_ALLOW_CORS") == "1":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

# Mount the accounts + devices router (JWT-authenticated endpoints)
app.include_router(devices_router)

app.mount("/static", StaticFiles(directory=_APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=_APP_DIR / "templates")


def _base_context(request: Request, username: str | None, **extra) -> dict:
    """Shared template context — version always present so base.html renders."""
    ctx = {"request": request, "username": username, "version": __version__, "flash": None}
    ctx.update(extra)
    return ctx


# ─────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────

@app.get("/healthz", tags=["health"])
def healthz() -> dict:
    return {"ok": True, "service": "nks-wdc-catalog-api", "version": __version__}


# ─────────────────────────────────────────────────────────────────────────
# Public JSON API (consumed by C# CatalogClient)
# ─────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/catalog", response_model=CatalogDocument, tags=["catalog"])
def api_get_catalog(db: Session = Depends(get_session)) -> CatalogDocument:
    return build_catalog_document(db)


@app.get("/api/v1/catalog/{app_name}", response_model=AppDoc, tags=["catalog"])
def api_get_app(app_name: str, db: Session = Depends(get_session)) -> AppDoc:
    doc = get_app_document(db, app_name)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_name}'")
    return doc


# ─────────────────────────────────────────────────────────────────────────
# Config sync (public, runs behind reverse-proxy auth in prod)
# ─────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/sync/config", response_model=ConfigSyncEntry, tags=["sync"])
def api_upsert_config(
    body: ConfigSyncUploadRequest,
    account: Account | None = Depends(optional_account),
    db: Session = Depends(get_session),
) -> ConfigSyncEntry:
    from datetime import datetime, timezone

    device_id = body.device_id.strip().lower()
    if not device_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "device_id is required")

    row = db.get(DeviceConfig, device_id)
    if row is None:
        row = DeviceConfig(device_id=device_id, payload=body.payload)
        db.add(row)
    else:
        row.payload = body.payload
        row.updated_at = datetime.now(timezone.utc)

    # Auto-link device to account on first authenticated push — no
    # explicit "register device" step needed. Also extract metadata
    # from the payload so the device list can show name/OS/arch/sites
    # without opening the full JSON blob.
    if account is not None and row.user_id is None:
        row.user_id = account.id
    elif account is not None and row.user_id == account.id:
        pass  # already linked
    row.last_seen_at = datetime.now(timezone.utc)

    # Extract device metadata from payload if present
    p = body.payload or {}
    if isinstance(p.get("settings"), dict):
        settings = p["settings"]
        if "sync.deviceName" in settings:
            row.name = settings["sync.deviceName"]
    if isinstance(p.get("sites"), list):
        row.site_count = len(p["sites"])
    if "deviceId" in p:
        pass  # already have device_id from URL

    # Extract OS info from system snapshot if pushed
    if isinstance(p.get("system"), dict):
        sys_info = p["system"]
        if isinstance(sys_info.get("os"), dict):
            row.os = sys_info["os"].get("tag")
            row.arch = sys_info["os"].get("arch")

    db.flush()
    return ConfigSyncEntry(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
        payload=row.payload,
    )


@app.get("/api/v1/sync/config/{device_id}", response_model=ConfigSyncEntry, tags=["sync"])
def api_get_config(device_id: str, db: Session = Depends(get_session)) -> ConfigSyncEntry:
    row = db.get(DeviceConfig, device_id.strip().lower())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No snapshot for {device_id}")
    return ConfigSyncEntry(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
        payload=row.payload,
    )


@app.get(
    "/api/v1/sync/config/{device_id}/exists",
    response_model=ConfigSyncListResponse,
    tags=["sync"],
)
def api_exists_config(device_id: str, db: Session = Depends(get_session)) -> ConfigSyncListResponse:
    row = db.get(DeviceConfig, device_id.strip().lower())
    if row is None:
        return ConfigSyncListResponse(device_id=device_id.lower(), has_config=False)
    return ConfigSyncListResponse(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        has_config=True,
    )


@app.delete("/api/v1/sync/config/{device_id}", tags=["sync"])
def api_delete_config(device_id: str, db: Session = Depends(get_session)) -> JSONResponse:
    row = db.get(DeviceConfig, device_id.strip().lower())
    if row is None:
        return JSONResponse({"ok": True, "removed": False})
    db.delete(row)
    return JSONResponse({"ok": True, "removed": True})


# ─────────────────────────────────────────────────────────────────────────
# Auth (login / logout / session cookie)
# ─────────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root(user: Annotated[str | None, Depends(optional_user)] = None):
    return RedirectResponse("/admin" if user else "/login")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", _base_context(request, None))


@app.post("/login", include_in_schema=False)
def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Session = Depends(get_session),
):
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request,
            "login.html",
            _base_context(request, None, error="Invalid username or password"),
            status_code=401,
        )
    token = issue_session(user.username)
    response = RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout", include_in_schema=False)
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ─────────────────────────────────────────────────────────────────────────
# Admin UI (authenticated HTML)
# ─────────────────────────────────────────────────────────────────────────

def _redirect(url: str, flash_kind: str | None = None, flash_message: str | None = None) -> RedirectResponse:
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    if flash_kind and flash_message:
        # Flash via short-lived cookie so the next GET picks it up.
        response.set_cookie("flash", f"{flash_kind}|{flash_message}", max_age=15, samesite="lax")
    return response


def _pop_flash(cookie: str | None) -> dict | None:
    if not cookie or "|" not in cookie:
        return None
    kind, _, message = cookie.partition("|")
    return {"kind": kind, "message": message}


def _clear_flash(response) -> None:
    response.delete_cookie("flash")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
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
        _base_context(request, username, apps=apps, flash=_pop_flash(flash)),
    )
    _clear_flash(response)
    return response


@app.get("/admin/new", response_class=HTMLResponse, include_in_schema=False)
def admin_new_app(
    request: Request,
    username: Annotated[str, Depends(current_user)],
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "app_form.html",
        _base_context(request, username, app=None),
    )


@app.post("/admin/new", include_in_schema=False)
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


@app.get("/admin/apps/{app_id}", response_class=HTMLResponse, include_in_schema=False)
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
        _base_context(
            request,
            username,
            app=app_row,
            has_generator=app_id.lower() in GENERATORS,
            flash=_pop_flash(flash),
        ),
    )
    _clear_flash(response)
    return response


@app.get("/admin/apps/{app_id}/edit", response_class=HTMLResponse, include_in_schema=False)
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
        _base_context(request, username, app=app_row),
    )


@app.post("/admin/apps/{app_id}/edit", include_in_schema=False)
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
        db, app_id,
        display_name=display_name,
        category=category,
        description=description,
        homepage=homepage,
        license=license,
    )
    if not app_row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    return _redirect(f"/admin/apps/{app_row.id}", "success", "Saved")


@app.post("/admin/apps/{app_id}/delete", include_in_schema=False)
def admin_delete_app(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    svc_delete_app(db, app_id)
    return _redirect("/admin", "success", f"Deleted {app_id}")


@app.post("/admin/apps/{app_id}/releases", include_in_schema=False)
def admin_add_release(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    version: Annotated[str, Form()],
    channel: Annotated[str, Form()] = "stable",
    released_at: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> RedirectResponse:
    rel = add_release(
        db, app_id, version,
        channel=channel,
        released_at=released_at or None,
    )
    if not rel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_id}'")
    return _redirect(f"/admin/apps/{app_id}", "success", f"Added {version}")


@app.post("/admin/releases/{release_id}/delete", include_in_schema=False)
def admin_delete_release(
    release_id: int,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from .db import Release as ReleaseModel

    rel = db.get(ReleaseModel, release_id)
    app_id = rel.app_id if rel else None
    delete_release(db, release_id)
    return _redirect(f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Release removed")


@app.post("/admin/releases/{release_id}/downloads", include_in_schema=False)
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
        db, release_id,
        url=url, os=os, arch=arch, archive_type=archive_type, source=source,
    )
    return _redirect(f"/admin/apps/{rel.app_id}", "success", "Download added")


@app.post("/admin/downloads/{download_id}/delete", include_in_schema=False)
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
    return _redirect(f"/admin/apps/{app_id}" if app_id else "/admin", "success", "Download removed")


@app.post("/admin/apps/{app_id}/auto-generate", include_in_schema=False)
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
        return _redirect(f"/admin/apps/{app_id}", "error", f"No generator for '{app_id}'")
    releases = run_generator(app_id, limit=limit)
    inserted = apply_generated_releases(db, app_id, releases)
    return _redirect(
        f"/admin/apps/{app_id}",
        "success" if inserted else "info",
        f"Auto-generated: {inserted} new release(s) from {len(releases)} scraped",
    )
