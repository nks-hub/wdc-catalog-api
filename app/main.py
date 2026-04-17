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

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response, status

from .csrf import require_csrf
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
from .devices import router as devices_router, optional_account, get_current_account
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
    from . import retention as _retention
    _retention.start_scheduler()
    try:
        yield
    finally:
        _retention.stop_scheduler()


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


# Rate limiting — protects auth + sync endpoints from brute force + DoS.
# Tests opt out with NKS_WDC_DISABLE_RATE_LIMITS=1.
from slowapi.errors import RateLimitExceeded

from .ratelimit import limiter

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        {"detail": f"Rate limit exceeded: {exc.detail}"},
        status_code=429,
    )


# Payload size ceiling — the config-sync endpoint accepts free-form JSON
# so an unbounded request body is a cheap DoS + storage-exhaust vector.
# 1 MiB covers legitimate WDC snapshots (seen in the wild: 50–300 KB).
MAX_REQUEST_BYTES = int(os.environ.get("NKS_WDC_MAX_REQUEST_BYTES", 1024 * 1024))


@app.middleware("http")
async def _limit_payload_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
                    status_code=413,
                )
        except ValueError:
            pass
    response = await call_next(request)
    # Keep the CSRF cookie fresh on every admin-UI HTML response so forms
    # always have a valid token paired with the session. Ignored by JSON
    # API consumers (they don't render HTML and don't inspect it).
    if request.url.path.startswith(("/admin", "/login")) and "text/html" in response.headers.get("content-type", ""):
        from .csrf import ensure_csrf_cookie
        existing = request.cookies.get("nks_wdc_csrf")
        ensure_csrf_cookie(response, existing)
    return response

# Mount the accounts + devices router (JWT-authenticated endpoints)
app.include_router(devices_router)

# Mount the admin JSON API (role-gated endpoints for user management)
from .admin_users import router as admin_users_router  # noqa: E402
from .admin_audit import router as admin_audit_router  # noqa: E402
from .admin_stats import router as admin_stats_router  # noqa: E402
from .admin_policies import router as admin_policies_router  # noqa: E402
from .admin_invites import (  # noqa: E402
    admin_router as admin_invites_router,
    public_router as public_invites_router,
)
from .backups import router as backups_router  # noqa: E402
from .admin_retention import router as admin_retention_router  # noqa: E402

app.include_router(admin_users_router)
app.include_router(admin_audit_router)
app.include_router(admin_stats_router)
app.include_router(admin_policies_router)
app.include_router(admin_invites_router)
app.include_router(public_invites_router)
app.include_router(backups_router)
app.include_router(admin_retention_router)

# Wire structured logging + Prometheus metrics + request-id middleware.
from . import observability  # noqa: E402

observability.install(app)

app.mount("/static", StaticFiles(directory=_APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=_APP_DIR / "templates")


def _base_context(request: Request, username: str | None, **extra) -> dict:
    """Shared template context — version always present so base.html renders.

    Includes the active CSRF token so admin templates can embed it as a
    hidden input on every form. The cookie itself is refreshed by the
    GET handler right before the template renders.
    """
    csrf = request.cookies.get("nks_wdc_csrf") or ""
    ctx = {
        "request": request,
        "username": username,
        "version": __version__,
        "flash": None,
        "csrf_token": csrf,
    }
    ctx.update(extra)
    return ctx


# ─────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────

@app.get("/healthz", tags=["health"])
def healthz(db: Session = Depends(get_session)) -> JSONResponse:
    """Liveness + readiness probe — verifies DB connectivity.

    Kubernetes/Docker compose both use this endpoint. Returning 503 when
    the DB is unreachable prevents the orchestrator from sending traffic
    to a broken replica.
    """
    try:
        db.execute(select(1)).scalar()
        return JSONResponse(
            {"ok": True, "service": "nks-wdc-catalog-api", "version": __version__, "db": "up"}
        )
    except Exception as exc:
        log.warning("healthz db probe failed: %s", exc)
        return JSONResponse(
            {"ok": False, "service": "nks-wdc-catalog-api", "db": "down"},
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


# ─────────────────────────────────────────────────────────────────────────
# Public JSON API (consumed by C# CatalogClient)
# ─────────────────────────────────────────────────────────────────────────

_CATALOG_CACHE_SECONDS = int(os.environ.get("NKS_WDC_CATALOG_CACHE_SECONDS", "60"))


@app.get("/api/v1/catalog", tags=["catalog"])
def api_get_catalog(request: Request, db: Session = Depends(get_session)) -> Response:
    """Public JSON catalog with ETag + Cache-Control.

    A hash-derived ETag lets clients (C# daemon, browsers, reverse proxies)
    skip re-downloading on restart. `Cache-Control: public, max-age=60`
    lets CDNs (Cloudflare) shield the origin from read-heavy traffic.
    """
    import hashlib
    doc = build_catalog_document(db)
    # ETag is derived from the apps payload only — excluding `generated_at`
    # so identical catalog content yields identical hashes across calls.
    apps_dump = doc.model_dump(by_alias=True, include={"apps", "schema_version"})
    etag_seed = str(sorted(apps_dump.items())).encode("utf-8")
    etag = '"' + hashlib.sha256(etag_seed).hexdigest()[:16] + '"'
    headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={_CATALOG_CACHE_SECONDS}",
    }
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    body = doc.model_dump_json(by_alias=True)
    return Response(content=body, media_type="application/json", headers=headers)


@app.get("/api/v1/catalog/{app_name}", response_model=AppDoc, tags=["catalog"])
def api_get_app(app_name: str, db: Session = Depends(get_session)) -> AppDoc:
    doc = get_app_document(db, app_name)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_name}'")
    return doc


# ─────────────────────────────────────────────────────────────────────────
# Config sync (public, runs behind reverse-proxy auth in prod)
# ─────────────────────────────────────────────────────────────────────────

# Device IDs are used as SQL primary keys and echoed back in responses.
# Restrict to the same shape the Electron client generates (lowercased
# alphanumerics + dashes, 3–64 chars) so garbage IDs can't pollute the
# device_configs table. This is defence-in-depth — SQLAlchemy already
# parameterizes the SQL, so the risk is cosmetic storage pollution, not
# injection.
import re as _re
_DEVICE_ID_RE = _re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


def _normalize_device_id(raw: str) -> str:
    """Lowercase + strip + validate a client-supplied device id.

    Raises HTTP 400 on any format violation so clients see a clear
    error instead of the request silently succeeding with a mangled id.
    """
    normalized = raw.strip().lower()
    if not normalized:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "device_id is required")
    if not _DEVICE_ID_RE.match(normalized):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "device_id must be 3–64 chars, lowercase alphanumeric + dashes",
        )
    return normalized


@app.post("/api/v1/sync/config", response_model=ConfigSyncEntry, tags=["sync"])
def api_upsert_config(
    body: ConfigSyncUploadRequest,
    account: Account | None = Depends(optional_account),
    db: Session = Depends(get_session),
) -> ConfigSyncEntry:
    from datetime import datetime, timezone

    device_id = _normalize_device_id(body.device_id)

    row = db.get(DeviceConfig, device_id)
    # Block anonymous or cross-account overwrite of an owned device (F-11).
    if row is not None and row.user_id is not None:
        if account is None or row.user_id != account.id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Device is linked to another account",
            )
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

    # Bridge legacy sync into the versioned snapshot store (Task 4.4).
    # Every authenticated push becomes an auto snapshot + HEAD move;
    # anonymous pushes skip snapshotting since we have no owner to
    # attribute storage against.
    if account is not None:
        from . import snapshots as _snap
        try:
            _snap.create_snapshot(
                db,
                device_id=device_id,
                account_id=account.id,
                payload=body.payload or {},
                kind="auto",
                created_by_ip=None,
            )
        except _snap.PayloadTooLarge:
            pass  # legacy clients pre-date payload ceiling; skip history.

    return ConfigSyncEntry(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
        payload=row.payload,
    )


def _require_owned_row(
    device_id: str,
    account: Account,
    db: Session,
    *,
    not_found_ok: bool = False,
) -> DeviceConfig | None:
    """Load a DeviceConfig, enforcing ownership (F-12 guard).

    Raises 404 when the row does not exist (unless ``not_found_ok``),
    raises 403 when the row belongs to a different account, and raises
    404 for unowned rows so we don't leak their existence.
    """
    normalized = _normalize_device_id(device_id)
    row = db.get(DeviceConfig, normalized)
    if row is None:
        if not_found_ok:
            return None
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No snapshot for {normalized}")
    if row.user_id is None or row.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No snapshot for {normalized}")
    return row


@app.get("/api/v1/sync/config/{device_id}", response_model=ConfigSyncEntry, tags=["sync"])
def api_get_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> ConfigSyncEntry:
    row = _require_owned_row(device_id, account, db)
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
def api_exists_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> ConfigSyncListResponse:
    normalized = _normalize_device_id(device_id)
    row = _require_owned_row(device_id, account, db, not_found_ok=True)
    if row is None:
        return ConfigSyncListResponse(device_id=normalized, has_config=False)
    return ConfigSyncListResponse(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        has_config=True,
    )


@app.delete("/api/v1/sync/config/{device_id}", tags=["sync"])
def api_delete_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> JSONResponse:
    row = _require_owned_row(device_id, account, db, not_found_ok=True)
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


@app.post("/login", include_in_schema=False, dependencies=[Depends(require_csrf)])
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
        samesite="strict",
        secure=_cookie_secure(),
    )
    return response


@app.post("/logout", include_in_schema=False, dependencies=[Depends(require_csrf)])
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ─────────────────────────────────────────────────────────────────────────
# Admin UI (authenticated HTML)
# ─────────────────────────────────────────────────────────────────────────

def _cookie_secure() -> bool:
    """Session cookies must carry the Secure flag in production.

    TestClient uses http:// so we cannot unconditionally set Secure. Respect
    an explicit opt-out for dev, default to Secure whenever we're not in
    DEV mode (production deployments run behind HTTPS reverse proxies).
    """
    return os.environ.get("NKS_WDC_CATALOG_DEV") != "1"


def _redirect(url: str, flash_kind: str | None = None, flash_message: str | None = None) -> RedirectResponse:
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    if flash_kind and flash_message:
        # Flash via short-lived cookie so the next GET picks it up.
        response.set_cookie(
            "flash",
            f"{flash_kind}|{flash_message}",
            max_age=15,
            httponly=True,
            samesite="strict",
            secure=_cookie_secure(),
        )
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


@app.post("/admin/new", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/apps/{app_id}/edit", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/apps/{app_id}/delete", include_in_schema=False, dependencies=[Depends(require_csrf)])
def admin_delete_app(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    svc_delete_app(db, app_id)
    return _redirect("/admin", "success", f"Deleted {app_id}")


@app.post("/admin/apps/{app_id}/releases", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/releases/{release_id}/delete", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/releases/{release_id}/downloads", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/downloads/{download_id}/delete", include_in_schema=False, dependencies=[Depends(require_csrf)])
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


@app.post("/admin/apps/{app_id}/auto-generate", include_in_schema=False, dependencies=[Depends(require_csrf)])
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
