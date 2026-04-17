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

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    status,
)

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
    issue_session,
    optional_user,
    verify_dummy_password,
    verify_password,
)
from .db import User, create_all, get_session, session_factory
from .devices import router as devices_router
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
    _warn_if_dev_in_prod()
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


def _warn_if_dev_in_prod() -> None:
    """Emit a *very loud* banner when DEV=1 flags look suspicious.

    Dev-mode unlocks:
    - admin/admin bootstrap password
    - ephemeral master + JWT + session keys
    - short NKS_WDC_MASTER_KEY accepted with sha256 padding
    Shipping any of these to a public-facing deployment is a foot-gun.
    We refuse to start when DEV=1 is combined with an explicit
    ``NKS_WDC_ENV=production`` signal, and otherwise just log prominently.
    """
    if os.environ.get("NKS_WDC_CATALOG_DEV") != "1":
        return
    env_label = (os.environ.get("NKS_WDC_ENV") or "").strip().lower()
    if env_label == "production":
        raise RuntimeError(
            "Refusing to start: NKS_WDC_CATALOG_DEV=1 together with "
            "NKS_WDC_ENV=production. Unset the DEV flag in production "
            "deployments — it disables several security guardrails."
        )
    banner = "=" * 72
    log.warning(banner)
    log.warning("NKS_WDC_CATALOG_DEV=1 — DEVELOPMENT MODE IS ACTIVE")
    log.warning(
        "  • admin/admin fallback enabled  • ephemeral signing keys  "
        "• short master keys accepted"
    )
    log.warning("  DO NOT use this flag in public-facing deployments.")
    log.warning(banner)


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
from slowapi.errors import RateLimitExceeded  # noqa: E402

from .ratelimit import limiter  # noqa: E402

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # Surface through the RFC 7807 handler so clients see a consistent
    # ``application/problem+json`` shape — the raw 429 used to leak a
    # plain ``{"detail": ...}`` body outside the problem contract.
    from .problems import problem_response

    return problem_response(
        request,
        429,
        f"Rate limit exceeded: {exc.detail}",
        title="Too Many Requests",
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
                from .problems import problem_response

                return problem_response(
                    request,
                    413,
                    f"Request body exceeds {MAX_REQUEST_BYTES} bytes",
                    title="Content Too Large",
                )
        except ValueError:
            pass
    response = await call_next(request)
    # Keep the CSRF cookie fresh on every admin-UI HTML response so forms
    # always have a valid token paired with the session. Ignored by JSON
    # API consumers (they don't render HTML and don't inspect it).
    if request.url.path.startswith(
        ("/admin", "/login")
    ) and "text/html" in response.headers.get("content-type", ""):
        from .csrf import ensure_csrf_cookie

        existing = request.cookies.get("nks_wdc_csrf")
        ensure_csrf_cookie(response, existing)
    # Session-refresh: when the admin user makes any authenticated hit,
    # re-issue the signed cookie so idle-timeout resets. Dormant sessions
    # hit ``SESSION_IDLE_TIMEOUT`` on the next visit and get kicked to
    # the login page.
    if request.url.path.startswith("/admin") and response.status_code < 400:
        existing_session = request.cookies.get(SESSION_COOKIE)
        if existing_session:
            from .auth import read_session

            username = read_session(existing_session)
            if username:
                response.set_cookie(
                    key=SESSION_COOKIE,
                    value=issue_session(username),
                    max_age=SESSION_MAX_AGE,
                    httponly=True,
                    samesite="strict",
                    secure=_cookie_secure(),
                )
    return response


# Public JSON API routers — extracted so this module focuses on
# wiring, middleware, and the HTML admin UI.
from .api_catalog import router as catalog_router  # noqa: E402
from .api_health import router as health_router  # noqa: E402
from .api_sync import router as sync_router  # noqa: E402

app.include_router(health_router)
app.include_router(catalog_router)
app.include_router(sync_router)

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
from .retention_policies import router as retention_policies_router  # noqa: E402

app.include_router(admin_users_router)
app.include_router(admin_audit_router)
app.include_router(admin_stats_router)
app.include_router(admin_policies_router)
app.include_router(admin_invites_router)
app.include_router(public_invites_router)
app.include_router(backups_router)
app.include_router(admin_retention_router)
app.include_router(retention_policies_router)

# Wire structured logging + Prometheus metrics + request-id middleware.
from . import observability  # noqa: E402

observability.install(app)

# Install RFC 7807 problem+json handlers for HTTPException + validation.
from .problems import install_problem_handlers  # noqa: E402

install_problem_handlers(app)

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


# Health probes extracted to ``app.api_health`` — mounted below.


# ─────────────────────────────────────────────────────────────────────────
# Public JSON API (consumed by C# CatalogClient)
# ─────────────────────────────────────────────────────────────────────────

_CATALOG_CACHE_SECONDS = int(os.environ.get("NKS_WDC_CATALOG_CACHE_SECONDS", "60"))


# Public catalog read endpoints live in ``app.api_catalog`` — mounted
# above via ``app.include_router``. Keeping them out of this module
# makes it easier to eventually front them with a dedicated CDN worker.


# ─────────────────────────────────────────────────────────────────────────
# Config sync (public, runs behind reverse-proxy auth in prod)
# ─────────────────────────────────────────────────────────────────────────

# Device IDs are used as SQL primary keys and echoed back in responses.
# Restrict to the same shape the Electron client generates (lowercased
# alphanumerics + dashes, 3–64 chars) so garbage IDs can't pollute the
# device_configs table. This is defence-in-depth — SQLAlchemy already
# parameterizes the SQL, so the risk is cosmetic storage pollution, not
# injection.


# sync/config endpoints live in ``app.api_sync`` � mounted below.


# ─────────────────────────────────────────────────────────────────────────
# Auth (login / logout / session cookie)
# ─────────────────────────────────────────────────────────────────────────


@app.get("/", include_in_schema=False)
def root(user: Annotated[str | None, Depends(optional_user)] = None):
    return RedirectResponse("/admin" if user else "/login")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "login.html", _base_context(request, None)
    )


@app.post("/login", include_in_schema=False, dependencies=[Depends(require_csrf)])
@limiter.limit("5/minute")
def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Session = Depends(get_session),
):
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None:
        verify_dummy_password(password)
        return templates.TemplateResponse(
            request,
            "login.html",
            _base_context(request, None, error="Invalid username or password"),
            status_code=401,
        )
    if not verify_password(password, user.password_hash):
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

from .cookies import cookie_secure as _cookie_secure  # noqa: E402  — re-export for legacy callsites


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
        # Flash via short-lived SIGNED cookie so a MITM or another cookie
        # writer (same-site subdomain) can't inject messages rendered
        # into the admin HTML. HttpOnly still prevents JS tampering; the
        # signature prevents everything else.
        signed = _flash_signer().sign(f"{flash_kind}|{flash_message}".encode("utf-8"))
        response.set_cookie(
            "flash",
            signed.decode("ascii"),
            max_age=15,
            httponly=True,
            samesite="strict",
            secure=_cookie_secure(),
        )
    return response


def _pop_flash(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    # Attempt signed verification first; fall back to legacy plain format
    # so flashes set before the signing change don't vanish on upgrade.
    from itsdangerous import BadSignature, SignatureExpired

    try:
        raw = _flash_signer().unsign(cookie.encode("ascii"), max_age=30).decode("utf-8")
    except (BadSignature, SignatureExpired, UnicodeDecodeError):
        if "|" in cookie:
            raw = cookie  # legacy unsigned cookie, accept once during rollout
        else:
            return None
    if "|" not in raw:
        return None
    kind, _, message = raw.partition("|")
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


@app.get(
    "/admin/apps/{app_id}/edit", response_class=HTMLResponse, include_in_schema=False
)
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


@app.post(
    "/admin/apps/{app_id}/edit",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
)
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


@app.post(
    "/admin/apps/{app_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
)
def admin_delete_app(
    app_id: str,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    svc_delete_app(db, app_id)
    return _redirect("/admin", "success", f"Deleted {app_id}")


@app.post(
    "/admin/apps/{app_id}/releases",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
)
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


@app.post(
    "/admin/releases/{release_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
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


@app.post(
    "/admin/releases/{release_id}/downloads",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
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


@app.post(
    "/admin/downloads/{download_id}/delete",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
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


@app.post(
    "/admin/apps/{app_id}/auto-generate",
    include_in_schema=False,
    dependencies=[Depends(require_csrf)],
)
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
