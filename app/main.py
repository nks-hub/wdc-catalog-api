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
from typing import AsyncIterator

from fastapi import (
    FastAPI,
    Request,
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    ensure_admin_user,
    issue_session,
)
from .cookies import cookie_secure as _cookie_secure
from .db import create_all, session_factory
from .devices import router as devices_router
from .service import (
    seed_from_json,
)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("nks-wdc-catalog")

_APP_DIR = Path(__file__).parent
_SEED_DIR = _APP_DIR / "data" / "apps"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
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

        # Prefer the token the template minted via ``base_context`` (see
        # templating._current_banner / base_context first-visit bootstrap)
        # so the form field and cookie always match on page one.
        existing = request.cookies.get("nks_wdc_csrf") or getattr(
            request.state, "csrf_token", None
        )
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

# Personal access token management (/api/v1/auth/tokens*) — user-owned
# API keys that authenticate alongside JWTs.
from .api_pats import router as pats_router  # noqa: E402

app.include_router(pats_router)

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

# Transport-level security headers (CSP, HSTS, X-Frame-Options, …).
# Applied last so it wraps every handler, including the problem-json
# and rate-limit exception handlers registered below.
from . import security_headers  # noqa: E402

security_headers.install(app)

# Install RFC 7807 problem+json handlers for HTTPException + validation.
from .problems import install_problem_handlers  # noqa: E402

install_problem_handlers(app)

app.mount("/static", StaticFiles(directory=_APP_DIR / "static"), name="static")

# Shared Jinja environment + base context live in ``app.templating``;
# aliased here so the admin HTML routes below keep their short names.


# ─────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────


# Health probes extracted to ``app.api_health`` — mounted below.


# Public catalog / sync / health routers are mounted above via the
# ``app.include_router`` calls — the JSON API endpoints live in their
# own focused modules (api_catalog, api_sync, api_health).


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


# /, /login, /logout live in ``app.api_auth_ui`` — mounted below.
from .api_auth_ui import router as auth_ui_router  # noqa: E402

app.include_router(auth_ui_router)


# /admin/* HTML routes live in ``app.admin_ui`` � mounted below.
from .admin_ui import router as admin_ui_router  # noqa: E402

app.include_router(admin_ui_router)
