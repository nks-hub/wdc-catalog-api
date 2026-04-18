"""Structured logging + Prometheus metrics + request-id middleware.

Call ``configure_logging()`` at module import time and
``install(app)`` from ``main.py`` to wire middleware + /metrics.

Logs land on stdout as JSON (``python-json-logger``) so container log
aggregators (Loki, CloudWatch, Datadog) can index fields directly. Each
line carries a ``request_id`` context var so every log produced during
one request can be correlated.

Metrics exposed at ``/metrics`` (Prometheus text format):

- ``http_requests_total{method,status,route}``
- ``http_request_duration_seconds`` histogram
- ``snapshot_created_total{kind}``
- ``retention_deleted_total``
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextvars import ContextVar

from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

try:
    # python-json-logger >= 3.0 moved the module.
    from pythonjsonlogger.json import JsonFormatter  # type: ignore
except ImportError:  # pragma: no cover - legacy path
    from pythonjsonlogger.jsonlogger import JsonFormatter  # type: ignore


REQUEST_ID_HEADER = "x-request-id"
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


# ── Metrics ────────────────────────────────────────────────────────────

HTTP_REQUESTS = Counter(
    "nks_wdc_http_requests_total",
    "Total HTTP requests",
    ["method", "status", "route"],
)

_HTTP_BUCKETS = (
    0.001,
    0.0025,
    0.005,
    0.0075,
    0.010,
    0.015,
    0.020,
    0.030,
    0.050,
    0.075,
    0.100,
    0.150,
    0.250,
    0.500,
    1.0,
    2.5,
    5.0,
)

HTTP_DURATION = Histogram(
    "nks_wdc_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "route"],
    buckets=_HTTP_BUCKETS,
)

SNAPSHOTS_CREATED = Counter(
    "nks_wdc_snapshot_created_total",
    "Snapshots committed via the backup / sync endpoints",
    ["kind"],
)

RETENTION_DELETED = Counter(
    "nks_wdc_retention_deleted_total",
    "Snapshots removed by the retention runner",
)

BLOB_ORPHAN_TOTAL = Counter(
    "nks_wdc_blob_orphan_total",
    "External blobs that failed to delete during retention — surfaces "
    "MinIO/S3 availability issues that would otherwise silently leak "
    "storage cost.",
)

AUTH_FAILURES = Counter(
    "nks_wdc_auth_failures_total",
    "Authentication / authorization failures bucketed by cause. "
    "Spikes in ``invalid_token`` or ``permission_denied`` are strong "
    "signals of credential-stuffing or lateral-movement attempts.",
    ["reason"],
)

SECURITY_EVENTS = Counter(
    "nks_wdc_security_events_total",
    "Security-significant audit events bucketed by action. "
    "Incremented from ``audit.emit`` for a curated subset of action "
    "names so Alertmanager can page on auth failures, RBAC denials, "
    "and session revocations without querying the DB directly. "
    "Complementary to ``nks_wdc_auth_failures_total`` — the latter "
    "counts pre-audit rejections (bad_password etc.) while this one "
    "tracks post-audit, fully-recorded security events.",
    ["action"],
)


# Curated allowlist of action prefixes/names that warrant a
# security-metric increment. Kept explicit (not "everything") so the
# counter's cardinality stays bounded and the meaning stays
# security-signal-shaped, not "every admin click".
SECURITY_ACTION_ALLOWLIST = frozenset({
    "login.failed",
    "login.locked_out",
    "login.lockout_armed",
    "totp.login_failed",
    "permission.denied",
    "password.change_failed",
    "user.suspended",
    "user.unlocked",
    "user.deleted",
    "user.tokens_revoked",
    "session.killed",
    "session.killed_others",
    "admin.global_session_kill",
    "totp.disabled",
    "backup.exported",
})


def inc_security_event(action: str) -> None:
    """Best-effort increment from ``audit.emit``. Never raises — metric
    failures must not block the audit write."""
    if action in SECURITY_ACTION_ALLOWLIST:
        try:
            SECURITY_EVENTS.labels(action=action).inc()
        except Exception:  # noqa: BLE001
            pass


# ── Logging config ─────────────────────────────────────────────────────


class _RequestIdInjector(logging.Filter):
    """Attach the current request_id context var to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging() -> None:
    """Root logger → JSON formatter on stdout. Idempotent."""
    root = logging.getLogger()
    if getattr(root, "_nks_configured", False):
        return
    handler = logging.StreamHandler()
    fmt = JsonFormatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s %(request_id)s",
        rename_fields={"asctime": "ts", "levelname": "level"},
    )
    handler.setFormatter(fmt)
    handler.addFilter(_RequestIdInjector())
    root.handlers = [handler]
    root.setLevel(os.environ.get("NKS_WDC_LOG_LEVEL", "INFO").upper())
    root._nks_configured = True  # type: ignore[attr-defined]


# ── Middleware ─────────────────────────────────────────────────────────


async def request_context_middleware(request: Request, call_next) -> Response:
    """Set request_id + collect metrics for every request."""
    req_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:16]
    token = request_id_var.set(req_id)
    route = _route_template(request)
    start = time.monotonic()
    try:
        response: Response = await call_next(request)
    except Exception:
        HTTP_REQUESTS.labels(method=request.method, status="500", route=route).inc()
        raise
    finally:
        HTTP_DURATION.labels(method=request.method, route=route).observe(
            time.monotonic() - start
        )
        request_id_var.reset(token)
    HTTP_REQUESTS.labels(
        method=request.method,
        status=str(response.status_code),
        route=route,
    ).inc()
    response.headers[REQUEST_ID_HEADER] = req_id
    return response


def _route_template(request: Request) -> str:
    """Return the matched route template (``/api/v1/devices/{id}``) so
    metric cardinality stays bounded. Falls back to the raw path if no
    route matched (404 cases)."""
    route = request.scope.get("route")
    if route is not None and hasattr(route, "path"):
        return route.path
    return request.url.path


# ── /metrics endpoint ──────────────────────────────────────────────────


def metrics_endpoint(request: Request) -> Response:
    """Prometheus scrape endpoint.

    When ``NKS_WDC_METRICS_TOKEN`` is set, callers must present it as a
    bearer token; scraping without the header returns 401. Unset (dev /
    trusted-network) means the endpoint is open, preserving backward
    compatibility.
    """
    expected = os.environ.get("NKS_WDC_METRICS_TOKEN")
    if expected:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != expected:
            return Response(status_code=401)
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── Installer ──────────────────────────────────────────────────────────


def install(app: FastAPI) -> None:
    configure_logging()
    app.middleware("http")(request_context_middleware)
    app.add_api_route(
        "/metrics",
        metrics_endpoint,
        methods=["GET"],
        include_in_schema=False,
        tags=["observability"],
    )


__all__ = [
    "configure_logging",
    "install",
    "request_id_var",
    "REQUEST_ID_HEADER",
    "HTTP_REQUESTS",
    "HTTP_DURATION",
    "SNAPSHOTS_CREATED",
    "RETENTION_DELETED",
    "BLOB_ORPHAN_TOTAL",
    "AUTH_FAILURES",
    "SECURITY_EVENTS",
    "SECURITY_ACTION_ALLOWLIST",
    "inc_security_event",
]
