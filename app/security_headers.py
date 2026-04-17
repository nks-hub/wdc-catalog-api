"""Transport-level security headers middleware.

Applied globally by ``install(app)`` from ``main.py``. Headers are
conservative defaults suitable for a self-hosted admin panel behind a
TLS-terminating reverse proxy (the actual setup on
``https://wdc.nks-hub.cz``):

- ``Strict-Transport-Security`` — force HTTPS for a year + preload.
  Disabled when ``NKS_WDC_CATALOG_DEV=1`` so local ``http://127.0.0.1``
  dev doesn't accidentally pin HTTPS in the browser.
- ``Content-Security-Policy`` — admin UI only needs its own stylesheets,
  inline small ``<style>`` blocks (Jinja template compat), and no JS
  bundles. Default-src 'self' + limited inline exceptions.
- ``X-Content-Type-Options: nosniff`` — MIME sniffing off.
- ``Referrer-Policy: strict-origin-when-cross-origin`` — don't leak
  path info on outbound links (catalog downloads to GitHub etc).
- ``X-Frame-Options: DENY`` — clickjacking defense.
- ``Permissions-Policy`` — turn off features the admin UI doesn't use.

JSON API responses inherit the same headers; CSP happens to be a no-op
for ``application/json`` content but HSTS + nosniff still apply.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request


# Template-specific: the admin panel renders no JavaScript today and the
# CSS + fonts are served from ``/static``. Keeping the policy strict
# makes future regressions (inline <script> injection, remote CDN creep)
# visible immediately in the browser console.
_CSP_DEFAULT = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

_HSTS = "max-age=31536000; includeSubDomains; preload"
_PERMISSIONS = (
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), payment=(), usb=()"
)


def install(app: FastAPI) -> None:
    """Register the security-headers middleware.

    Idempotent: calling twice stacks two middlewares but the effect is
    the same — headers get overwritten with identical values. Callers
    shouldn't rely on that, but it keeps tests that spin the app up
    multiple times from dying on "middleware already installed".
    """
    dev_mode = os.environ.get("NKS_WDC_CATALOG_DEV") == "1"

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        # Don't stamp these on the /metrics endpoint — Prometheus
        # scrapers are strict about content shape and CSP on a plain
        # text body is silly.
        path = request.url.path or ""
        if path.startswith("/metrics"):
            return response
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", _PERMISSIONS)
        # CSP applies to HTML + JSON alike; browsers only enforce on
        # HTML but stamping it everywhere keeps audit tools happy.
        response.headers.setdefault("Content-Security-Policy", _CSP_DEFAULT)
        if not dev_mode:
            response.headers.setdefault("Strict-Transport-Security", _HSTS)
        return response


__all__ = ["install"]
