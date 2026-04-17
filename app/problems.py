"""RFC 7807 Problem+JSON error format.

Installed by ``install_problem_handlers(app)``. Every ``HTTPException``
and Pydantic ``RequestValidationError`` now surfaces with Content-Type
``application/problem+json`` and the canonical shape::

    {
      "type":     "https://wdc.nks-hub.cz/errors/404",
      "title":    "Not Found",
      "status":   404,
      "detail":   "No snapshot for abc",
      "instance": "/api/v1/sync/config/abc",
      "request_id": "b3f7a..."
    }

We keep the legacy ``detail`` field populated so the large existing
test suite + deployed C# client continue to work unchanged. Additional
RFC 7807 fields are additive.
"""

from __future__ import annotations

import http
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


PROBLEM_MEDIA_TYPE = "application/problem+json"
PROBLEM_BASE_URL = os.environ.get(
    "NKS_WDC_PROBLEM_BASE_URL", "https://wdc.nks-hub.cz/errors"
)


def _phrase(status_code: int) -> str:
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return "Error"


def _request_id(request: Request) -> str | None:
    try:
        from .observability import request_id_var

        rid = request_id_var.get()
        return rid if rid and rid != "-" else None
    except Exception:  # pragma: no cover
        return None


def problem_response(
    request: Request,
    status_code: int,
    detail: Any,
    *,
    title: str | None = None,
    extra: dict | None = None,
    headers: dict | None = None,
) -> JSONResponse:
    body: dict = {
        "type": f"{PROBLEM_BASE_URL}/{status_code}",
        "title": title or _phrase(status_code),
        "status": status_code,
        "detail": detail,
        "instance": request.url.path,
    }
    rid = _request_id(request)
    if rid:
        body["request_id"] = rid
    if extra:
        body.update(extra)
    return JSONResponse(
        status_code=status_code,
        media_type=PROBLEM_MEDIA_TYPE,
        content=jsonable_encoder(body),
        headers=headers,
    )


def _prefers_html(request: Request) -> bool:
    """Classify the request so errors render nicely for browsers without
    breaking JSON API consumers.

    Rule: HTML only when the *Accept* header explicitly prefers HTML AND
    the path is an admin/login/root page. API clients (``/api/v1/*``)
    always get Problem+JSON even if their Accept happens to include
    ``text/html`` via ``*/*``.
    """
    path = request.url.path or ""
    if path.startswith(("/api/", "/metrics", "/healthz", "/readyz", "/docs")):
        return False
    accept = request.headers.get("accept", "")
    return "text/html" in accept.lower()


def _html_error_response(
    request: Request, status_code: int, detail: str, title: str | None = None
) -> Response:
    """Render the ``error.html`` template when available; fall back to a
    short inline HTML body so missing templates can't 500 the handler."""
    try:
        from .templating import base_context, templates

        # ``templates`` is a Jinja2Templates object with TemplateResponse.
        # The error template reads just request/title/status/detail.
        ctx = base_context(
            request,
            username=None,
            status_code=status_code,
            title=title or _phrase(status_code),
            detail=detail,
        )
        return templates.TemplateResponse(
            request, "error.html", ctx, status_code=status_code
        )
    except Exception:  # noqa: BLE001
        body = (
            f"<!doctype html><title>{status_code}</title>"
            f"<h1>{status_code} {_phrase(status_code)}</h1>"
            f"<p>{detail}</p>"
        )
        return Response(content=body, status_code=status_code, media_type="text/html")


def install_problem_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI instance.

    We register against both ``fastapi.HTTPException`` *and* the raw
    ``starlette.exceptions.HTTPException`` so that 404s raised by the
    router itself (for paths that never matched any route) still flow
    through our HTML/JSON content negotiator instead of Starlette's
    default JSON 404.
    """

    @app.exception_handler(StarletteHTTPException)
    async def _starlette_http_exc(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        if (
            _prefers_html(request)
            and 400 <= exc.status_code < 600
            and exc.status_code != 401
        ):
            return _html_error_response(
                request,
                exc.status_code,
                str(exc.detail) if exc.detail else _phrase(exc.status_code),
                title=_phrase(exc.status_code),
            )
        return problem_response(
            request,
            exc.status_code,
            exc.detail or _phrase(exc.status_code),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException) -> Response:
        if (
            _prefers_html(request)
            and 400 <= exc.status_code < 600
            and exc.status_code != 401
        ):
            # 401 stays JSON so the admin-UI redirect-to-/login middleware
            # keeps working (it watches for JSON shape).
            return _html_error_response(
                request,
                exc.status_code,
                str(exc.detail),
                title=_phrase(exc.status_code),
            )
        return problem_response(
            request,
            exc.status_code,
            exc.detail,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(
        request: Request, exc: RequestValidationError
    ) -> Response:
        if _prefers_html(request):
            return _html_error_response(
                request,
                422,
                "The submitted form data was invalid.",
                title="Invalid submission",
            )
        return problem_response(
            request,
            422,
            exc.errors(),
            title="Unprocessable Entity",
            extra={"errors": exc.errors()},
        )


__all__ = [
    "PROBLEM_MEDIA_TYPE",
    "problem_response",
    "install_problem_handlers",
]
