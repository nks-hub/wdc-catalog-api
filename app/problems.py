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

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


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


def install_problem_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI instance."""

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException) -> JSONResponse:
        return problem_response(
            request,
            exc.status_code,
            exc.detail,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Surface per-field validation errors under ``errors`` while
        # keeping ``detail`` set to the FastAPI default (list) so
        # existing clients that parsed the old shape still work.
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
