"""Public catalog read endpoints — the JSON contract the C# daemon hits.

Extracted from ``main.py`` to keep the hot-path serialization code in a
focused module. The endpoints are intentionally stateless (no admin
dependencies, no cookies) so this router can move behind a dedicated
CDN-frontend worker later without dragging the admin UI along.
"""

from __future__ import annotations

import hashlib
import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ._cache import catalog_response_cache
from .db import get_session
from .schemas import AppDoc
from .service import build_catalog_document, get_app_document


router = APIRouter(tags=["catalog"])

_CATALOG_CACHE_SECONDS = int(os.environ.get("NKS_WDC_CATALOG_CACHE_SECONDS", "60"))


@router.get("/api/v1/catalog")
def api_get_catalog(request: Request, db: Session = Depends(get_session)) -> Response:
    """Public JSON catalog with ETag + Cache-Control.

    Hot path: an in-process TTL cache (``_cache.catalog_response_cache``)
    stores the serialized body + ETag + the ``generated_at`` timestamp
    keyed by content hash. A cache refresh whose hash matches the prior
    build reuses the prior timestamp — so clients doing naïve JSON diff
    don't see the catalog "change" every TTL window (code-review M7).

    Admin mutations invalidate the cache via ``invalidate_catalog()``.
    """
    cached = catalog_response_cache.get("catalog")
    if cached is None:
        doc = build_catalog_document(db)
        # ETag is derived from the content *excluding* ``generated_at``
        # (that timestamp intentionally stays stable across rebuilds
        # with identical catalog state — see M7). ``model_dump_json``
        # with ``exclude={"generated_at"}`` walks the doc once; the
        # response body then uses the same pydantic result with the
        # stable timestamp re-applied.
        etag_bytes = doc.model_dump_json(
            by_alias=True, exclude={"generated_at"}
        ).encode("utf-8")
        etag = '"' + hashlib.sha256(etag_bytes).hexdigest()[:16] + '"'

        stable = catalog_response_cache.get("stable")
        if stable is not None and stable["etag"] == etag:
            doc.generated_at = stable["generated_at"]
        else:
            catalog_response_cache.set(
                "stable",
                {"etag": etag, "generated_at": doc.generated_at},
                ttl=24 * 3600,
            )
        body = doc.model_dump_json(by_alias=True)
        cached = (etag, body)
        catalog_response_cache.set("catalog", cached)
    etag, body = cached
    headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={_CATALOG_CACHE_SECONDS}, stale-while-revalidate=300",
        "Vary": "Accept-Encoding",
        "CDN-Cache-Control": f"public, max-age={_CATALOG_CACHE_SECONDS * 10}",
    }
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content=body, media_type="application/json", headers=headers)


@router.get("/api/v1/catalog/{app_name}", response_model=AppDoc)
def api_get_app(app_name: str, db: Session = Depends(get_session)) -> AppDoc:
    doc = get_app_document(db, app_name)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown app '{app_name}'")
    return doc


__all__ = ["router"]
