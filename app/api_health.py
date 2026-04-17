"""Liveness + readiness probes.

Split from ``main.py`` so the probe contract stays visible — K8s and
Docker orchestrators both reference these paths and a refactor of the
application-level routers shouldn't ripple through deployment manifests.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__
from .db import get_session


log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> JSONResponse:
    """Liveness probe — succeeds as long as the process is running.

    Deliberately does *not* hit the DB: a transient connection blip
    shouldn't kill the pod. Kubernetes liveness failures trigger a
    container restart; we want that reserved for real deadlocks.
    Readiness (route traffic or not) belongs on ``/readyz``.
    """
    return JSONResponse(
        {"ok": True, "service": "nks-wdc-catalog-api", "version": __version__}
    )


@router.get("/readyz")
def readyz(db: Session = Depends(get_session)) -> JSONResponse:
    """Readiness probe — verifies every upstream the service depends on.

    Checks:
    - DB round-trip (``SELECT 1``) — the catalog can't serve without it.
    - Blob backend (when configured) — optional, but catalog storage
      tiering needs S3/MinIO for large payloads.

    Failures return 503 with a per-dependency status so operators can
    see *which* dep is unhappy from a curl.
    """
    checks: dict[str, str] = {}
    overall_ok = True

    try:
        db.execute(select(1)).scalar()
        checks["db"] = "up"
    except Exception as exc:  # noqa: BLE001
        log.warning("readyz db probe failed: %s", exc)
        checks["db"] = "down"
        overall_ok = False

    from . import blob_store

    if blob_store.is_configured():
        try:
            # head_bucket is a cheap no-op — we only care whether the
            # endpoint is reachable with the configured credentials.
            client, cfg = blob_store._client()  # noqa: SLF001
            client.head_bucket(Bucket=cfg.bucket)
            checks["blob"] = "up"
        except Exception as exc:  # noqa: BLE001
            log.warning("readyz blob probe failed: %s", exc)
            checks["blob"] = "down"
            overall_ok = False

    body = {
        "ok": overall_ok,
        "service": "nks-wdc-catalog-api",
        "version": __version__,
        "checks": checks,
    }
    return JSONResponse(
        body,
        status_code=(
            status.HTTP_200_OK if overall_ok else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
    )


__all__ = ["router"]
