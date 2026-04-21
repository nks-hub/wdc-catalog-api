"""Per-device config-sync JSON endpoints.

``POST /api/v1/sync/config``          upsert the current payload
``GET  /api/v1/sync/config/{id}``     fetch owner's snapshot
``HEAD /api/v1/sync/config/{id}``     existence probe (RFC-style)
``GET  /api/v1/sync/config/{id}/exists``  deprecated legacy existence check
``DELETE /api/v1/sync/config/{id}``   tombstone

Pulled out of ``main.py`` so the sync hot path is reviewable without
the 700+ lines of admin HTML it used to live next to.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .db import Account, DeviceConfig, get_session
from .device_ids import normalize_device_id
from .devices import get_current_account, optional_account
from .schemas import ConfigSyncEntry, ConfigSyncListResponse, ConfigSyncUploadRequest


log = logging.getLogger(__name__)
router = APIRouter(tags=["sync"])


@router.post("/api/v1/sync/config", response_model=ConfigSyncEntry)
def api_upsert_config(
    body: ConfigSyncUploadRequest,
    account: Account | None = Depends(optional_account),
    db: Session = Depends(get_session),
) -> ConfigSyncEntry:
    device_id = normalize_device_id(body.device_id)

    # Writes require authentication. Anonymous upsert let an attacker
    # squat any device_id (pre-register a row with ``user_id IS NULL``)
    # so a later legitimate push from that device would be treated as a
    # "first auth push" and auto-linked to whoever's token happened to
    # hit the endpoint. Requiring auth for every write closes the vector
    # and matches the pattern every other mutation on this service uses.
    if account is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Authentication required to push device config",
        )

    row = db.get(DeviceConfig, device_id)
    # Cross-account overwrite of a linked device remains a separate 403
    # (owned by another user) rather than 401 — the caller IS
    # authenticated, just not as the owner.
    if row is not None and row.user_id is not None and row.user_id != account.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Device is linked to another account"
        )

    # Snapshot the PREVIOUS payload before overwriting so the client can
    # roll back. Skipped on first push (no prior content).
    if row is not None and row.payload:
        from .api_sync_snapshots import create_sync_snapshot as _snap_prev

        try:
            _snap_prev(
                db,
                device_id=device_id,
                account_id=account.id,
                payload=row.payload,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("sync snapshot skipped for device=%s: %s", device_id, exc)

    if row is None:
        row = DeviceConfig(device_id=device_id, payload=body.payload)
        db.add(row)
    else:
        row.payload = body.payload
        row.updated_at = datetime.now(timezone.utc)

    # Auto-link device to account on first authenticated push.
    if row.user_id is None:
        row.user_id = account.id
    row.last_seen_at = datetime.now(timezone.utc)

    # Extract device metadata from payload if present so the device
    # list can show name/OS/arch/sites without opening the JSON blob.
    p = body.payload or {}
    if isinstance(p.get("settings"), dict):
        settings = p["settings"]
        if "sync.deviceName" in settings:
            row.name = settings["sync.deviceName"]
    if isinstance(p.get("sites"), list):
        row.site_count = len(p["sites"])
    if isinstance(p.get("system"), dict):
        sys_info = p["system"]
        if isinstance(sys_info.get("os"), dict):
            row.os = sys_info["os"].get("tag")
            row.arch = sys_info["os"].get("arch")

    db.flush()

    # Bridge legacy sync into the versioned snapshot store — every
    # authenticated push becomes an auto snapshot + HEAD move.
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
    except _snap.PayloadTooLarge as exc:
        # Legacy clients pre-date the snapshot size ceiling. Skip the
        # versioned write but log so operators spot the oversize cohort.
        log.warning("sync bridge skipped snapshot for device=%s: %s", device_id, exc)

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
    and 404 when the row belongs to a different account — keeping the
    existence leak surface identical across owned vs unowned ids.
    """
    normalized = normalize_device_id(device_id)
    row = db.get(DeviceConfig, normalized)
    if row is None:
        if not_found_ok:
            return None
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No snapshot for {normalized}")
    if row.user_id is None or row.user_id != account.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No snapshot for {normalized}")
    return row


@router.get("/api/v1/sync/config/{device_id}", response_model=ConfigSyncEntry)
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


@router.head("/api/v1/sync/config/{device_id}")
def api_head_config(
    device_id: str,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> Response:
    """Resource-oriented existence probe — 200 if a snapshot exists for
    the caller's device, 404 otherwise."""
    row = _require_owned_row(device_id, account, db, not_found_ok=True)
    if row is None:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    headers = {}
    if row.updated_at is not None:
        headers["Last-Modified"] = row.updated_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
    return Response(status_code=status.HTTP_200_OK, headers=headers)


@router.get(
    "/api/v1/sync/config/{device_id}/exists",
    response_model=ConfigSyncListResponse,
    deprecated=True,
    description="Deprecated — use HEAD /api/v1/sync/config/{device_id} instead.",
)
def api_exists_config(
    device_id: str,
    response: Response,
    account: Account = Depends(get_current_account),
    db: Session = Depends(get_session),
) -> ConfigSyncListResponse:
    # RFC 8594 sunset + deprecation signal.
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = (
        f'</api/v1/sync/config/{device_id}>; rel="successor-version"'
    )
    # ``_require_owned_row`` will normalize + validate; reuse its result
    # rather than calling ``normalize_device_id`` twice.
    row = _require_owned_row(device_id, account, db, not_found_ok=True)
    if row is None:
        return ConfigSyncListResponse(
            device_id=normalize_device_id(device_id), has_config=False
        )
    return ConfigSyncListResponse(
        device_id=row.device_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
        has_config=True,
    )


@router.delete("/api/v1/sync/config/{device_id}")
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


__all__ = ["router"]
