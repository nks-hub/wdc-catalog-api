"""Idempotency-Key replay cache for mutating endpoints.

A client that retries the same POST (typically from a flaky mobile
network) should receive the original response rather than trigger the
mutation a second time. The standard HTTP idiom is the
``Idempotency-Key`` header — any random UUID the client generates.

Implementation
--------------

1. Caller sends ``Idempotency-Key: <uuid>`` on a POST request.
2. We hash ``(account_id, method, path, idempotency_key)`` and look up
   ``IdempotencyRecord`` by key_hash.
3. If a row exists and hasn't expired, replay its status + body.
4. Otherwise let the handler run; wrap its response and persist it
   under the same key.

TTL defaults to 24 hours. The retention runner (or a simple background
sweep) should periodically purge expired rows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import Account, IdempotencyRecord


IDEMPOTENCY_TTL_SECONDS = 24 * 3600
IDEMPOTENCY_HEADER = "Idempotency-Key"


def _hash_key(account_id: Optional[int], method: str, path: str, key: str) -> str:
    seed = f"{account_id or 'anon'}|{method.upper()}|{path}|{key}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _canonical_body_hash(body: object) -> str:
    """Hash a parsed request body in a stable way. ``None`` and empty dict
    both hash to the empty-body sentinel so bodyless endpoints keep
    working without special cases."""
    import json as _json

    if body is None:
        return hashlib.sha256(b"").hexdigest()
    if hasattr(body, "model_dump"):
        payload = body.model_dump(mode="json")
    elif isinstance(body, (dict, list)):
        payload = body
    else:
        payload = str(body)
    raw = _json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def replay_if_present(
    db: Session,
    request: Request,
    account: Optional[Account],
    *,
    body: object = None,
) -> Optional[Response]:
    """Return a cached response for this request, or None on miss.

    When ``body`` is supplied the handler opts into body-tamper detection:
    if a prior request with the same ``Idempotency-Key`` persisted a row
    carrying a different body hash, we raise 422 instead of replaying.
    Legacy rows without ``body_hash`` skip the check (backward-compat on
    the transition migration).
    """
    key = request.headers.get(IDEMPOTENCY_HEADER)
    if not key:
        return None
    if len(key) < 4 or len(key) > 128:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{IDEMPOTENCY_HEADER} must be 4–128 characters",
        )
    account_id = account.id if account else None
    key_hash = _hash_key(account_id, request.method, request.url.path, key)
    row = db.get(IdempotencyRecord, key_hash)
    if row is None:
        return None
    if row.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
        db.delete(row)
        return None
    if body is not None and row.body_hash is not None:
        if _canonical_body_hash(body) != row.body_hash:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"{IDEMPOTENCY_HEADER} reused with a different request body",
            )
    return Response(
        content=row.response_body,
        status_code=row.status_code,
        media_type=row.content_type,
        headers={"Idempotency-Replay": "true"},
    )


def persist(
    db: Session,
    request: Request,
    account: Optional[Account],
    *,
    status_code: int,
    body: bytes,
    content_type: str = "application/json",
    request_body: object = None,
) -> None:
    """Store a response under the Idempotency-Key if the client sent one.

    Uses INSERT-and-rollback to handle the concurrent-writer race: two
    requests with the same key may both land here when the first's
    ``replay_if_present`` miss hadn't yet committed. We attempt the
    INSERT inside a SAVEPOINT so an ``IntegrityError`` (PK collision)
    leaves the outer transaction intact and the loser just drops their
    row — the first writer's response remains authoritative.
    """
    key = request.headers.get(IDEMPOTENCY_HEADER)
    if not key:
        return
    account_id = account.id if account else None
    key_hash = _hash_key(account_id, request.method, request.url.path, key)
    expires = datetime.now(timezone.utc) + timedelta(seconds=IDEMPOTENCY_TTL_SECONDS)
    row = IdempotencyRecord(
        key_hash=key_hash,
        account_id=account_id,
        method=request.method.upper(),
        path=request.url.path,
        body_hash=_canonical_body_hash(request_body) if request_body is not None else None,
        status_code=status_code,
        response_body=body,
        content_type=content_type,
        expires_at=expires.replace(tzinfo=None),
    )
    try:
        with db.begin_nested():  # SAVEPOINT — auto-rollback on IntegrityError
            db.add(row)
            db.flush()
    except IntegrityError:
        # Another concurrent writer persisted the same key first.
        # First-write-wins — keep outer transaction alive.
        pass


def wrap_json(
    db: Session,
    request: Request,
    account: Optional[Account],
    payload: dict,
    *,
    status_code: int = 201,
    request_body: object = None,
) -> JSONResponse:
    """Convenience: serialize payload, persist it, return the JSONResponse."""
    import json as _json

    body = _json.dumps(payload).encode("utf-8")
    persist(
        db,
        request,
        account,
        status_code=status_code,
        body=body,
        content_type="application/json",
        request_body=request_body,
    )
    return JSONResponse(status_code=status_code, content=payload)


__all__ = [
    "IDEMPOTENCY_HEADER",
    "IDEMPOTENCY_TTL_SECONDS",
    "replay_if_present",
    "persist",
    "wrap_json",
]
