"""Best-effort outbound HTTP notifications for audit events.

Runs every POST in a small shared thread pool so the request path
never blocks on the remote webhook. Uses ``urllib`` instead of
``httpx`` to avoid pulling a new dep for what is essentially a
fire-and-forget JSON POST with a 5-second timeout.
"""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib import request as _urlreq
from urllib.error import HTTPError, URLError

log = logging.getLogger(__name__)

# Shared pool — sized conservatively; under sustained high audit
# throughput the audit write path outruns the webhook delivery and
# events just queue. max_workers=4 keeps the thread-count small
# on a healthy deployment and bounds the fan-out during an incident
# when a spike of permission.denied rows would otherwise flood the
# receiver.
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wdc-webhook")
_POST_TIMEOUT = 5.0  # seconds


def _matches(action: str, prefixes: list[str]) -> bool:
    """Return True if ``action`` matches any of the configured prefixes.

    A prefix ending with "." is a wildcard: "session." matches "session.killed"
    but not "sessionless". A prefix without a trailing dot requires an exact match.
    """
    for p in prefixes:
        p = p.strip()
        if not p:
            continue
        if p.endswith("."):
            if action.startswith(p):
                return True
        else:
            if action == p:
                return True
    return False


def _resolve_config(db) -> tuple[str | None, list[str]]:
    """Load webhook URL + prefix list from the singleton GlobalPolicy row."""
    from .db import GlobalPolicy

    row = db.get(GlobalPolicy, 1)
    if row is None or not (row.webhook_url or "").strip():
        return None, []
    prefixes = [p.strip() for p in (row.webhook_event_prefixes or "").split(",") if p.strip()]
    return row.webhook_url.strip(), prefixes


def fire(event: dict[str, Any], *, db=None) -> None:
    """Dispatch ``event`` to the configured webhook if the action matches.

    Non-blocking: enqueues the POST on the shared thread pool and
    returns immediately. Never raises — webhook delivery is advisory.
    """
    if os.environ.get("NKS_WDC_DISABLE_WEBHOOKS") == "1":
        return

    try:
        if db is None:
            from .db import session_factory

            with session_factory() as fresh:
                url, prefixes = _resolve_config(fresh)
        else:
            url, prefixes = _resolve_config(db)
    except Exception as exc:  # noqa: BLE001
        log.warning("webhooks: config resolve failed: %s", exc)
        return

    if not url or not prefixes:
        return
    if not _matches(event.get("action", ""), prefixes):
        return

    payload = {
        "source": "nks-wdc-catalog-api",
        "ts": time.time(),
        "event": event,
    }
    _pool.submit(_post, url, payload)


def _post(url: str, payload: dict) -> None:
    event_action: str | None = None
    try:
        event_action = (payload.get("event") or {}).get("action")
    except Exception:
        pass

    body = json.dumps(payload, default=str).encode("utf-8")
    req = _urlreq.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "nks-wdc-catalog-api/webhook",
        },
    )
    t0 = time.monotonic()
    status_code: int | None = None
    err: str | None = None
    try:
        with _urlreq.urlopen(req, timeout=_POST_TIMEOUT) as resp:
            status_code = resp.status
            if resp.status >= 300:
                err = f"HTTP {resp.status}"
                log.warning("webhooks: POST %s returned %s", url, resp.status)
    except HTTPError as exc:
        status_code = exc.code
        err = f"HTTP {exc.code}"
        log.warning("webhooks: POST %s returned %s", url, exc.code)
    except URLError as exc:
        err = f"URLError: {exc}"
        log.warning("webhooks: POST %s failed: %s", url, exc)
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        log.warning("webhooks: POST %s unexpected error: %s", url, exc)
    finally:
        duration_ms = int((time.monotonic() - t0) * 1000)
        _record_delivery(
            url=url,
            event_action=event_action,
            status_code=status_code,
            duration_ms=duration_ms,
            error=err,
        )


def _record_delivery(*, url, event_action, status_code, duration_ms, error):
    """Best-effort delivery recorder — never raises. Called from the thread pool."""
    try:
        from .db import WebhookDelivery, session_factory
        with session_factory() as db:
            db.add(WebhookDelivery(
                url=url,
                event_action=event_action,
                status_code=status_code,
                duration_ms=duration_ms,
                error=(error[:512] if error else None),
            ))
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("webhooks: failed to record delivery: %s", exc)


def drain(timeout: float = 10.0) -> None:
    """Block until queued webhooks finish. Called only from tests."""
    _pool.shutdown(wait=True, cancel_futures=False)


def _reset_pool_for_tests() -> None:
    """Reopen the pool after a test-time ``drain()``."""
    global _pool
    if _pool._shutdown:
        _pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wdc-webhook")


__all__ = ["fire", "drain", "_reset_pool_for_tests"]
