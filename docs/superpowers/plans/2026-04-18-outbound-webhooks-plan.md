# Outbound webhook notifications — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** allow an owner to register a single Slack/Discord/generic-HTTP webhook URL. When configured, the server POSTs a small JSON payload for every audit event whose action matches a configured category prefix. Removes the need for someone to stare at `/admin/audit` during incidents.

**Architecture:** one dispatcher module (`app/webhooks.py`) with a thread-backgrounded `fire(event_dict)` function (non-blocking from the request path), reading config from `GlobalPolicy`. `audit.emit()` calls `webhooks.fire(payload)` right after `event_bus.publish(payload)` — same try/except pattern so webhook failure never breaks the audit write.

**Tech stack:** stdlib `urllib.request` (no new deps; don't pull httpx just for fire-and-forget), `concurrent.futures.ThreadPoolExecutor` with a small pool, two new `GlobalPolicy` columns, settings UI, tests via a mock HTTP server.

---

## File Structure

| Path | Role |
|---|---|
| `app/db.py` (edit) | Add `webhook_url: String(512)` + `webhook_event_prefixes: Text` (comma-separated prefixes, e.g. `permission.denied,login.failed`) to `GlobalPolicy` |
| `app/webhooks.py` (new, ~80 LOC) | `fire(event)` — thread-pool dispatch, prefix match, best-effort POST, timeout 5 s |
| `app/audit.py` (edit) | After `event_bus.publish(payload)`, call `webhooks.fire(payload)` inside its own try/except |
| `app/admin_ui.py` (edit) | `admin_save_settings` reads + persists new fields; `admin_settings` GET passes them into context. New `POST /admin/settings/webhook-test` that fires a synthetic event. |
| `app/templates/settings.html` (edit) | New "Notifications" fieldset with URL input + prefix list + "Send test event" button |
| `tests/test_webhooks.py` (new, ~170 LOC) | 5 tests: mock server receives POST, prefix filter honoured, disabled when url blank, audit write unaffected by webhook failure, "Send test event" button hits the URL |

---

## Task 1 — dispatcher + schema + tests (atomic commit)

**Files:** `app/db.py`, `app/webhooks.py`, `app/audit.py`, `tests/test_webhooks.py`

### Schema

On `GlobalPolicy` in `app/db.py`:
```python
webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
# Comma-separated action prefixes: "permission.denied,login.failed,session."
# A trailing dot ("session.") matches all child actions.
webhook_event_prefixes: Mapped[str] = mapped_column(
    Text, default="permission.denied,login.failed,session.killed,user.suspended,user.deleted,totp.login_failed",
    nullable=False,
)
```

### Dispatcher module — `app/webhooks.py`

```python
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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib import request as _urlreq
from urllib.error import URLError

log = logging.getLogger(__name__)

# Shared pool — sized conservatively; under sustained high audit
# throughput the audit write path outruns the webhook delivery and
# events just queue. ``max_workers=4`` keeps the thread-count small
# on a healthy deployment and bounds the fan-out during an incident
# when a spike of permission.denied rows would otherwise flood the
# receiver.
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wdc-webhook")
_POST_TIMEOUT = 5.0  # seconds


def _matches(action: str, prefixes: list[str]) -> bool:
    for p in prefixes:
        p = p.strip()
        if not p:
            continue
        if p.endswith("."):
            # Prefix match: "session." matches session.killed but not
            # "sessionless". Rejected-path: the trailing-dot form
            # prevents accidental under-matches.
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
    # Test hook: ``NKS_WDC_DISABLE_WEBHOOKS=1`` short-circuits everything
    # so CI doesn't accidentally hit real URLs if a test leaks config.
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
    try:
        with _urlreq.urlopen(req, timeout=_POST_TIMEOUT) as resp:
            if resp.status >= 300:
                log.warning(
                    "webhooks: POST %s returned %s", url, resp.status
                )
    except URLError as exc:
        log.warning("webhooks: POST %s failed: %s", url, exc)
    except Exception as exc:  # noqa: BLE001
        log.warning("webhooks: POST %s unexpected error: %s", url, exc)


def drain(timeout: float = 10.0) -> None:
    """Block until queued webhooks finish. Called only from tests."""
    _pool.shutdown(wait=True, cancel_futures=False)


def _reset_pool_for_tests() -> None:
    """Reopen the pool after a test-time ``drain()``."""
    global _pool
    if _pool._shutdown:
        _pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wdc-webhook")


__all__ = ["fire", "drain", "_reset_pool_for_tests"]
```

### Hook into `audit.emit`

In `app/audit.py`, right after the `event_bus.publish(payload)` call:

```python
try:
    from . import webhooks as _webhooks
    _webhooks.fire(payload, db=db)
except Exception as exc:
    log.warning("webhooks.fire failed: %s", exc)
```

Same pattern as the event_bus publish — defensive try/except so webhook failures never affect the audit write path.

### Tests — `tests/test_webhooks.py`

Use `http.server.HTTPServer` in a background thread as the mock target. Pattern:

```python
import json, socket, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

class _CapturingHandler(BaseHTTPRequestHandler):
    received: list = []  # class-level — tests reset

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length)
        type(self).received.append(json.loads(body.decode("utf-8")))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass  # silent


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
```

Fixture spins up the server + sets `GlobalPolicy.webhook_url = f"http://127.0.0.1:{port}/hook"` + resets `_CapturingHandler.received` + tears down. Remember to `os.environ.pop("NKS_WDC_DISABLE_WEBHOOKS", None)` before each test.

Tests:

1. `test_webhook_fires_on_matching_event` — config set, action=`permission.denied`, event_bus.publish indirectly via `audit.emit`. Assert `_CapturingHandler.received` captures one payload whose `event.action == "permission.denied"`.

2. `test_webhook_skipped_on_non_matching_action` — action=`snapshot.created`. Assert no POST received.

3. `test_webhook_disabled_when_url_blank` — clear `webhook_url`. `audit.emit` with a matching action. Assert no POST.

4. `test_webhook_failure_does_not_break_audit_emit` — point `webhook_url` at `http://127.0.0.1:1/unreachable`. Call `audit.emit`. Assert the DB row was still written. (Timeout risk: the `_post` will take 5 s; either reduce `_POST_TIMEOUT` for tests via monkeypatch OR assert on `fire()` returning immediately — it's fire-and-forget, should be near-instant on the calling thread.)

5. `test_prefix_match_wildcard` — configure `webhook_event_prefixes = "session."`. Emit `session.killed`, `session.killed_others`, `login.ok`. Assert the two session events POSTed; login.ok skipped.

Use `webhooks.drain(timeout=5)` + `webhooks._reset_pool_for_tests()` inside a fixture teardown so each test gets a clean pool.

## Run

- `pytest tests/test_webhooks.py -x -v` — 5 green.
- `pytest -x -q` — 369 total (364 + 5).

## Commit

```
git add -A
git commit -m "feat(webhooks): outbound audit-event dispatcher with prefix filter"
git push origin main
```

---

## Task 2 — settings UI + test-webhook button (atomic commit)

**Files:** `app/admin_ui.py`, `app/templates/settings.html`, extend `tests/test_webhooks.py`

### Settings handler

In `admin_save_settings`, add:
```python
webhook_url: Annotated[str, Form()] = "",
webhook_event_prefixes: Annotated[str, Form()] = "",
```

Extend `before`/`after` dicts with:
```python
"webhook_url": row.webhook_url,
"webhook_event_prefixes": row.webhook_event_prefixes,
```

Set:
```python
row.webhook_url = webhook_url.strip() or None
row.webhook_event_prefixes = webhook_event_prefixes.strip() or "permission.denied,login.failed,session.killed,user.suspended,user.deleted,totp.login_failed"
```

GET handler: pass both into `policy` dict.

### Test-webhook handler

```python
@router.post("/admin/settings/webhook-test", dependencies=[Depends(require_csrf)])
def admin_settings_webhook_test(
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import webhooks as _webhooks

    url, _ = _webhooks._resolve_config(db)
    if not url:
        return _redirect("/admin/settings", "error", "No webhook URL configured")
    # Fire a synthetic test event that's NOT subject to the prefix filter
    # so the admin sees immediate feedback regardless of their category
    # choices. Direct _post call bypasses _matches().
    _webhooks._pool.submit(_webhooks._post, url, {
        "source": "nks-wdc-catalog-api",
        "test": True,
        "event": {"action": "webhook.test", "actor_email": f"{username}@admin.local"},
    })
    return _redirect("/admin/settings", "success", "Test webhook enqueued")
```

### Settings template

In `app/templates/settings.html`, add a new fieldset between "Admin UI" and the submit button — OR after "Audit retention" which v0.13.0 added. Content:

```html
<fieldset class="form-fieldset">
  <legend>Outbound notifications</legend>
  <label class="span-all">Webhook URL
    <input type="url" name="webhook_url" value="{{ policy.webhook_url or '' }}" placeholder="https://hooks.slack.com/services/…">
    <span class="hint">Slack-compatible incoming webhook URL. Leave blank to disable. POSTed as <code>{ source, ts, event }</code>.</span>
  </label>
  <label class="span-all">Event prefixes
    <input type="text" name="webhook_event_prefixes" value="{{ policy.webhook_event_prefixes or '' }}">
    <span class="hint">Comma-separated. Trailing dot matches children: <code>session.</code> matches <code>session.killed</code>. Exact match without dot.</span>
  </label>
</fieldset>
```

And a separate button BELOW the main save form but still inside the page:

```html
{% if policy.webhook_url %}
<form method="post" action="/admin/settings/webhook-test" class="inline" style="margin-top: var(--space-3);">
  <input type="hidden" name="_csrf" value="{{ csrf_token }}">
  <button class="btn">Send test webhook</button>
</form>
{% endif %}
```

### Extra test

Append one to `tests/test_webhooks.py`:

```python
def test_settings_test_button_posts_synthetic_event(admin_client, mock_webhook):
    # mock_webhook fixture already set webhook_url + spawned capture server
    csrf = admin_client.cookies.get("nks_wdc_csrf") or ""
    r = admin_client.post("/admin/settings/webhook-test", data={"_csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    webhooks.drain(timeout=3)
    received = _CapturingHandler.received
    assert len(received) == 1
    assert received[0]["event"]["action"] == "webhook.test"
    assert received[0].get("test") is True
```

## Run

- `pytest tests/test_webhooks.py -x -v` — 6 green.
- `pytest -x -q` — 370 total.

## Commit

```
git add -A
git commit -m "feat(webhooks): settings UI + test-webhook button"
git push origin main
```

---

## Task 3 — release v0.16.0

- Bump to `0.16.0` in `app/__init__.py` + `pyproject.toml`.
- Prepend CHANGELOG entry.
- `pytest -x -q` final.
- `git commit -m "chore: v0.16.0 — outbound webhook notifications"`
- `git tag -a v0.16.0 -m "v0.16.0 — outbound webhooks"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.16.0"`.

---

## Constraints

- **No new deps** — `urllib` handles the POST; thread-pool is stdlib.
- **Never block the audit write path** — fire-and-forget via ThreadPoolExecutor; wrap everything in try/except.
- **`NKS_WDC_DISABLE_WEBHOOKS=1`** env for CI/test isolation even if a fixture leaks config.
- **5 s timeout** on `urlopen` so a hung receiver doesn't pile up workers.
- **Payload shape**: `{source, ts, event: {...the audit row as published to event_bus...}}` — trivially routable by Slack's "Incoming Webhook" handler (it ignores unknown top-level fields but renders `text` if you wanted a human string — skip that for now; this is a machine-to-machine signal).
- **No retries on POST failure** — webhooks are advisory; receivers are expected to be highly available or accept loss.
