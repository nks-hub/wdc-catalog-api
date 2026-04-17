# Live audit tail (SSE) — design

**Status:** Accepted · **Target release:** v0.9.0 · **Author:** autonomous-loop

## Problem

The admin panel's audit log (`/admin/audit`) is pull-only — operators
re-submit the filter form to see new rows. During an incident this is
exactly the wrong ergonomics: you want to *watch* login failures or
RBAC denials unfold in real time, not refresh every few seconds.

`nks_wdc_auth_failures_total` counters already surface spikes at the
Prometheus layer (alerts ship in `ops/prometheus/alerts.yml` as of
v0.8.1). What's missing is a row-level live view in the UI.

## Non-goals

- Multi-pod distribution (we run one container; pub/sub stays in-proc).
- Durability / replay — reconnecting clients see only new events.
- Historical backfill beyond the current audit table (already filterable).

## Architecture

Three layers, thin in each:

1. **`app/event_bus.py`** — process-local async pub/sub. One bus
   instance, one `asyncio.Queue` per subscriber (`maxsize=128`,
   drop-oldest-on-overflow so a slow EventSource can't pin memory).
   Publisher API: `bus.publish(event: dict)`; consumer API:
   `async for event in bus.subscribe(): ...` with automatic cleanup
   on cancellation. Bounded subscriber cap (`MAX_SUBSCRIBERS=32`)
   refuses new connections beyond the cap with a friendly 503.
2. **Audit integration** — `app/audit.emit()` gets a best-effort call
   into the bus after the DB row is flushed. Publish failure must
   never break the audit write path; wrap in try/except.
3. **SSE endpoint** — `GET /admin/audit/stream` (auth via
   `current_user`, role-gated ≥ `support`). Streams
   `text/event-stream`: a `connected` event on open, per-row
   `audit` events (JSON), and a comment heartbeat every 15 s so
   idle proxies don't drop the connection.

Client side:

4. **Admin UI "Live" toggle** — pill toggle on `/admin/audit` that
   opens an `EventSource` (CSP-clean, same-origin). New events are
   prepended to the table with a 500 ms accent-glow fade-in,
   respecting `prefers-reduced-motion`. Connection closes on toggle
   off or page navigation.

## Payload shape

```json
{
  "id": 1423,
  "created_at": "2026-04-18T01:58:12Z",
  "actor_id": 1,
  "actor_email": "admin@admin.local",
  "action": "login.ok",
  "resource_type": "account",
  "resource_id": "1",
  "ip": "127.0.0.1",
  "detail": null
}
```

Same shape the template already receives — the client renders into
an identical `<tr>`, filter-aware (drop events that don't match the
current URL filter).

## Risks / constraints

- **CPU / memory under subscriber load**: capped at 32 concurrent
  subscribers; each queue is 128 × ~500 B ≈ 65 KB. Worst case ~2 MB.
- **Auth refresh during stream**: session TTL is 24 h; short-lived
  streams are fine. Longer streams should reconnect naturally when
  the session expires (EventSource auto-reconnect).
- **CSP**: stream endpoint served from the same origin, so default
  `connect-src 'self'` covers it — no policy change needed.

## Testing strategy

- **Unit** (`tests/test_event_bus.py`): pub/sub fanout, queue bounded
  drop-oldest, subscriber cap, cancellation cleanup.
- **Integration** (`tests/test_audit_stream.py`): TestClient opens
  `/admin/audit/stream` via `stream=True`, publishes an audit event,
  asserts the SSE frame arrives. Second test asserts unauthenticated
  clients get 401.
- **UI smoke**: `test_admin_ui` already renders `/admin/audit`; add a
  marker assertion for the Live toggle.

## File inventory

- **Create:** `app/event_bus.py` (~80 LOC), `tests/test_event_bus.py`,
  `tests/test_audit_stream.py`.
- **Modify:** `app/audit.py` (publish hook, ~10 LOC),
  `app/admin_ui.py` (add `/admin/audit/stream` handler, ~50 LOC),
  `app/templates/audit.html` (Live toggle markup),
  `app/static/admin.js` (EventSource subscriber),
  `app/static/admin.css` (toggle pill + new-row glow).

## Phases

Each phase is one atomic commit with tests green before commit.

1. **`feat(event-bus)`** — `app/event_bus.py` + unit tests.
2. **`feat(audit)`** — `audit.emit` publishes to bus.
3. **`feat(admin)`** — `/admin/audit/stream` SSE endpoint + tests.
4. **`feat(ui)`** — Live toggle + JS subscriber + CSS.
5. **`chore`** — `v0.9.0` tag + CHANGELOG + deploy.
