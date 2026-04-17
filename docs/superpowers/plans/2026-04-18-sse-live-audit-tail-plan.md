# SSE Live Audit Tail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a real-time audit-log tail on `/admin/audit` via Server-Sent Events, gated by RBAC, CSP-clean, no broker.

**Architecture:** In-process async pub/sub bus (`app/event_bus.py`) → `audit.emit()` publishes each DB-flushed row → `/admin/audit/stream` SSE endpoint yields JSON-per-event → admin.html Live toggle opens an `EventSource` and prepends rows with a fade-in that respects `prefers-reduced-motion`.

**Tech stack:** FastAPI `StreamingResponse`, `asyncio.Queue` per subscriber, vanilla `EventSource` on the client side (no dep).

---

## File Structure

| Path | Role |
|---|---|
| `app/event_bus.py` (new, ~80 LOC) | Process-local pub/sub + subscriber cap + drop-oldest backpressure |
| `app/audit.py` (edit) | Best-effort `bus.publish()` after DB flush |
| `app/admin_ui.py` (edit) | `GET /admin/audit/stream` SSE handler |
| `app/templates/audit.html` (edit) | Live toggle pill markup |
| `app/static/admin.js` (edit) | `EventSource` subscriber, row prepender |
| `app/static/admin.css` (edit) | Toggle pill + `.audit-row-new` fade-in |
| `tests/test_event_bus.py` (new) | Fanout, drop-oldest, subscriber cap, cancellation |
| `tests/test_audit_stream.py` (new) | Auth gate, event delivery, unauth 401 |

---

## Task 1: Event bus

**Files:**
- Create: `app/event_bus.py`
- Test:   `tests/test_event_bus.py`

- [ ] **Step 1: Write failing tests** — fanout to 2 subscribers, drop-oldest when queue full, subscriber cap rejects 33rd, cancellation removes subscriber.
- [ ] **Step 2: Implement** — module-level `_bus` singleton, `subscribe()` as async generator context manager, `publish()` non-blocking via `put_nowait` + drop-oldest fallback.
- [ ] **Step 3: `pytest tests/test_event_bus.py -x`** green.
- [ ] **Step 4: Commit** — `feat(event-bus): in-process pub/sub for live streaming`

## Task 2: Audit publish hook

**Files:**
- Modify: `app/audit.py`

- [ ] **Step 1:** After the existing `db.flush()` of the audit row, call `event_bus.publish(row_as_dict)` inside `try/except Exception: log.warning(...)` so bus failure never breaks the audit write.
- [ ] **Step 2: Regression test** — extend `tests/test_event_bus.py` or add to existing audit tests: fire `audit.emit()` inside a subscriber context, assert the event arrives.
- [ ] **Step 3: Full suite** `pytest -x -q` green.
- [ ] **Step 4: Commit** — `feat(audit): publish flushed rows to event bus`

## Task 3: SSE endpoint

**Files:**
- Modify: `app/admin_ui.py` (add handler)
- Test:   `tests/test_audit_stream.py`

- [ ] **Step 1:** Handler `GET /admin/audit/stream`, auth via `current_user`. Return `StreamingResponse` with media type `text/event-stream`; initial `event: connected\ndata: {}\n\n`; then async iterate subscriber, emit `event: audit\ndata: {json}\n\n`; heartbeat comment `: ping\n\n` every 15 s via `asyncio.wait_for`.
- [ ] **Step 2: Tests** — unauthenticated client gets 401/303. Authenticated client opens stream, concurrent `audit.emit()` call produces a line beginning with `event: audit`.
- [ ] **Step 3: Commit** — `feat(admin): /admin/audit/stream SSE endpoint`

## Task 4: Live toggle UI

**Files:**
- Modify: `app/templates/audit.html`, `app/static/admin.js`, `app/static/admin.css`

- [ ] **Step 1: Template** — add a pill toggle next to "Export CSV" that renders `<button class="live-toggle" data-live="off">Live ●</button>`.
- [ ] **Step 2: JS** — click handler opens `new EventSource('/admin/audit/stream')`; on `event: audit` build `<tr class="audit-row-new">` matching existing markup and prepend to `tbody`; on click again close the EventSource. Guard on `data-live` attribute flip.
- [ ] **Step 3: CSS** — `.live-toggle` pill with red dot when active; `.audit-row-new` fade-in 500 ms wrapped in `@media (prefers-reduced-motion: no-preference)`.
- [ ] **Step 4: Manual smoke** — `curl -N https://wdc.nks-hub.cz/admin/audit/stream` after login cookie, trigger `audit.emit` from another session, observe event.
- [ ] **Step 5: Commit** — `feat(ui): live audit tail toggle on /admin/audit`

## Task 5: Release

- [ ] **Step 1:** Bump `app/__init__.py` + `pyproject.toml` to `0.9.0`.
- [ ] **Step 2:** Append CHANGELOG entry with the feature summary.
- [ ] **Step 3:** Final `pytest -x -q` (target ~328 tests).
- [ ] **Step 4:** `git tag -a v0.9.0 -m "v0.9.0 — live audit tail"` + push tags.
- [ ] **Step 5:** `./scripts/deploy.sh` and verify `/healthz.version == "0.9.0"`.

---

## Notes for executing agent

- **Follow existing patterns**: admin handler audit emits + role gating; template `.audit-row-new` class uses existing `--accent-subtle` token; JS goes in the same `admin.js` IIFE as the copy-button wiring (CSP `script-src 'self'`).
- **Do not add deps**: all of this is stdlib + FastAPI already-imported.
- **Do not refactor** unrelated code; touch only the files listed.
