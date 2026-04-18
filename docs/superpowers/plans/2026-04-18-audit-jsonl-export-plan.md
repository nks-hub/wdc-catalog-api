# Audit bulk JSON-lines export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** add `GET /admin/audit/export.jsonl.gz` — streaming, gzipped NDJSON bulk export of audit events honoring the same filter params as the HTML audit page. Completes the forensics story (CSV + live tail + retention already shipped).

**Architecture:** reuse the existing filter-building code from `admin_audit`, extract into a shared `_audit_filter_stmt(stmt, ...)` helper, stream rows via `StreamingResponse` + a generator that yields `gzip.compress(...)` chunks. NDJSON = one JSON object per line — trivially ingestible by `jq`, SIEM tools, logstash.

**Tech stack:** `gzip.GzipFile` wrapping an in-memory buffer, `StreamingResponse`, stdlib-only.

---

## Task 1 — endpoint + tests (atomic commit)

**Files:**
- Modify: `app/admin_ui.py` — extract `_audit_filter_stmt` helper + new `admin_audit_export_jsonl` handler
- Modify: `app/templates/audit.html` — add "Export JSONL" button next to existing "Export CSV"
- New: `tests/test_audit_jsonl_export.py` (4 tests)

### Extract helper

In `app/admin_ui.py`, above or inside `admin_audit`, factor:

```python
def _audit_filter_stmt(stmt, *, action="", resource_type="", resource_id="", actor_id=None):
    from .db import AuditEvent
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    return stmt
```

Update `admin_audit` (and `admin_audit_csv` if it exists — check `grep -n 'admin_audit.csv\|admin_audit_csv' app/admin_ui.py`) to call `_audit_filter_stmt(stmt, ...)`.

### New endpoint

```python
@router.get("/admin/audit/export.jsonl.gz")
def admin_audit_export_jsonl(
    username: Annotated[str, Depends(current_user)],
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
    actor_id: int | None = None,
    limit: int = 50000,
    db: Session = Depends(get_session),
):
    import gzip, io, json
    from sqlalchemy import select as _sel
    from fastapi.responses import StreamingResponse
    from .db import AuditEvent

    stmt = _audit_filter_stmt(
        _sel(AuditEvent),
        action=action, resource_type=resource_type,
        resource_id=resource_id, actor_id=actor_id,
    ).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(
        max(1, min(limit, 200000))
    )

    def generator():
        # Stream in 1000-row batches; gzip-compress each batch before
        # yielding so memory stays bounded regardless of limit.
        buf = io.BytesIO()
        gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6)
        batch_size = 1000
        rows = db.scalars(stmt).all()  # SQLAlchemy loads all at once; good enough
        for i, r in enumerate(rows, 1):
            line = json.dumps({
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "actor_id": r.actor_id,
                "actor_email": r.actor_email,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "detail": r.detail,
            }, default=str, ensure_ascii=False) + "\n"
            gz.write(line.encode("utf-8"))
            if i % batch_size == 0:
                gz.flush()
                data = buf.getvalue()
                buf.seek(0); buf.truncate()
                if data:
                    yield data
        gz.close()
        final = buf.getvalue()
        if final:
            yield final

    return StreamingResponse(
        generator(),
        media_type="application/gzip",
        headers={
            "Content-Disposition": 'attachment; filename="audit.jsonl.gz"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
```

### Template button

In `app/templates/audit.html`, next to the existing `<a class="btn" href="/admin/audit.csv…">Export CSV</a>`:

```html
<a class="btn" href="/admin/audit/export.jsonl.gz{% if qs %}?{{ qs[:-1] }}{% endif %}" download>Export JSONL.gz</a>
```

Place it immediately after the CSV link; both in the same `section-head` container.

### Tests — `tests/test_audit_jsonl_export.py`

Fixture pattern: borrow from `tests/test_global_search.py` (resets 2FA + TOTP, logs in as admin).

1. `test_jsonl_export_returns_gzip_with_correct_disposition`:
   ```python
   r = admin_client.get("/admin/audit/export.jsonl.gz")
   assert r.status_code == 200
   assert r.headers["content-type"] == "application/gzip"
   assert 'attachment; filename="audit.jsonl.gz"' in r.headers["content-disposition"]
   # Body is gzip-compressed — magic bytes 0x1f 0x8b.
   assert r.content[:2] == b"\x1f\x8b"
   ```

2. `test_jsonl_export_decompresses_to_ndjson`:
   ```python
   # Seed 3 distinct AuditEvent rows, then export, decompress, verify line count + JSON shape.
   import gzip, json
   r = admin_client.get("/admin/audit/export.jsonl.gz?action=test.jsonl-export")
   decoded = gzip.decompress(r.content).decode("utf-8")
   lines = [json.loads(line) for line in decoded.strip().splitlines()]
   assert len(lines) >= 3
   for obj in lines:
       assert "id" in obj and "action" in obj and "created_at" in obj
   ```

3. `test_jsonl_export_honors_filter`:
   ```python
   # Seed two events with distinct actions. Export filtered on one action.
   # Decompress; assert only the filtered action appears.
   ```

4. `test_jsonl_export_requires_auth`:
   ```python
   # TestClient without a session cookie.
   with TestClient(app) as c:
       r = c.get("/admin/audit/export.jsonl.gz", follow_redirects=False)
       assert r.status_code in (302, 303)
       assert "/login" in r.headers["location"]
   ```

## Run

- `pytest tests/test_audit_jsonl_export.py -x -v` — 4 green.
- `pytest -x -q` — 364 total (360 + 4).

## Commit

```
git add -A
git commit -m "feat(audit): gzipped JSONL bulk export endpoint with filters"
git push origin main
```

## Task 2 — release v0.15.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.15.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- `git commit -m "chore: v0.15.0 — gzipped audit JSONL bulk export"`
- `git tag -a v0.15.0 -m "v0.15.0 — audit JSONL bulk export"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.15.0"`.

## Constraints

- **No new deps** — `gzip` + `json` + `io` are stdlib.
- **Bounded limit**: default 50k, hard cap 200k to avoid OOM on pathological queries. Past 200k, use direct DB dump.
- **Filters MUST match the HTML page** — hence the shared `_audit_filter_stmt` helper.
- **No streaming-from-DB yield-per-row** — SQLAlchemy `db.scalars(stmt).all()` is fine up to 200k rows (each row ~1 KB → ~200 MB RAM worst case; acceptable for a one-off export). Don't optimize prematurely.
- `X-Content-Type-Options: nosniff` on the response so browsers don't reinterpret the gzip as text.
