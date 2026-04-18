# PAT last-used source tracking — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** record the source IP + user-agent of each successful PAT authentication alongside `last_used_at`. Surface on `/admin/account` so operators can spot tokens used from unexpected origins without digging through audit.

**Architecture:** two new columns on `PersonalAccessToken`. `try_authenticate_pat` optionally accepts a `request` kwarg and stamps the source fields when matched. Admin UI renders a collapsible "source" cell showing `<ip> · <UA truncated>` next to the `Last used` column.

---

## Task 1 — schema + auth stamping + UI + tests + release (single sweep)

**Files:**
- Modify: `app/db.py` — two new columns
- Modify: `app/pats.py::try_authenticate_pat` — accept `request=None`, stamp on success
- Modify: `app/devices.py::get_current_account` — pass `request` into `try_authenticate_pat`
- Modify: `app/admin_ui.py::_pat_view_rows` — include the new fields in dict
- Modify: `app/templates/account.html` — new "Last source" column or inline `details`
- New: `tests/test_pat_last_used_source.py` (4 tests)
- Release bump to v0.33.0

### Schema

On `PersonalAccessToken` near `last_used_at`:
```python
last_used_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
last_used_ua: Mapped[str | None] = mapped_column(String(256), nullable=True)
```

45 char IP field matches the existing audit/session IP columns (accommodates IPv6). 256 for UA matches the admin_sessions column.

### `try_authenticate_pat` signature change

```python
def try_authenticate_pat(
    db: Session,
    bearer_value: str,
    *,
    request=None,  # kwarg: existing callers stay back-compat
) -> Optional[tuple[Account, PersonalAccessToken]]:
    ...
    try:
        row.last_used_at = now
        if request is not None:
            row.last_used_ip = (request.client.host if request.client else None)
            ua = request.headers.get("user-agent")
            row.last_used_ua = (ua or "")[:256] or None
        db.flush()
    except Exception:
        pass
    return account, row
```

### `get_current_account` call-site

Pass `request` kwarg:
```python
match = try_authenticate_pat(db, token, request=request)
```

### `_pat_view_rows`

Add:
```python
"last_used_ip": r.last_used_ip,
"last_used_ua": r.last_used_ua,
```

### Template

Replace the existing plain `Last used` cell with a compact-expand pair:
```html
<td class="nowrap">
  {% if t.last_used_at %}
    {{ t.last_used_at[:19] }}
    {% if t.last_used_ip or t.last_used_ua %}
      <details style="display: inline;">
        <summary class="muted" style="cursor: pointer; font-size: 0.8em;">source</summary>
        <div class="muted" style="font-size: 0.85em; margin-top: 4px;">
          {% if t.last_used_ip %}<code>{{ t.last_used_ip }}</code>{% endif %}
          {% if t.last_used_ua %}<br><span title="{{ t.last_used_ua }}" style="max-width: 32ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block;">{{ t.last_used_ua }}</span>{% endif %}
        </div>
      </details>
    {% endif %}
  {% else %}—
  {% endif %}
</td>
```

### Tests — `tests/test_pat_last_used_source.py`

Pattern lifted from `tests/test_pat_read_only.py`. Use TestClient with explicit `client=("127.0.0.1", 50000)` so IP is known.

1. `test_pat_auth_stamps_last_used_ip_and_ua`:
   - Mint RW PAT. Call any authenticated endpoint (e.g. `GET /api/v1/auth/me`) with the token + `User-Agent: test-agent/1.0`.
   - Query DB — row has `last_used_ip == "127.0.0.1"`, `last_used_ua == "test-agent/1.0"`, `last_used_at` populated.

2. `test_pat_auth_without_ua_header_leaves_ua_null`:
   - Some HTTP clients don't send UA. Strip UA header. Row has `last_used_ua IS NULL`, `last_used_ip` still set.

3. `test_ua_truncated_to_256_chars`:
   - UA of 500 chars. Row has `len(last_used_ua) == 256`.

4. `test_account_page_shows_source_details(admin_client)`:
   - Seed a PAT with `last_used_ip="203.0.113.42"` + `last_used_ua="curl/7.88"`.
   - GET `/admin/account` — body contains `203.0.113.42` and `curl/7.88` and the `<summary class="muted"` details wrapper.

### Run

- `pytest tests/test_pat_last_used_source.py -x -v` — 4 green.
- `pytest -x -q` — 455 total (451 + 4).

### Commit #1

```
git add -A
git commit -m "feat(pats): stamp last_used_ip + last_used_ua on auth success"
git push origin main
```

## Task 2 — release v0.33.0

- Bump to `0.33.0`.
- Prepend CHANGELOG.
- `pytest -x -q` final green.
- Commit + tag + push + deploy.

---

## Constraints

- **`request=None` kwarg default** — any caller of `try_authenticate_pat` that doesn't have a request (e.g. future tests / CLI tooling) still works; the stamp is simply skipped.
- **UA capped at 256 chars** — matches the `admin_sessions.user_agent` limit. Longer UAs (there are some pathological ones in the wild) get the suffix truncated; the prefix carries the interesting product info.
- **No audit event** — stamping the row on every auth is already a write; emitting an audit event per authenticated request would 10x the audit table growth. The stamp itself is the record.
- **No back-fill** — legacy rows stay with NULL IP/UA until their next use. That's fine; the feature only claims "last-used" source, not historical usage.
- No new deps.
