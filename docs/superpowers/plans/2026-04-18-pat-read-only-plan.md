# PAT read-only flag — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** allow operators to mint Personal Access Tokens that can read but not write — a meaningful scope restriction without the complexity of per-endpoint granular scopes. Useful for monitoring dashboards, analytics scripts, and third-party integrations that only need catalog/audit data.

**Architecture:** one new boolean column on `PersonalAccessToken`. `try_authenticate_pat` returns the matched row so `get_current_account` can stash `request.state.pat_read_only` on the request. `get_current_account` then rejects write-method requests (POST/PUT/PATCH/DELETE) when the flag is set, returning 403 with a clear error body. Admin UI gets a checkbox at mint time + a `read-only` pill in the list; JSON API accepts a `read_only` flag in the `POST /api/v1/auth/tokens` body.

**Tech stack:** SQLAlchemy boolean column (auto-ALTER), existing FastAPI dep chain. No new deps.

---

## Task 1 — schema + auth core + tests (atomic commit)

**Files:**
- Modify: `app/db.py` — add column
- Modify: `app/pats.py` — rework `try_authenticate_pat` to return `(Account, PersonalAccessToken) | None`; update `issue` to accept `read_only`
- Modify: `app/devices.py::get_current_account` — unpack tuple, stash `request.state`, reject writes from RO tokens
- New: `tests/test_pat_read_only.py` (5 tests)

### Schema

On `PersonalAccessToken`:
```python
read_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
```

Auto-ALTER handles legacy rows (default False → unchanged behaviour).

### `app/pats.py::issue`

Signature gains `read_only: bool = False` kwarg:
```python
def issue(
    db: Session,
    *,
    account_id: int,
    name: str,
    expires_at: Optional[datetime] = None,
    read_only: bool = False,
) -> tuple[PersonalAccessToken, str]:
    ...
    row = PersonalAccessToken(
        account_id=account_id,
        name=name.strip()[:128] or "unnamed",
        token_hash=hashed,
        token_prefix=plaintext[:PREFIX_PERSISTED_LEN],
        expires_at=expires_at.replace(tzinfo=None) if expires_at else None,
        read_only=bool(read_only),
    )
    db.add(row); db.flush()
    return row, plaintext
```

### `app/pats.py::try_authenticate_pat`

Change return type to `Optional[tuple[Account, PersonalAccessToken]]`:

```python
def try_authenticate_pat(
    db: Session, bearer_value: str
) -> Optional[tuple[Account, PersonalAccessToken]]:
    ...
    for row in candidates:
        ...
        if match:
            account = db.get(Account, row.account_id)
            if account is None or account.suspended_at is not None:
                return None
            try:
                row.last_used_at = now
                db.flush()
            except Exception:
                pass
            return account, row
    return None
```

Update the `__all__` export list if needed.

### `app/devices.py::get_current_account`

```python
from fastapi import HTTPException, Request, status

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

def get_current_account(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_session),
) -> Account:
    from .pats import TOKEN_PREFIX, try_authenticate_pat

    token = credentials.credentials
    if token.startswith(TOKEN_PREFIX):
        match = try_authenticate_pat(db, token)
        if match is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
        account, pat = match
        request.state.pat_id = pat.id
        request.state.pat_read_only = bool(pat.read_only)
        if pat.read_only and request.method in _WRITE_METHODS:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Read-only PAT cannot perform write operations",
            )
        return account

    # ... existing JWT path unchanged (read_only=False semantics by default)
    return _authenticate_jwt(token, db)  # whatever the existing name is
```

**Carefully check the existing `get_current_account`** before writing — it may already take `request` / may have different control flow. Preserve any JWT branch unchanged and only extend the PAT branch. If the handler doesn't currently take `request`, add `request: Request` as the first parameter.

### Tests — `tests/test_pat_read_only.py`

Use a plain JSON-API path (via `/api/v1/auth/tokens` + `/api/v1/auth/me` or similar existing endpoints). Pattern lifted from `tests/test_pat_audit_events.py` or similar:

```python
def _mint_pat(read_only: bool) -> str:
    """Register a new account, mint a PAT with read_only flag, return plaintext."""
    ...
```

1. `test_rw_pat_allows_post` — mint `read_only=False` token, POST any JSON-API write endpoint, assert 2xx (or whatever non-403 status the endpoint returns).
2. `test_ro_pat_allows_get` — mint `read_only=True` token, GET `/api/v1/auth/me`, assert 200.
3. `test_ro_pat_rejects_post_with_403` — same RO token, POST `/api/v1/auth/tokens` (minting another token is a write operation), assert 403 with message containing "read-only" or similar.
4. `test_ro_pat_rejects_put_patch_delete` — parametrized over PUT / PATCH / DELETE against any existing write endpoint; all 403.
5. `test_invalid_pat_still_401_not_403` — random bad token gets 401, not 403 (clarifies that 403 is specifically the RO-write rejection).

### Run

- `pytest tests/test_pat_read_only.py -x -v` — 5+ green (parametrized).
- `pytest -q` — 433+ total (428 + ≥5).

### Commit #1

```
git add -A
git commit -m "feat(pats): read_only flag with write-method enforcement"
git push origin main
```

---

## Task 2 — admin UI + JSON API surface (atomic commit)

**Files:**
- Modify: `app/admin_ui.py::admin_create_account_token` — accept `read_only` form param
- Modify: `app/api_pats.py` — accept `read_only` in request body
- Modify: `app/admin_ui.py::_pat_view_rows` — include `read_only` in the dict
- Modify: `app/templates/account.html` — mint form gets a checkbox; PAT list row gets a `read-only` pill

### Handler — `admin_create_account_token`

```python
def admin_create_account_token(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    name: Annotated[str, Form()],
    ttl_days: Annotated[str, Form()] = "",
    read_only: Annotated[str, Form()] = "",
    db: Session = Depends(get_session),
) -> HTMLResponse:
    ...
    row, plaintext = _pats.issue(
        db, account_id=acct.id, name=name,
        expires_at=expires_at,
        read_only=bool(read_only),
    )
    ... audit detail gains "read_only": bool(read_only)
```

### JSON API — `app/api_pats.py`

Add `read_only: bool = Field(default=False)` on `TokenCreateRequest`. Thread into the `pats.issue` call.

### `_pat_view_rows`

Add `"read_only": bool(r.read_only)` to each dict.

### Template

Mint form, after the TTL input:
```html
<label class="checkbox">
  <input type="checkbox" name="read_only" value="1">
  Read-only (cannot POST/PUT/PATCH/DELETE)
</label>
```

List row, status cell alongside the existing active/expired/revoked/stale pills:
```html
{% if t.read_only %}<span class="pill pill-warn">read-only</span>{% endif %}
```

### Extra tests — append to `tests/test_pat_read_only.py`

6. `test_admin_ui_mint_creates_ro_token` — login as admin, POST `/admin/account/tokens` with `read_only=1`, assert the newly-minted row has `read_only=True` in the DB.
7. `test_account_page_shows_read_only_pill` — seed an RO PAT for the admin account, GET `/admin/account`, body contains `read-only` pill.

### Run
- `pytest -q` — 435+ total.

### Commit #2

```
git add -A
git commit -m "feat(pats): admin UI + JSON API accept read_only flag"
git push origin main
```

---

## Task 3 — release v0.30.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.30.0`.
- Prepend CHANGELOG.
- Final `pytest -q` green.
- Commit + tag + push + deploy.

---

## Constraints

- **Back-compat default `read_only=False`** — every existing PAT continues to behave as before.
- **401 vs 403 distinction matters** — invalid/expired/revoked stays 401 (authentication problem); RO-writes get 403 (authorization problem). Don't merge them.
- **Only HTTP method matters**, not endpoint path — simpler to reason about, harder to misconfigure.
- **PAT audit detail** — the `pat.created` event's detail gains `read_only: bool`. No new audit action.
- No new deps.
