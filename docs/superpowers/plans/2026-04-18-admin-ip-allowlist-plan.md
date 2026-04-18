# Global admin-UI IP allowlist — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** let the instance owner lock the admin UI to a set of CIDR ranges (office, VPN). Mirrors v0.31.0's PAT IP allowlist but at the session / admin-UI layer. When an admin's browser IP is outside every configured CIDR, `current_user` bounces them to /login — same response they'd see without a cookie.

**Architecture:** new `admin_ip_allowlist: JSON nullable` column on `GlobalPolicy`. `current_user` in `app/auth.py` gets a CIDR check step after the fingerprint lookup. Blank/NULL = no restriction (back-compat). Malformed CIDRs in the stored list silently skipped; all-malformed or all-non-match → redirect to /login (302) like any other un-authenticated admin request.

**Tech stack:** stdlib `ipaddress`. No new deps.

---

## Task 1 — schema + auth check + settings + tests + release (single sweep)

**Files:**
- Modify: `app/db.py` — add column
- Modify: `app/auth.py::current_user` — CIDR check after fingerprint lookup
- Modify: `app/admin_ui.py::admin_save_settings` — form param + before/after diff
- Modify: `app/admin_ui.py::admin_settings` — GET handler passes the value into policy dict
- Modify: `app/templates/settings.html` — textarea in the "Access" fieldset
- New: `tests/test_admin_ip_allowlist.py` (5 tests)
- Release bump to v0.32.0

### Schema

On `GlobalPolicy` after `require_2fa_for_admins`:
```python
admin_ip_allowlist: Mapped[list | None] = mapped_column(JSON, nullable=True)
```

Blank / NULL = no restriction (back-compat for every legacy instance).

### `current_user` CIDR check

Add after the fingerprint block, before returning `username`:

```python
# Global admin IP allowlist (v0.32.0)
# When configured, the request.client.host must be inside at least
# one CIDR. Same 302-to-/login response as "no session cookie" so
# we don't leak the existence of the allowlist to scanners.
try:
    from .db import GlobalPolicy as _GlobalPolicy

    policy = db.get(_GlobalPolicy, 1)
    allowlist = policy.admin_ip_allowlist if policy else None
    if allowlist:
        import ipaddress

        client_host = request.client.host if request.client else None
        ok = False
        if client_host:
            try:
                client_addr = ipaddress.ip_address(client_host)
                for cidr in allowlist:
                    try:
                        if client_addr in ipaddress.ip_network(cidr, strict=False):
                            ok = True
                            break
                    except ValueError:
                        continue
            except ValueError:
                ok = False
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_302_FOUND,
                detail="Not authenticated",
                headers={"Location": "/login"},
            )
except HTTPException:
    raise
except Exception:  # noqa: BLE001
    # Fail-open on unexpected DB / parse errors — breaking the gate
    # wide open is better than locking operators out.
    pass
```

Place this block BEFORE the return of `username` at the end of `current_user`.

### Settings — handler + template

1. `admin_save_settings` gains `admin_ip_allowlist_raw: Annotated[str, Form()] = ""`. Parse same as PAT allowlist (newline/comma split). Persist as list or None. Extend `before`/`after` dicts with `admin_ip_allowlist`.

2. GET handler includes `admin_ip_allowlist` in the `policy` dict.

3. Template — inside the "Access" fieldset (already has the 2FA checkbox), add:
   ```html
   <label class="span-all">Admin IP allowlist (optional, one CIDR per line)
     <textarea name="admin_ip_allowlist_raw" rows="3" placeholder="10.0.0.0/8&#10;203.0.113.42/32">{% if policy.admin_ip_allowlist %}{% for c in policy.admin_ip_allowlist %}{{ c }}
{% endfor %}{% endif %}</textarea>
     <span class="hint">Blank = no restriction. Admins outside every CIDR get redirected to /login as if unauthenticated. Malformed entries are silently skipped; an all-invalid list locks everyone out — fail-closed.</span>
   </label>
   ```

### Tests — `tests/test_admin_ip_allowlist.py`

Critical: because this LOCKS THE ADMIN UI, tests MUST reset the allowlist to None in teardown or fixture prelude, otherwise subsequent suites fail wholesale. Use a module-level `autouse=True` fixture that clears `admin_ip_allowlist=None` after every test.

Pattern from `tests/test_2fa_enforcement.py`:

```python
@pytest.fixture(autouse=True)
def _clear_allowlist():
    yield
    from app.db import GlobalPolicy, session_factory
    with session_factory() as db:
        policy = db.get(GlobalPolicy, 1)
        if policy is not None:
            policy.admin_ip_allowlist = None
            db.commit()
```

Test cases:

1. `test_no_allowlist_admin_can_reach_admin_pages(admin_client)` — policy value None (default). GET `/admin` → 200.

2. `test_matching_cidr_allows_admin_access(admin_client)` — set `admin_ip_allowlist=["127.0.0.0/8"]`. GET `/admin` → 200. (TestClient's default `client=("testclient", ...)` would fail — override to `client=("127.0.0.1", 50000)` on the TestClient constructor.)

3. `test_non_matching_cidr_redirects_to_login` — set `admin_ip_allowlist=["10.0.0.0/8"]`. Make the TestClient send from 127.0.0.1. GET `/admin` → 302 with `Location: /login`.

4. `test_malformed_cidrs_all_fail_closed` — set `admin_ip_allowlist=["bogus", "also-bad"]`. GET → 302.

5. `test_settings_save_persists_allowlist(admin_client)` — POST `/admin/settings` with `admin_ip_allowlist_raw="127.0.0.0/8\n10.0.0.0/8"`. Verify `policy.admin_ip_allowlist == ["127.0.0.0/8", "10.0.0.0/8"]`. Verify `settings.updated` audit detail carries the diff.

6. `test_login_page_accessible_regardless_of_allowlist` — set non-matching allowlist. GET `/login` → 200 (the `/login` route is in `api_auth_ui.py`, NOT under the admin router that uses `current_user`, so this tests that the allowlist doesn't accidentally block login itself).

### Run

- `pytest tests/test_admin_ip_allowlist.py -x -v` — 6 green.
- `pytest -x -q` — 451 total (445 + 6).

### Commit #1

```
git add -A
git commit -m "feat(security): global admin_ip_allowlist on GlobalPolicy + current_user gate"
git push origin main
```

## Task 2 — release v0.32.0

- Bump to `0.32.0`.
- Prepend CHANGELOG.
- `pytest -x -q` final.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.32.0"`.

---

## Constraints

- **Fail-OPEN on unexpected errors** — DB lookup failure, weird exception → let the admin in. Breaking the gate when it's broken is better than locking everyone out. (Different from the per-PAT allowlist where fail-closed is the right call.)
- **Test teardown MUST clear the allowlist** — a test that leaves a mismatching allowlist set would break the other 440+ tests.
- **302 to /login matches the no-cookie response** — doesn't hint at the allowlist's existence.
- **No per-account allowlist** — too risky (admin's home IP changes, they're locked out). Global scope only; operators who need per-account can use PAT + v0.31.0.
- No new deps.
