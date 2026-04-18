# PAT IP allowlist — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** let operators constrain a PAT to a set of IP CIDR ranges at mint time. When the request's client IP is outside every listed range, authentication fails with 401. Complements v0.30.0's read-only flag: scope-by-method + scope-by-network-origin.

**Architecture:** new `ip_allowlist` JSON column on `PersonalAccessToken` (list of CIDR strings). `get_current_account` (v0.30.0 already unpacks `(Account, PAT)`) gets a CIDR check step after the read-only check. Admin UI mint form + JSON API accept a comma/newline-separated input → parsed into CIDRs at save time. Empty / NULL = no restriction (back-compat).

**Tech stack:** stdlib `ipaddress` module — no new deps.

---

## Task 1 — schema + auth check + 5 tests (atomic commit)

**Files:**
- Modify: `app/db.py` — add column
- Modify: `app/pats.py::issue` — accept + persist `ip_allowlist`
- Modify: `app/devices.py::get_current_account` — CIDR check after read-only check
- New: `tests/test_pat_ip_allowlist.py` (5 tests)

### Schema

On `PersonalAccessToken` near `read_only`:
```python
ip_allowlist: Mapped[list | None] = mapped_column(JSON, nullable=True)
```

`JSON` is already imported. Auto-ALTER handles legacy rows (NULL = no restriction = back-compat).

### `pats.py::issue`

Add `ip_allowlist: list[str] | None = None` kwarg. Persist as-is if provided; NULL otherwise.

### `get_current_account` CIDR check

After the v0.30.0 `pat.read_only` block:

```python
allowlist = pat.ip_allowlist
if allowlist:
    import ipaddress
    client_host = request.client.host if request.client else None
    if not client_host:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid token"
        )
    try:
        client_addr = ipaddress.ip_address(client_host)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    in_range = False
    for cidr in allowlist:
        try:
            if client_addr in ipaddress.ip_network(cidr, strict=False):
                in_range = True
                break
        except ValueError:
            # A malformed CIDR in the list means that entry is ignored —
            # fail-closed on other entries still applies.
            continue
    if not in_range:
        # Return 401 (not 403) because the token is effectively invalid
        # for this IP — the client shouldn't get any hint that the
        # "same token from another IP" would work.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid token"
        )
```

**Important**: use 401 (not 403) on out-of-allowlist — don't leak that the token was otherwise valid, just from the wrong IP. This is the same rationale as treating bad-password + bad-username with identical latency + response.

### Tests — `tests/test_pat_ip_allowlist.py`

Pattern lifted from `tests/test_pat_read_only.py`. Direct `pats.issue` for the non-HTTP test setup + manipulate `ip_allowlist` column post-mint.

1. `test_pat_without_allowlist_works_from_any_ip` — mint with `ip_allowlist=None`; auth from `127.0.0.1` succeeds.
2. `test_pat_with_matching_cidr_succeeds` — `ip_allowlist=["127.0.0.0/8"]`; auth from `127.0.0.1` succeeds with 200.
3. `test_pat_with_non_matching_cidr_returns_401` — `ip_allowlist=["10.0.0.0/8"]`; auth from `127.0.0.1` (TestClient default) returns 401.
4. `test_pat_with_multiple_cidrs_any_match_succeeds` — `["10.0.0.0/8", "127.0.0.0/8"]`; auth from `127.0.0.1` succeeds.
5. `test_pat_with_malformed_cidr_is_skipped_gracefully` — `["not-a-cidr", "127.0.0.0/8"]`; valid entry still matches → 200.
6. `test_pat_with_only_malformed_cidrs_returns_401` — `["not-a-cidr", "also-bad"]` (all invalid) → 401.

To manipulate `request.client.host` in tests, TestClient always sends `127.0.0.1` — tests 3 and 6 rely on the default-loopback address NOT being in the configured allowlist. Good enough without needing to fake the host.

### Run

- `pytest tests/test_pat_ip_allowlist.py -x -v` — 6 green.
- `pytest -x -q` — 443 total (437 + 6).

### Commit #1

```
git add -A
git commit -m "feat(pats): ip_allowlist column + CIDR enforcement in auth"
git push origin main
```

## Task 2 — admin UI + JSON API surface + 2 tests

**Files:**
- Modify: `app/admin_ui.py::admin_create_account_token` — accept `ip_allowlist` form (newline-separated), parse + pass to `pats.issue`
- Modify: `app/api_pats.py::TokenCreateRequest` — add `ip_allowlist: list[str] | None = None`
- Modify: `app/admin_ui.py::_pat_view_rows` — include `ip_allowlist` (list)
- Modify: `app/templates/account.html` — textarea in mint form, `🌐 N IPs` pill in list

### Admin handler

Add `ip_allowlist_raw: Annotated[str, Form()] = ""` to `admin_create_account_token`. Parse:
```python
cidrs = [
    line.strip()
    for line in ip_allowlist_raw.replace(",", "\n").splitlines()
    if line.strip()
] or None
```
Pass `ip_allowlist=cidrs` into `_pats.issue`. Audit detail gains `"ip_allowlist_count": len(cidrs) if cidrs else 0`.

### JSON API

`TokenCreateRequest.ip_allowlist: list[str] | None = Field(default=None)`. Validate each entry is a parseable CIDR at request time (Pydantic validator) — reject malformed on POST so operators get immediate feedback instead of silent skip.

### Template

Mint form, below TTL + Read-only:
```html
<label>IP allowlist (optional, one CIDR per line)
  <textarea name="ip_allowlist_raw" rows="3" placeholder="10.0.0.0/8&#10;203.0.113.42/32"></textarea>
  <span class="hint">Blank = no restriction. Malformed entries at save time are silently skipped, but an all-malformed list fails-closed (401).</span>
</label>
```

List row, alongside the other pills:
```html
{% if t.ip_allowlist %}
  <span class="pill pill-warn" title="{{ t.ip_allowlist|join(', ') }}">🌐 {{ t.ip_allowlist|length }} IP{{ '' if t.ip_allowlist|length == 1 else 's' }}</span>
{% endif %}
```

### Extra tests — append to `tests/test_pat_ip_allowlist.py`

7. `test_admin_ui_mint_parses_allowlist_from_textarea` — POST with newline-separated CIDRs; DB row has parsed list.
8. `test_json_api_rejects_malformed_cidr_at_request_time` — POST with `ip_allowlist=["not-a-cidr"]`; 422 or 400.

## Task 3 — release v0.31.0

- Bump to `0.31.0`.
- Prepend CHANGELOG entry.
- `pytest -x -q` final.
- Commit + tag + push + deploy.

---

## Constraints

- **401, not 403, on out-of-allowlist** — don't hint at "this token would work from another IP."
- **Silent skip of malformed CIDRs in stored allowlist** — a corrupt DB value shouldn't make every request fail; each line independently.
- **But the JSON API validates at POST time** — operators get immediate error feedback when pasting.
- **Empty list = no restriction** (back-compat); only present-and-non-empty triggers enforcement.
- **IPv4 + IPv6 both supported** via `ipaddress` module.
- No new deps.
