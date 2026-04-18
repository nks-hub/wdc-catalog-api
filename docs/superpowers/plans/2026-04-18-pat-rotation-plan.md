# PAT rotation audit action — v0.48.0

## Problem

Today a user rotating a Personal Access Token has two separate
operations: `POST /api/v1/auth/tokens` (mint) + `DELETE
/api/v1/auth/tokens/{id}` (revoke old). The resulting audit trail is
two unrelated rows (`pat.created`, `pat.revoked`) — forensics cannot
tell whether a new PAT was a fresh issuance or a rotation of a
compromised one, and the old→new pairing is lost.

## Solution

Add `POST /api/v1/auth/tokens/{id}/rotate` which atomically:
- revokes the existing PAT row (same account only)
- mints a new PAT carrying over name, `read_only`, `ip_allowlist` and
  the remaining TTL (computed from `expires_at - now`, if set)
- emits a single `pat.rotated` audit event referencing both IDs in
  the detail payload

New PAT's plaintext is returned once in the response (same contract
as mint).

## Tasks

1. Add `pats.rotate(db, account_id, token_id)` helper in
   `app/pats.py` — atomic revoke-then-issue with attribute carry-over.
   Returns `(old_id, new_row, plaintext)` or `None` if not found /
   already revoked.
2. Add `POST /api/v1/auth/tokens/{token_id}/rotate` endpoint in
   `app/api_pats.py`. Response = `TokenCreateResponse` (reuse).
3. Emit `pat.rotated` audit event with detail `{old_token_id,
   new_name, new_prefix, read_only, ip_allowlist_count,
   expires_at}`. Wrap in try/except per house pattern.
4. Add `pat.rotated` to `SECURITY_ACTION_ALLOWLIST` in
   `app/observability.py` — rotations are a security signal.
5. Write `tests/test_pat_rotation.py` mirroring the
   `test_login_lockout_audit.py` pattern: module-scoped
   `_bootstrap_db`, `TestClient(app, client=("127.0.0.1", 50000))`.
   Cover: happy path rotate, wrong-user denied (404), already-revoked
   denied (404), audit row lands, allowlist sanity.
6. Bump to `v0.48.0` in `app/__init__.py` + `pyproject.toml`,
   prepend CHANGELOG entry.
7. Atomic conventional commit, tag, push, deploy.
