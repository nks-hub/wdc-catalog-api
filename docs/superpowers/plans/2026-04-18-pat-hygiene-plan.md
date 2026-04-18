# PAT hygiene indicator — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: documented after-the-fact; inline implementation chosen for the trivial scope.

**Goal:** surface stale-unused Personal Access Tokens in the `/admin/account` list via a `⚠ unused Nd` amber pill, so operators spot forgotten CI keys at a glance.

**Architecture:** extend the existing `_pat_view_rows` shared render helper with a `stale_days: int | None` field. Template renders the pill conditionally. No schema, no settings knob — 30-day threshold is a sensible default and the pill itself teaches the threshold visually.

**Rule:** stale when (not revoked, not expired, and `(last_used_at or created_at)` is ≥ 30 days old).

---

## Files

- `app/admin_ui.py::_pat_view_rows` — compute `stale_days` + `last_used_ever`.
- `app/templates/account.html` — pill block inside the Status cell.
- `tests/test_pat_hygiene.py` (new) — 5 tests covering each branch.

## Tests shipped

1. `test_active_recently_used_pat_has_no_stale_pill` — used 5 days ago → no pill.
2. `test_never_used_old_pat_shows_stale_pill` — never used, 45 days since creation → `⚠ unused 45d`.
3. `test_used_long_ago_pat_shows_stale_pill` — last used 90 days ago → `⚠ unused 90d`.
4. `test_recently_created_never_used_is_not_stale` — created 3 days ago → no pill.
5. `test_revoked_pat_never_flagged_as_stale` — revoked rows carry only the revoked pill.

## Release notes (v0.29.0)

One minor, user-visible polish; no schema, no new audit events, no new deps.
