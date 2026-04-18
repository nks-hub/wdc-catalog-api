# Auto-revoke idle admin sessions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** the nightly retention runner auto-revokes `admin_sessions` rows whose `last_seen_at` is older than a configurable threshold. Complements v0.10.0 manual session kill + v0.21.1 test-stability fix. When an admin forgets to log out from a coffee-shop laptop, the session dies on its own.

**Architecture:** one new `admin_session_idle_days` column on `GlobalPolicy` (default 0 = disabled — explicit opt-in for back-compat). `_do_retention` gets one extra SQL UPDATE sweeping matching rows. Summary dict gains `admin_sessions_auto_revoked`. Settings UI: one input in the Access fieldset.

---

## Task 1 — schema + runner + settings + tests + release (single sweep)

**Files:**
- Modify: `app/db.py` — add column on `GlobalPolicy`
- Modify: `app/retention.py::_do_retention` — auto-revoke sweep + return key + skipped-branch key
- Modify: `app/admin_ui.py::admin_save_settings` + GET handler policy dict + flash text
- Modify: `app/templates/settings.html` — input in "Access" fieldset
- New: `tests/test_admin_session_idle_revoke.py` (4 tests)
- Release bump to v0.34.0

### Schema

On `GlobalPolicy` after `admin_ip_allowlist`:
```python
admin_session_idle_days: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
```

Default 0 = disabled — explicit opt-in so legacy deployments don't suddenly kick admins out. Auto-ALTER handles legacy DBs.

### Runner — `_do_retention` in `app/retention.py`

After the `webhook_deliveries` sweep (shipped v0.23.0), add:

```python
admin_session_idle_days = policy_row.admin_session_idle_days if policy_row else 0
if admin_session_idle_days is None:
    admin_session_idle_days = 0
admin_sessions_auto_revoked = 0
if admin_session_idle_days > 0:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=admin_session_idle_days
    )
    from sqlalchemy import update as _update
    from .db import AdminSession
    result = session.execute(
        _update(AdminSession)
        .where(
            AdminSession.last_seen_at < cutoff,
            AdminSession.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc).replace(tzinfo=None))
    )
    admin_sessions_auto_revoked = int(result.rowcount or 0)
```

Extend the return dict with `"admin_sessions_auto_revoked": admin_sessions_auto_revoked`.

Patch the `{"skipped": True}` empty-summary return in `run_retention()` to include `"admin_sessions_auto_revoked": 0`.

Extend `admin_retention_run_now` flash text with `, admin_sessions_auto_revoked={summary.get('admin_sessions_auto_revoked', 0)}`.

### Settings

1. `admin_save_settings` gains `admin_session_idle_days: Annotated[int, Form()] = 0`. Extend `before`/`after` dicts. Set `row.admin_session_idle_days = max(0, min(int(admin_session_idle_days), 3650))`.

2. GET policy dict includes `admin_session_idle_days`.

3. `settings.html` "Access" fieldset — below the admin IP allowlist textarea:
   ```html
   <label>Auto-revoke idle admin sessions after (days)
     <input type="number" name="admin_session_idle_days" value="{{ policy.admin_session_idle_days }}" min="0" max="3650">
     <span class="hint">Nightly retention runner revokes sessions idle longer than this. 0 = disabled. Users are bounced to /login on their next request.</span>
   </label>
   ```

### Tests — `tests/test_admin_session_idle_revoke.py`

Pattern from `tests/test_webhook_deliveries_retention.py`. Use `_bootstrap_db` autouse fixture.

1. `test_sweep_revokes_stale_sessions`:
   - Seed three `AdminSession` rows: last_seen_at 40d ago, 5d ago, now. All `revoked_at=None`.
   - Set `GlobalPolicy.admin_session_idle_days = 30`.
   - Call `run_retention(db)`; commit.
   - Assert `summary["admin_sessions_auto_revoked"] == 1`.
   - Query DB — one row has `revoked_at IS NOT NULL`, two rows stay NULL.

2. `test_zero_means_disabled`:
   - Seed a session with `last_seen_at = 2000d ago`. Set `admin_session_idle_days = 0`.
   - Run retention. Assert `admin_sessions_auto_revoked == 0`. Row stays un-revoked.

3. `test_already_revoked_sessions_not_touched`:
   - Seed two sessions: one stale + already revoked 5d ago, one stale + not revoked.
   - Set `admin_session_idle_days = 30`. Run.
   - `admin_sessions_auto_revoked == 1` (only the not-yet-revoked one).
   - The previously-revoked row's `revoked_at` is unchanged.

4. `test_settings_save_persists_idle_days(admin_client)`:
   - POST `/admin/settings` with `admin_session_idle_days=14`.
   - Verify `GlobalPolicy.admin_session_idle_days == 14`.
   - Verify `settings.updated` audit detail carries `{"from": 0, "to": 14}`.

Direct-insert helper:
```python
from app.db import AdminSession, User, session_factory
from datetime import datetime, timezone, timedelta

with session_factory() as db:
    user_id = db.scalar(_sel(User).where(User.username == "admin")).id
    db.add(AdminSession(
        user_id=user_id,
        fingerprint="a" * 64,  # unique per test
        ip="127.0.0.1",
        user_agent="test",
        last_seen_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40),
    ))
    db.commit()
```

### Run

- `pytest tests/test_admin_session_idle_revoke.py -x -v` — 4 green.
- `pytest -x -q` — 459 total (455 + 4).

### Commit #1

```
git add -A
git commit -m "feat(retention): admin_sessions idle-revoke sweep + settings knob"
git push origin main
```

## Task 2 — release v0.34.0

- Bump to `0.34.0`.
- Prepend CHANGELOG.
- `pytest -x -q` final green.
- Commit + tag + push + deploy.

---

## Constraints

- **Default 0 = disabled** — back-compat. Legacy instances don't suddenly log admins out after upgrade.
- **Capped at 3650 days** (10 years) — same ceiling as other retention windows.
- **Revoked sessions stay revoked** — the sweep only flips `revoked_at` on rows where it's currently NULL.
- **No audit event** — the sweep runs nightly under `retention.manual_run` / scheduled retention context; the summary already surfaces in the `SchedulerRun(job="retention")` row the operator can browse. Per-session audit on bulk sweeps would be noisy.
- No new deps.
