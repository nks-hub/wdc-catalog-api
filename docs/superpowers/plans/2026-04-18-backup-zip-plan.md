# Full admin-state backup ZIP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** one-click `GET /admin/backup/export.zip` that bundles every human-editable table into a single downloadable archive plus a signed-ish manifest with per-file SHA-256 hashes. Gives operators a DR-friendly point-in-time dump they can stash off-site.

**Architecture:** single handler, in-memory ZIP via `zipfile.ZipFile(BytesIO, "w", ZIP_DEFLATED)`. Each entity is serialized as JSON (for small tables) or gzipped NDJSON (for audit, reusing the v0.15.0 helper). `manifest.json` at the root lists every file with byte length + SHA-256.

**Tech stack:** stdlib only (`zipfile`, `gzip`, `json`, `hashlib`, `io`). No new deps.

---

## Task 1 — endpoint + tests (atomic commit)

**Files:**
- Modify: `app/admin_ui.py` — new `GET /admin/backup/export.zip` handler
- Modify: `app/templates/ops.html` — "Download backup ZIP" button in a new "Backup" card
- New: `tests/test_backup_zip.py` (5 tests)

### Handler

```python
@router.get("/admin/backup/export.zip")
def admin_backup_export_zip(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
):
    import gzip, hashlib, io, json, zipfile
    from datetime import datetime, timezone
    from sqlalchemy import select as _sel

    from . import __version__
    from . import audit as _audit
    from .db import (
        Account, App, AuditEvent, ConsumedInvite, Download, GlobalPolicy,
        Release, SchedulerRun, User,
    )

    def _rows(stmt):
        return db.scalars(stmt).all()

    # Apps + releases + downloads — flat JSON arrays.
    apps = [
        {
            "id": a.id, "display_name": a.display_name, "category": a.category,
            "description": a.description, "homepage": a.homepage,
            "license": a.license,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in _rows(_sel(App).order_by(App.id.asc()))
    ]
    releases = [
        {
            "id": r.id, "app_id": r.app_id, "version": r.version,
            "channel": r.channel, "released_at": r.released_at,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in _rows(_sel(Release).order_by(Release.id.asc()))
    ]
    downloads = [
        {
            "id": d.id, "release_id": d.release_id, "url": d.url,
            "os": d.os, "arch": d.arch, "archive_type": d.archive_type,
            "source": d.source, "headers": d.headers,
            "sha256": d.sha256, "size_bytes": d.size_bytes,
        }
        for d in _rows(_sel(Download).order_by(Download.id.asc()))
    ]

    # Accounts — exclude password + TOTP secret. Leak risk too high.
    accounts = [
        {
            "id": a.id, "email": a.email, "role": a.role,
            "suspended_at": a.suspended_at.isoformat() if a.suspended_at else None,
            "token_version": a.token_version,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_login_at": a.last_login_at.isoformat() if a.last_login_at else None,
            "failed_login_count": a.failed_login_count,
            "locked_until": a.locked_until.isoformat() if a.locked_until else None,
            "totp_enabled": a.totp_enabled,
            "totp_enabled_at": a.totp_enabled_at.isoformat() if a.totp_enabled_at else None,
            # NB: totp_secret + totp_recovery_hashes + password_hash NOT included.
        }
        for a in _rows(_sel(Account).order_by(Account.id.asc()))
    ]

    users = [
        {"id": u.id, "username": u.username,
         "created_at": u.created_at.isoformat() if u.created_at else None,
         "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None}
        for u in _rows(_sel(User).order_by(User.id.asc()))
    ]

    invites = [
        {"nonce": i.nonce, "email": i.email,
         "consumed_at": i.consumed_at.isoformat() if i.consumed_at else None,
         "account_id": i.account_id}
        for i in _rows(_sel(ConsumedInvite).order_by(ConsumedInvite.consumed_at.asc()))
    ]

    scheduler_runs = [
        {"id": r.id, "job": r.job,
         "started_at": r.started_at.isoformat() if r.started_at else None,
         "finished_at": r.finished_at.isoformat() if r.finished_at else None,
         "duration_ms": r.duration_ms, "summary": r.summary, "error": r.error}
        for r in _rows(_sel(SchedulerRun).order_by(SchedulerRun.id.asc()))
    ]

    policy = db.get(GlobalPolicy, 1)
    settings = None
    if policy is not None:
        settings = {
            "snapshot_keep_last_n": policy.snapshot_keep_last_n,
            "snapshot_retain_days": policy.snapshot_retain_days,
            "max_bytes_per_user": policy.max_bytes_per_user,
            "registration_enabled": policy.registration_enabled,
            "default_role": policy.default_role,
            "banner_message": policy.banner_message,
            "audit_retention_days": policy.audit_retention_days,
            "require_2fa_for_admins": policy.require_2fa_for_admins,
            "webhook_url": policy.webhook_url,  # operator can decide whether to share
            "webhook_event_prefixes": policy.webhook_event_prefixes,
            "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
            "updated_by_email": policy.updated_by_email,
        }

    # Audit: gzip NDJSON so the archive stays small.
    audit_gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=audit_gz_buf, mode="wb", compresslevel=6) as gz:
        for e in _rows(_sel(AuditEvent).order_by(AuditEvent.id.asc())):
            gz.write((json.dumps({
                "id": e.id,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "actor_id": e.actor_id, "actor_email": e.actor_email,
                "action": e.action, "resource_type": e.resource_type,
                "resource_id": e.resource_id, "ip": e.ip,
                "user_agent": e.user_agent, "detail": e.detail,
            }, default=str, ensure_ascii=False) + "\n").encode("utf-8"))
    audit_bytes = audit_gz_buf.getvalue()

    # Assemble files + manifest.
    files: list[tuple[str, bytes]] = []
    def _add(name: str, payload: bytes):
        files.append((name, payload))

    def _dump(name: str, obj) -> None:
        _add(name, json.dumps(obj, indent=2, ensure_ascii=False, default=str).encode("utf-8"))

    _dump("apps.json", apps)
    _dump("releases.json", releases)
    _dump("downloads.json", downloads)
    _dump("accounts.json", accounts)
    _dump("users.json", users)
    _dump("invites_consumed.json", invites)
    _dump("scheduler_runs.json", scheduler_runs)
    _dump("settings.json", settings)
    _add("audit.jsonl.gz", audit_bytes)

    manifest = {
        "source": "nks-wdc-catalog-api",
        "version": __version__,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": f"{username}@admin.local",
        "files": [
            {"name": n, "size": len(p), "sha256": hashlib.sha256(p).hexdigest()}
            for n, p in files
        ],
        "counts": {
            "apps": len(apps), "releases": len(releases),
            "downloads": len(downloads), "accounts": len(accounts),
            "users": len(users), "invites_consumed": len(invites),
            "scheduler_runs": len(scheduler_runs),
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    # Build the ZIP.
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("manifest.json", manifest_bytes)
        for n, p in files:
            z.writestr(n, p)
    zbuf.seek(0)

    # Audit the export itself so abuse shows up on the trail.
    try:
        from .db import Account as _Acct
        from sqlalchemy import select as __sel
        acct = db.scalar(__sel(_Acct).where(_Acct.email == f"{username}@admin.local"))
        _audit.emit(
            db, request=request, actor=acct, action="backup.exported",
            resource_type="backup",
            detail={"bytes": zbuf.getbuffer().nbytes,
                    "counts": manifest["counts"]},
        )
    except Exception:
        pass

    from fastapi.responses import Response
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=zbuf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="nks-wdc-backup-{ts}.zip"',
            "Cache-Control": "no-store",
        },
    )
```

### Template addition — `app/templates/ops.html`

Add a new stat-card in the second row (alongside Retention scheduler + Webhooks + Observability — replaces or supplements the layout). Cleanest: insert a fourth card in the second row as a 4-column grid OR add a compact link under one of the existing cards. Pick a third row with a single full-width card to keep the symmetry clean:

```html
<div class="stat-grid stat-grid-3" style="margin-top: var(--space-4);">
  <div class="stat-card stat-card-wide">
    <h3>Backup</h3>
    <div class="stat-row">
      <span>Full JSON + audit snapshot</span>
      <b><a class="btn btn-primary btn-sm" href="/admin/backup/export.zip" download>Download ZIP</a></b>
    </div>
    <div class="stat-sub muted">
      Contains apps, releases, downloads, accounts (no secrets), users, invites_consumed, scheduler_runs, settings, audit.jsonl.gz, manifest.json (with per-file SHA-256).
    </div>
  </div>
</div>
```

`.stat-card-wide` already exists (from the dashboard top-actions card). It spans the full grid row.

### Tests — `tests/test_backup_zip.py`

Borrow fixture from `tests/test_scheduler_runs_history.py`.

1. `test_zip_endpoint_returns_correct_headers_and_magic`:
   ```python
   r = admin_client.get("/admin/backup/export.zip")
   assert r.status_code == 200
   assert r.headers["content-type"] == "application/zip"
   assert 'attachment; filename="nks-wdc-backup-' in r.headers["content-disposition"]
   assert r.content[:4] == b"PK\x03\x04"  # ZIP magic
   ```

2. `test_zip_contains_expected_entries`:
   ```python
   import io, zipfile
   r = admin_client.get("/admin/backup/export.zip")
   z = zipfile.ZipFile(io.BytesIO(r.content))
   names = set(z.namelist())
   assert {"manifest.json", "apps.json", "releases.json", "downloads.json",
           "accounts.json", "users.json", "invites_consumed.json",
           "scheduler_runs.json", "settings.json", "audit.jsonl.gz"} <= names
   ```

3. `test_manifest_sha256_matches_file_bytes`:
   ```python
   import hashlib, io, json, zipfile
   z = zipfile.ZipFile(io.BytesIO(r.content))
   manifest = json.loads(z.read("manifest.json"))
   for entry in manifest["files"]:
       data = z.read(entry["name"])
       assert hashlib.sha256(data).hexdigest() == entry["sha256"]
       assert len(data) == entry["size"]
   ```

4. `test_accounts_json_excludes_secrets`:
   ```python
   import json, zipfile, io
   z = zipfile.ZipFile(io.BytesIO(r.content))
   for row in json.loads(z.read("accounts.json")):
       assert "password_hash" not in row
       assert "totp_secret" not in row
       assert "totp_recovery_hashes" not in row
   ```

5. `test_export_emits_backup_exported_audit_event`:
   ```python
   admin_client.get("/admin/backup/export.zip")
   # Query DB for audit row
   from app.db import AuditEvent, session_factory
   from sqlalchemy import select as _sel
   with session_factory() as db:
       evt = db.scalar(_sel(AuditEvent).where(AuditEvent.action == "backup.exported").order_by(AuditEvent.id.desc()).limit(1))
   assert evt is not None
   assert "bytes" in (evt.detail or {})
   ```

6. `test_unauth_gets_login_redirect`:
   ```python
   with TestClient(app) as c:
       r = c.get("/admin/backup/export.zip", follow_redirects=False)
       assert r.status_code in (302, 303)
       assert "/login" in r.headers["location"]
   ```

Seed a few apps + accounts inside the fixture so the tests exercise non-empty data.

## Run

- `pytest tests/test_backup_zip.py -x -v` — 6 green.
- `pytest -x -q` — 390 total (384 + 6).

## Commit

```
git add -A
git commit -m "feat(backup): /admin/backup/export.zip full-state archive with manifest"
git push origin main
```

## Task 2 — release v0.20.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.20.0`.
- Prepend CHANGELOG.
- `pytest -x -q` final.
- `git commit -m "chore: v0.20.0 — full-state backup ZIP export"`
- `git tag -a v0.20.0 -m "v0.20.0 — full-state backup ZIP"`
- `git push origin main --tags`
- `./scripts/deploy.sh`, verify `/healthz.version == "0.20.0"`.

---

## Constraints

- **No secrets in the ZIP.** `password_hash`, `totp_secret`, `totp_recovery_hashes`, `admin_sessions.fingerprint`, pending-2FA cookies — none of those get serialized. A leaked backup must not be a credential-stuffing weapon.
- **Manifest is not cryptographically signed.** SHA-256 per file catches corruption + accidental edits. Signing the manifest itself is a v-future concern (needs a key-mgmt story).
- **ZIP assembly is in-memory.** On a small instance (~500 MB audit), that's fine. Past that, stream to disk or switch to `zipstream-new`. Document the limit.
- **No new deps** — `zipfile`, `gzip`, `hashlib`, `io`, `json` all stdlib.
- **No restore endpoint.** Restoring a backup is a DB-level operation (stop container, `sqlite3 .read` / `psql -f`, restart). Surface this in the CHANGELOG entry so nobody expects a one-click restore.
- **Audit the export itself** (`backup.exported` event) — so operators can prove who pulled a backup and when.
