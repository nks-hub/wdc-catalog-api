# Manual backup-to-disk — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** let operators click a button in the admin UI to write the v0.20.0 full-state ZIP to a server-side directory instead of downloading it in the browser. Useful for the "dump to disk before upgrading" workflow and sets up the ground for scheduled nightly backups in a later release.

**Architecture:** extract the v0.20.0 `admin_backup_export_zip` body into `app/backup.py::generate_backup_bytes(db, *, actor_email) -> (bytes, filename, manifest)`. The existing download handler becomes a thin wrapper. Add `GlobalPolicy.backup_directory` column. New `POST /admin/backup/run-now-to-disk` writes the ZIP to `<dir>/<filename>`, emits `backup.saved_to_disk` audit event, redirects with flash.

**Tech stack:** stdlib only. Same `zipfile + gzip + hashlib` tooling as v0.20.0.

---

## Task 1 — module extraction + schema + endpoint + UI + tests + release (single sweep)

**Files:**
- New: `app/backup.py` — holds `generate_backup_bytes(db, *, actor_email)` (pure data, no HTTP concerns)
- Modify: `app/admin_ui.py::admin_backup_export_zip` — thin wrapper around the new helper
- Modify: `app/db.py` — add `backup_directory` column on `GlobalPolicy`
- Modify: `app/admin_ui.py` — new `POST /admin/backup/run-now-to-disk`
- Modify: `app/admin_ui.py` (`admin_save_settings` + GET policy dict) + `app/templates/settings.html` — "Backup" fieldset with the directory field
- Modify: `app/templates/ops.html` — the existing full-width Backup card gets a "Save to disk" form when `backup_directory` configured
- New: `tests/test_backup_to_disk.py` (4 tests)
- Release bump to v0.26.0

### Module — `app/backup.py`

```python
"""Full-state backup assembly — module-level so HTTP and scheduler
paths share one implementation."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select as _sel
from sqlalchemy.orm import Session


def generate_backup_bytes(db: Session, *, actor_email: str | None = None) -> tuple[bytes, str, dict[str, Any]]:
    """Build the full-state ZIP. Returns (zip_bytes, filename, manifest_dict).

    Moves the assembly out of the HTTP handler so both the download
    endpoint and the disk-write endpoint share identical data.
    """
    from . import __version__
    from .db import (
        Account, App, AuditEvent, ConsumedInvite, Download, GlobalPolicy,
        Release, SchedulerRun, User,
    )

    # ... copy verbatim from admin_backup_export_zip, but return bytes
    #     instead of Response and drop the audit.emit (callers handle it).
    ...

    return zbuf.getvalue(), f"nks-wdc-backup-{ts}.zip", manifest
```

Faithfully port the v0.20.0 body — same table pulls, same secret-field omission in accounts, same manifest with SHA-256 per file.

### Schema

On `GlobalPolicy` after `webhook_event_prefixes`:
```python
backup_directory: Mapped[str | None] = mapped_column(String(512), nullable=True)
```

Auto-ALTER handles legacy DBs. Blank / NULL = feature off.

### Handlers

Refactor existing download:
```python
@router.get("/admin/backup/export.zip")
def admin_backup_export_zip(request, username, db):
    from . import audit as _audit
    from . import backup as _backup
    from .db import Account as _Acct
    from sqlalchemy import select as __sel

    zip_bytes, filename, manifest = _backup.generate_backup_bytes(
        db, actor_email=f"{username}@admin.local"
    )
    try:
        acct = db.scalar(__sel(_Acct).where(_Acct.email == f"{username}@admin.local"))
        _audit.emit(db, request=request, actor=acct, action="backup.exported",
                    resource_type="backup",
                    detail={"bytes": len(zip_bytes), "counts": manifest["counts"]})
    except Exception:
        pass
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
```

New disk-write endpoint:
```python
@router.post("/admin/backup/run-now-to-disk", dependencies=[Depends(require_csrf)])
def admin_backup_run_to_disk(request, username, db):
    import os

    from . import audit as _audit
    from . import backup as _backup
    from .db import GlobalPolicy

    policy = db.get(GlobalPolicy, 1)
    directory = (policy.backup_directory or "").strip() if policy else ""
    if not directory:
        return _redirect("/admin/ops", "error", "No backup directory configured")
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        return _redirect("/admin/ops", "error", f"Directory unusable: {exc}")

    zip_bytes, filename, manifest = _backup.generate_backup_bytes(
        db, actor_email=f"{username}@admin.local"
    )
    out_path = os.path.join(directory, filename)
    try:
        with open(out_path, "wb") as fh:
            fh.write(zip_bytes)
    except OSError as exc:
        return _redirect("/admin/ops", "error", f"Write failed: {exc}")

    acct = _admin_account(db, username)
    _audit.emit(
        db, request=request, actor=acct, action="backup.saved_to_disk",
        resource_type="backup",
        detail={
            "path": out_path, "bytes": len(zip_bytes),
            "counts": manifest["counts"],
        },
    )
    return _redirect("/admin/ops", "success",
                     f"Wrote {filename} ({len(zip_bytes)} bytes) to {directory}")
```

### Settings handler + template

1. **Handler** — add `backup_directory: Annotated[str, Form()] = ""` to `admin_save_settings`. Extend `before`/`after` dicts + GET policy dict. Set `row.backup_directory = backup_directory.strip() or None`.

2. **Template** — `app/templates/settings.html`, add a new "Backup" fieldset (similar to the "Outbound notifications" one shipped in v0.16.0), placed before or after "Outbound notifications":

   ```html
   <fieldset class="form-fieldset">
     <legend>Backup</legend>
     <label class="span-all">Backup directory
       <input type="text" name="backup_directory" value="{{ policy.backup_directory or '' }}" placeholder="/state/backups">
       <span class="hint">Server-side path. Blank = disable. The "Save to disk" button on <code>/admin/ops</code> writes a ZIP here.</span>
     </label>
   </fieldset>
   ```

### Ops card

In `app/templates/ops.html`, inside the existing full-width "Backup" card, add a conditional "Save to disk" form when `backup_directory` is configured. The `admin_ops` handler must pass `backup_directory_configured = bool(policy and (policy.backup_directory or "").strip())` into the template context.

```html
<div class="stat-row">
  <span>Full JSON + audit snapshot</span>
  <b>
    <a class="btn btn-primary btn-sm" href="/admin/backup/export.zip" download>Download ZIP</a>
    {% if backup_directory_configured %}
    <form method="post" action="/admin/backup/run-now-to-disk" class="inline" style="display: inline; margin-left: var(--space-2);">
      <input type="hidden" name="_csrf" value="{{ csrf_token }}">
      <button class="btn btn-sm">Save to disk</button>
    </form>
    {% endif %}
  </b>
</div>
```

### Tests — `tests/test_backup_to_disk.py`

Borrow `admin_client` fixture from `tests/test_backup_zip.py` (already disables 2FA + resets TOTP). Reset `backup_directory` at fixture teardown.

1. `test_generate_backup_bytes_returns_same_shape_as_endpoint`:
   - Call `backup.generate_backup_bytes(db, actor_email="x@admin.local")`.
   - Assert first element is bytes starting with `PK\x03\x04` (zip magic).
   - Open via `zipfile.ZipFile(io.BytesIO(...))` and assert `manifest.json` + `apps.json` + `audit.jsonl.gz` are all present.

2. `test_run_to_disk_writes_file(admin_client, tmp_path)`:
   - Set `GlobalPolicy.backup_directory = str(tmp_path)`.
   - POST `/admin/backup/run-now-to-disk` with CSRF.
   - Assert redirect 303 to `/admin/ops`.
   - Assert `tmp_path` now contains exactly one file matching `nks-wdc-backup-*.zip`.
   - Assert the file is valid gzip-zip (magic bytes).

3. `test_run_to_disk_no_directory_configured_errors(admin_client)`:
   - Clear `backup_directory` (NULL).
   - POST run-now-to-disk.
   - Redirect 303; next `/admin/ops` GET includes the flash "No backup directory configured".

4. `test_run_to_disk_emits_audit_event(admin_client, tmp_path)`:
   - Configure directory, POST.
   - Query latest `AuditEvent` where action=`backup.saved_to_disk`.
   - Assert detail carries `path`, `bytes`, `counts`.

### Run

- `pytest tests/test_backup_to_disk.py -x -v` — 4 green.
- `pytest -x -q` — 412 total (408 + 4).

### Commit #1

```
git add -A
git commit -m "feat(backup): extract to app/backup.py + /admin/backup/run-now-to-disk"
git push origin main
```

## Task 2 — release v0.26.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.26.0`.
- Prepend CHANGELOG.
- Final `pytest -x -q` green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.26.0"`.

---

## Constraints

- **Directory validation is best-effort** — `os.makedirs(..., exist_ok=True)` covers permission issues; don't try to chmod.
- **No retention / prune yet** — files accumulate. Defer retention to a v0.27.x that adds the scheduled job + prune logic.
- **Writes happen in the request thread** — a 50 MB ZIP write is fast (< 1s on SSD); no async I/O needed.
- **No new deps.**
- **Reuses v0.20.0 body verbatim** — do NOT alter the manifest shape or secret-field omission. Copy the assembly faithfully.
