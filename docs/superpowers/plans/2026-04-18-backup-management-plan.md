# Backup management page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** `/admin/ops/backups` — browse on-disk backup files in `GlobalPolicy.backup_directory`, manually trigger prune, and delete individual files. Completes the operator-side backup workflow.

**Architecture:** one new GET handler listing files via `os.scandir`, two POST handlers (prune-now + delete-one), Jinja template, link from `/admin/ops`.

**Tech stack:** stdlib `os` + existing `_prune_disk_backups` helper. No new deps.

---

## Task 1 — endpoint(s) + template + tests + release (single sweep)

**Files:**
- Modify: `app/admin_ui.py` — three new handlers
- New: `app/templates/backups.html`
- Modify: `app/templates/ops.html` — "Manage →" link under the Backup card
- New: `tests/test_backup_management.py` (6 tests)
- Release bump to v0.28.0

### Handlers

```python
import os
from datetime import datetime, timezone


@router.get("/admin/ops/backups", response_class=HTMLResponse)
def admin_backups_list(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    flash: Annotated[str | None, Cookie(alias="flash")] = None,
    db: Session = Depends(get_session),
) -> HTMLResponse:
    from .db import GlobalPolicy

    policy = db.get(GlobalPolicy, 1)
    directory = (policy.backup_directory or "").strip() if policy else ""
    retention_count = policy.backup_retention_count if policy else 7

    files: list[dict] = []
    total_bytes = 0
    dir_exists = bool(directory) and os.path.isdir(directory)

    if dir_exists:
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if not entry.is_file():
                        continue
                    name = entry.name
                    if not (name.startswith("nks-wdc-backup-") and name.endswith(".zip")):
                        continue
                    try:
                        stat = entry.stat()
                    except OSError:
                        continue
                    files.append({
                        "name": name,
                        "size_bytes": stat.st_size,
                        "size_mb": round(stat.st_size / 1024 / 1024, 2),
                        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    })
                    total_bytes += stat.st_size
        except OSError:
            dir_exists = False
    files.sort(key=lambda f: f["mtime"], reverse=True)

    total_mb = round(total_bytes / 1024 / 1024, 2) if total_bytes else 0

    ctx = base_context(
        request, username,
        directory=directory,
        dir_exists=dir_exists,
        files=files,
        total_mb=total_mb,
        retention_count=retention_count,
        flash=_pop_flash(flash),
    )
    response = templates.TemplateResponse(request, "backups.html", ctx)
    _clear_flash(response)
    return response


@router.post("/admin/ops/backups/prune-now", dependencies=[Depends(require_csrf)])
def admin_backups_prune_now(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from . import backup as _backup
    from .db import GlobalPolicy

    policy = db.get(GlobalPolicy, 1)
    directory = (policy.backup_directory or "").strip() if policy else ""
    if not directory or not os.path.isdir(directory):
        return _redirect("/admin/ops/backups", "error", "No backup directory configured")

    keep = policy.backup_retention_count or 0
    removed = _backup._prune_disk_backups(directory, keep)
    acct = _admin_account(db, username)
    _audit.emit(
        db, request=request, actor=acct, action="backup.pruned",
        resource_type="backup",
        detail={"directory": directory, "kept": keep, "removed": removed},
    )
    return _redirect(
        "/admin/ops/backups", "success",
        f"Prune complete — removed {removed} file(s), kept newest {keep}",
    )


@router.post("/admin/ops/backups/delete", dependencies=[Depends(require_csrf)])
def admin_backups_delete_one(
    request: Request,
    username: Annotated[str, Depends(current_user)],
    filename: Annotated[str, Form()],
    db: Session = Depends(get_session),
) -> RedirectResponse:
    from . import audit as _audit
    from .db import GlobalPolicy

    policy = db.get(GlobalPolicy, 1)
    directory = (policy.backup_directory or "").strip() if policy else ""
    if not directory or not os.path.isdir(directory):
        return _redirect("/admin/ops/backups", "error", "No backup directory configured")

    # Tight path-traversal guard: we accept only plain basenames matching
    # the backup filename convention. Anything with slashes or not matching
    # the prefix is rejected before we concat the path.
    basename = os.path.basename(filename or "")
    if (not basename
        or basename != filename
        or not basename.startswith("nks-wdc-backup-")
        or not basename.endswith(".zip")):
        return _redirect("/admin/ops/backups", "error", "Invalid filename")

    target = os.path.join(directory, basename)
    if not os.path.isfile(target):
        return _redirect("/admin/ops/backups", "error", "File not found")

    try:
        size = os.path.getsize(target)
    except OSError:
        size = None
    try:
        os.remove(target)
    except OSError as exc:
        return _redirect("/admin/ops/backups", "error", f"Delete failed: {exc}")

    acct = _admin_account(db, username)
    _audit.emit(
        db, request=request, actor=acct, action="backup.deleted",
        resource_type="backup",
        detail={"filename": basename, "directory": directory, "bytes": size},
    )
    return _redirect("/admin/ops/backups", "success", f"Deleted {basename}")
```

### Template — `app/templates/backups.html`

```html
{% extends "base.html" %}
{% block title %}Backup management — NKS WDC{% endblock %}
{% block content %}
<section class="section">
  <header class="section-head">
    <h1>Backup files ({{ files | length }})</h1>
    <a class="btn" href="/admin/ops">← Ops</a>
  </header>

  {% if not directory %}
    <div class="empty-state">
      <div class="empty-icon">📦</div>
      <h3>No backup directory configured</h3>
      <p>Set <code>backup_directory</code> in <a href="/admin/settings">Settings</a> to enable browsing.</p>
    </div>
  {% elif not dir_exists %}
    <div class="empty-state">
      <div class="empty-icon">⚠️</div>
      <h3>Directory not found</h3>
      <p>Configured path <code>{{ directory }}</code> does not exist or isn't readable by the service user.</p>
    </div>
  {% elif not files %}
    <p class="muted">
      Directory: <code>{{ directory }}</code>. No backup files found.
      Trigger one via <a href="/admin/backup/export.zip" download>Download ZIP</a>
      or enable the scheduled job in Settings.
    </p>
  {% else %}
    <p class="muted">
      Directory: <code>{{ directory }}</code> · {{ files | length }} file(s) · {{ total_mb }} MB total ·
      retention: keep last {{ retention_count if retention_count else '∞' }}
    </p>

    <form method="post" action="/admin/ops/backups/prune-now" class="inline"
          onsubmit="return confirm('Prune now? Oldest files beyond retention={{ retention_count }} will be removed.');"
          style="margin-bottom: var(--space-3);">
      <input type="hidden" name="_csrf" value="{{ csrf_token }}">
      <button class="btn btn-warn">Prune now</button>
    </form>

    <table class="data compact">
      <thead>
        <tr><th>Filename</th><th>Size</th><th>Modified</th><th>Actions</th></tr>
      </thead>
      <tbody>
        {% for f in files %}
        <tr>
          <td><code>{{ f.name }}</code></td>
          <td class="nowrap">{{ f.size_mb }} MB</td>
          <td class="nowrap">{{ f.mtime[:19] }}</td>
          <td class="actions">
            <form method="post" action="/admin/ops/backups/delete" class="inline"
                  onsubmit="return confirm('Delete {{ f.name }} permanently?');">
              <input type="hidden" name="_csrf" value="{{ csrf_token }}">
              <input type="hidden" name="filename" value="{{ f.name }}">
              <button class="btn btn-sm btn-warn">delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}
</section>
{% endblock %}
```

### `/admin/ops` wire-up

In the existing Backup `.stat-card-wide`, extend the `stat-sub` or row to include a "Manage →" link when `backup_directory_configured`:

```html
{% if backup_directory_configured %}
  <div class="stat-sub muted">
    <a class="btn btn-ghost btn-sm" href="/admin/ops/backups">Manage files →</a>
  </div>
{% endif %}
```

### Tests — `tests/test_backup_management.py`

Reuse `admin_client` fixture from `tests/test_scheduled_backup.py`. Use `tmp_path`.

1. `test_list_empty_when_no_directory`:
   - Clear `backup_directory`. GET `/admin/ops/backups` → 200, body contains "No backup directory configured".

2. `test_list_shows_files(admin_client, tmp_path)`:
   - Set `backup_directory = str(tmp_path)`. Pre-write `nks-wdc-backup-20260101T120000Z.zip` (dummy bytes).
   - GET page. Body contains the filename + ".zip".

3. `test_prune_now_removes_old_files(admin_client, tmp_path)`:
   - Configure dir + `backup_retention_count = 2`. Write 5 dummy backup files with varying mtimes.
   - POST `/admin/ops/backups/prune-now` with CSRF. Redirect 303.
   - Assert 2 files remain. Audit event `backup.pruned` exists with `detail.removed == 3`.

4. `test_delete_one_file(admin_client, tmp_path)`:
   - Write 2 dummy files. POST `/admin/ops/backups/delete` with `filename=<file1>`.
   - Redirect 303. Only file2 remains. Audit event `backup.deleted`.

5. `test_delete_rejects_path_traversal(admin_client, tmp_path)`:
   - Write a file outside the dir (in `tmp_path.parent`).
   - POST delete with `filename="../<name>"`. Redirect 303. The file OUTSIDE still exists (not deleted). Flash contains "Invalid filename".

6. `test_ops_page_links_to_backups_when_configured(admin_client, tmp_path)`:
   - Set dir. GET `/admin/ops`. Body contains `href="/admin/ops/backups"`.

### Run

- `pytest tests/test_backup_management.py -x -v` — 6 green.
- `pytest -x -q` — 423 total (417 + 6).

### Commit #1

```
git add -A
git commit -m "feat(backup): /admin/ops/backups list + prune + delete handlers"
git push origin main
```

## Task 2 — release v0.28.0

- Bump `app/__init__.py` + `pyproject.toml` to `0.28.0`.
- Prepend CHANGELOG.
- `pytest -x -q` final green.
- Commit + tag + push + deploy. Verify `/healthz.version == "0.28.0"`.

---

## Constraints

- **Path-traversal hardened** — delete endpoint accepts only plain basenames matching the `nks-wdc-backup-*.zip` convention. Any slash / prefix mismatch rejects with "Invalid filename" before touching the filesystem.
- **No listing of arbitrary files** — only files matching the backup naming convention show up in the listing. A misconfigured directory won't leak unrelated content.
- **No rename / upload endpoints** — keep the surface minimal: view, prune, delete.
- **Restore-from-file is out of scope** — matches v0.20.0's stance; restore remains an out-of-band DB operation.
- No new CSS, no new deps.
