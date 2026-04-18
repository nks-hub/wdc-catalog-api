"""Full-state backup assembly — module-level so HTTP and scheduler
paths share one implementation."""

from __future__ import annotations

import glob as _glob
import gzip
import hashlib
import io
import json
import logging
import os
import time as _time
import zipfile
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select as _sel
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


def _prune_disk_backups(directory: str, keep_count: int) -> int:
    """Delete oldest files matching nks-wdc-backup-*.zip beyond the cap.

    Returns the number of files removed. ``keep_count <= 0`` is a
    never-prune escape hatch.
    """
    if keep_count <= 0:
        return 0
    try:
        pattern = os.path.join(directory, "nks-wdc-backup-*.zip")
        files = sorted(
            (f for f in _glob.glob(pattern) if os.path.isfile(f)),
            key=os.path.getmtime,
        )
    except OSError:
        return 0
    if len(files) <= keep_count:
        return 0
    to_delete = files[: len(files) - keep_count]
    removed = 0
    for path in to_delete:
        try:
            os.remove(path)
            removed += 1
        except OSError as exc:
            log.warning("backup prune: failed to remove %s: %s", path, exc)
    return removed


def run_scheduled_backup(db=None) -> dict:
    """Write a backup ZIP to the configured directory and prune retention.

    Mirrors ``retention.run_retention`` — when *db* is provided the caller
    owns the commit; otherwise we open our own session. Always records a
    ``SchedulerRun(job="backup")`` row (success + skip + failure) so the
    scheduler-runs history page surfaces it.
    """
    from .db import GlobalPolicy, SchedulerRun, session_factory

    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    t0 = _time.monotonic()

    def _record(session, summary, error):
        try:
            row = SchedulerRun(
                job="backup",
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
                duration_ms=int((_time.monotonic() - t0) * 1000),
                summary=summary,
                error=error,
            )
            session.add(row)
            session.flush()
        except Exception as exc:
            log.warning("scheduled backup: failed to record SchedulerRun: %s", exc)

    def _run(session) -> dict:
        policy = session.get(GlobalPolicy, 1)
        if policy is None or not policy.backup_enabled:
            return {"skipped": True, "reason": "backup_disabled"}
        directory = (policy.backup_directory or "").strip()
        if not directory:
            return {"skipped": True, "reason": "no_directory"}

        os.makedirs(directory, exist_ok=True)
        zip_bytes, filename, manifest = generate_backup_bytes(
            session, actor_email="scheduler@nks-wdc"
        )
        out_path = os.path.join(directory, filename)
        with open(out_path, "wb") as fh:
            fh.write(zip_bytes)

        pruned = _prune_disk_backups(directory, policy.backup_retention_count or 0)
        return {
            "path": out_path,
            "bytes": len(zip_bytes),
            "counts": manifest["counts"],
            "pruned": pruned,
        }

    if db is not None:
        try:
            summary = _run(db)
            _record(db, summary, None)
            db.flush()
            return summary
        except Exception as exc:
            _record(db, None, str(exc))
            raise
    else:
        session = session_factory()
        try:
            try:
                summary = _run(session)
                _record(session, summary, None)
                session.commit()
                return summary
            except Exception as exc:
                session.rollback()
                try:
                    err_s = session_factory()
                    err_row = SchedulerRun(
                        job="backup",
                        started_at=started_at,
                        finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
                        duration_ms=int((_time.monotonic() - t0) * 1000),
                        summary=None,
                        error=str(exc),
                    )
                    err_s.add(err_row)
                    err_s.commit()
                    err_s.close()
                except Exception:
                    pass
                raise
        finally:
            session.close()


def generate_backup_bytes(
    db: Session, *, actor_email: str | None = None
) -> tuple[bytes, str, dict[str, Any]]:
    """Build the full-state ZIP. Returns (zip_bytes, filename, manifest_dict).

    Moves the assembly out of the HTTP handler so both the download
    endpoint and the disk-write endpoint share identical data.
    """
    from . import __version__
    from .db import (
        Account,
        App,
        AuditEvent,
        ConsumedInvite,
        Download,
        GlobalPolicy,
        Release,
        SchedulerRun,
        User,
    )

    def _rows(stmt):
        return db.scalars(stmt).all()

    apps = [
        {
            "id": a.id,
            "display_name": a.display_name,
            "category": a.category,
            "description": a.description,
            "homepage": a.homepage,
            "license": a.license,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in _rows(_sel(App).order_by(App.id.asc()))
    ]
    releases = [
        {
            "id": r.id,
            "app_id": r.app_id,
            "version": r.version,
            "channel": r.channel,
            "released_at": r.released_at,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in _rows(_sel(Release).order_by(Release.id.asc()))
    ]
    downloads = [
        {
            "id": d.id,
            "release_id": d.release_id,
            "url": d.url,
            "os": d.os,
            "arch": d.arch,
            "archive_type": d.archive_type,
            "source": d.source,
            "headers": d.headers,
            "sha256": d.sha256,
            "size_bytes": d.size_bytes,
        }
        for d in _rows(_sel(Download).order_by(Download.id.asc()))
    ]

    # Accounts — explicit allowlist; credential fields intentionally absent.
    accounts = [
        {
            "id": a.id,
            "email": a.email,
            "role": a.role,
            "suspended_at": a.suspended_at.isoformat() if a.suspended_at else None,
            "token_version": a.token_version,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_login_at": a.last_login_at.isoformat() if a.last_login_at else None,
            "failed_login_count": a.failed_login_count,
            "locked_until": a.locked_until.isoformat() if a.locked_until else None,
            "totp_enabled": a.totp_enabled,
            "totp_enabled_at": a.totp_enabled_at.isoformat()
            if a.totp_enabled_at
            else None,
            # NB: password_hash, totp_secret, totp_recovery_hashes NOT included.
        }
        for a in _rows(_sel(Account).order_by(Account.id.asc()))
    ]

    users = [
        {
            "id": u.id,
            "username": u.username,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in _rows(_sel(User).order_by(User.id.asc()))
    ]

    invites = [
        {
            "nonce": i.nonce,
            "email": i.email,
            "consumed_at": i.consumed_at.isoformat() if i.consumed_at else None,
            "account_id": i.account_id,
        }
        for i in _rows(_sel(ConsumedInvite).order_by(ConsumedInvite.consumed_at.asc()))
    ]

    scheduler_runs = [
        {
            "id": r.id,
            "job": r.job,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "duration_ms": r.duration_ms,
            "summary": r.summary,
            "error": r.error,
        }
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
            "webhook_url": policy.webhook_url,
            "webhook_event_prefixes": policy.webhook_event_prefixes,
            "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
            "updated_by_email": policy.updated_by_email,
        }

    # Audit: gzip NDJSON so the archive stays compact.
    audit_gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=audit_gz_buf, mode="wb", compresslevel=6) as gz:
        for e in _rows(_sel(AuditEvent).order_by(AuditEvent.id.asc())):
            gz.write(
                (
                    json.dumps(
                        {
                            "id": e.id,
                            "created_at": e.created_at.isoformat()
                            if e.created_at
                            else None,
                            "actor_id": e.actor_id,
                            "actor_email": e.actor_email,
                            "action": e.action,
                            "resource_type": e.resource_type,
                            "resource_id": e.resource_id,
                            "ip": e.ip,
                            "user_agent": e.user_agent,
                            "detail": e.detail,
                        },
                        default=str,
                        ensure_ascii=False,
                    )
                    + "\n"
                ).encode("utf-8")
            )
    audit_bytes = audit_gz_buf.getvalue()

    # Assemble files list, then build manifest with per-file SHA-256.
    files: list[tuple[str, bytes]] = []

    def _add(name: str, payload: bytes) -> None:
        files.append((name, payload))

    def _dump(name: str, obj) -> None:
        _add(
            name,
            json.dumps(obj, indent=2, ensure_ascii=False, default=str).encode("utf-8"),
        )

    _dump("apps.json", apps)
    _dump("releases.json", releases)
    _dump("downloads.json", downloads)
    _dump("accounts.json", accounts)
    _dump("users.json", users)
    _dump("invites_consumed.json", invites)
    _dump("scheduler_runs.json", scheduler_runs)
    _dump("settings.json", settings)
    _add("audit.jsonl.gz", audit_bytes)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest = {
        "source": "nks-wdc-catalog-api",
        "version": __version__,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "exported_by": actor_email or "unknown",
        "files": [
            {"name": n, "size": len(p), "sha256": hashlib.sha256(p).hexdigest()}
            for n, p in files
        ],
        "counts": {
            "apps": len(apps),
            "releases": len(releases),
            "downloads": len(downloads),
            "accounts": len(accounts),
            "users": len(users),
            "invites_consumed": len(invites),
            "scheduler_runs": len(scheduler_runs),
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    zbuf = io.BytesIO()
    with zipfile.ZipFile(
        zbuf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as z:
        z.writestr("manifest.json", manifest_bytes)
        for n, p in files:
            z.writestr(n, p)

    filename = f"nks-wdc-backup-{ts}.zip"
    return zbuf.getvalue(), filename, manifest
