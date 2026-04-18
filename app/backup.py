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
            "totp_enabled_at": a.totp_enabled_at.isoformat() if a.totp_enabled_at else None,
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
                            "created_at": e.created_at.isoformat() if e.created_at else None,
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
    with zipfile.ZipFile(zbuf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("manifest.json", manifest_bytes)
        for n, p in files:
            z.writestr(n, p)

    filename = f"nks-wdc-backup-{ts}.zip"
    return zbuf.getvalue(), filename, manifest
