"""Service layer that bridges SQLAlchemy models and the API schemas.

Keeps routes thin — every persistence operation goes through a function
here so tests can exercise the business logic without spinning up the
HTTP layer.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from .db import App, Download, Release
from .generators import GenRelease
from .schemas import AppDoc, CatalogDocument, DownloadDoc, ReleaseDoc

log = logging.getLogger(__name__)


# ── Read side — assemble the CatalogDocument for the public API ────────

def build_catalog_document(db: Session) -> CatalogDocument:
    apps = db.scalars(
        select(App).options(selectinload(App.releases).selectinload(Release.downloads))
    ).all()

    return CatalogDocument(
        schema_version="1",
        generated_at=datetime.now(timezone.utc).isoformat(),
        apps={a.id: _app_to_schema(a) for a in apps},
    )


def get_app_document(db: Session, app_id: str) -> AppDoc | None:
    app = db.scalar(
        select(App)
        .where(App.id == app_id.lower())
        .options(selectinload(App.releases).selectinload(Release.downloads))
    )
    return _app_to_schema(app) if app else None


def _app_to_schema(app: App) -> AppDoc:
    return AppDoc(
        name=app.id,
        display_name=app.display_name or app.id,
        category=app.category or "other",
        description=app.description or "",
        homepage=app.homepage,
        license=app.license,
        releases=[
            ReleaseDoc(
                version=r.version,
                major_minor=r.major_minor,
                channel=r.channel,
                released_at=r.released_at,
                downloads=[
                    DownloadDoc(
                        url=d.url,
                        os=d.os,
                        arch=d.arch,
                        archive_type=d.archive_type,
                        source=d.source,
                        headers=d.headers,
                        sha256=d.sha256,
                        size_bytes=d.size_bytes,
                    )
                    for d in r.downloads
                ],
            )
            for r in app.releases
        ],
    )


# ── Write side — CRUD used by admin UI + auto-generators ───────────────

def list_apps(db: Session) -> list[App]:
    return list(db.scalars(select(App).order_by(App.id)).all())


def get_app(db: Session, app_id: str) -> App | None:
    return db.scalar(select(App).where(App.id == app_id.lower()))


def create_app(
    db: Session,
    *,
    app_id: str,
    display_name: str = "",
    category: str = "other",
    description: str = "",
    homepage: str | None = None,
    license: str | None = None,
) -> App:
    app_id = app_id.strip().lower()
    if not app_id:
        raise ValueError("app id must be non-empty")
    app = App(
        id=app_id,
        display_name=display_name or app_id,
        category=category,
        description=description,
        homepage=homepage,
        license=license,
    )
    db.add(app)
    db.commit()
    return app


def update_app(
    db: Session,
    app_id: str,
    *,
    display_name: str | None = None,
    category: str | None = None,
    description: str | None = None,
    homepage: str | None = None,
    license: str | None = None,
) -> App | None:
    app = get_app(db, app_id)
    if not app:
        return None
    if display_name is not None:
        app.display_name = display_name
    if category is not None:
        app.category = category
    if description is not None:
        app.description = description
    if homepage is not None:
        app.homepage = homepage or None
    if license is not None:
        app.license = license or None
    db.commit()
    return app


def delete_app(db: Session, app_id: str) -> bool:
    app = get_app(db, app_id)
    if not app:
        return False
    db.delete(app)
    db.commit()
    return True


def add_release(
    db: Session,
    app_id: str,
    version: str,
    *,
    major_minor: str = "",
    channel: str = "stable",
    released_at: str | None = None,
) -> Release | None:
    app = get_app(db, app_id)
    if not app:
        return None
    rel = Release(
        app_id=app.id,
        version=version,
        major_minor=major_minor or _major_minor(version),
        channel=channel,
        released_at=released_at,
    )
    db.add(rel)
    db.commit()
    return rel


def delete_release(db: Session, release_id: int) -> bool:
    rel = db.get(Release, release_id)
    if not rel:
        return False
    db.delete(rel)
    db.commit()
    return True


def add_download(
    db: Session,
    release_id: int,
    *,
    url: str,
    os: str = "windows",
    arch: str = "x64",
    archive_type: str = "zip",
    source: str = "manual",
    headers: dict | None = None,
) -> Download | None:
    rel = db.get(Release, release_id)
    if not rel:
        return None
    dl = Download(
        release_id=rel.id,
        url=url,
        os=os,
        arch=arch,
        archive_type=archive_type,
        source=source,
        headers=headers,
    )
    db.add(dl)
    db.commit()
    return dl


def delete_download(db: Session, download_id: int) -> bool:
    dl = db.get(Download, download_id)
    if not dl:
        return False
    db.delete(dl)
    db.commit()
    return True


def _major_minor(version: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


# ── Auto-generator integration ──────────────────────────────────────────

def apply_generated_releases(
    db: Session,
    app_id: str,
    releases: list[GenRelease],
    *,
    replace: bool = False,
) -> int:
    """Persist scraped releases. Skips versions that already exist on
    the app unless `replace=True` (which wipes ALL releases first).

    Returns the number of NEW releases inserted.
    """
    app = get_app(db, app_id)
    if not app:
        return 0

    if replace:
        db.execute(delete(Release).where(Release.app_id == app.id))
        db.commit()

    existing = {r.version for r in app.releases}
    inserted = 0
    for gen in releases:
        if gen.version in existing:
            continue
        rel = Release(
            app_id=app.id,
            version=gen.version,
            major_minor=gen.major_minor or _major_minor(gen.version),
            channel=gen.channel,
            released_at=gen.released_at,
        )
        db.add(rel)
        db.flush()  # need rel.id for downloads
        for gd in gen.downloads:
            db.add(Download(
                release_id=rel.id,
                url=gd.url,
                os=gd.os,
                arch=gd.arch,
                archive_type=gd.archive_type,
                source=gd.source,
                headers=gd.headers,
            ))
        inserted += 1
    db.commit()
    return inserted


# ── Seed from existing JSON files on first run ──────────────────────────

def seed_from_json(db: Session, data_dir: Path) -> int:
    """If the DB has zero apps, import every `*.json` file under
    `data_dir` so the service boots with a sensible catalog without
    requiring the admin to click Auto-generate for every app.
    """
    if db.scalar(select(App).limit(1)) is not None:
        return 0  # already seeded — no-op

    if not data_dir.is_dir():
        log.info("Seed dir not found, starting with empty catalog: %s", data_dir)
        return 0

    count = 0
    for path in sorted(data_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            app_id = (raw.get("name") or path.stem).lower()
            app = App(
                id=app_id,
                display_name=raw.get("display_name", app_id),
                category=raw.get("category", "other"),
                description=raw.get("description", ""),
                homepage=raw.get("homepage"),
                license=raw.get("license"),
            )
            db.add(app)
            db.flush()
            for r in raw.get("releases", []):
                rel = Release(
                    app_id=app.id,
                    version=r.get("version", "0.0.0"),
                    major_minor=r.get("major_minor") or _major_minor(r.get("version", "0.0.0")),
                    channel=r.get("channel", "stable"),
                    released_at=r.get("released_at"),
                )
                db.add(rel)
                db.flush()
                for d in r.get("downloads", []):
                    db.add(Download(
                        release_id=rel.id,
                        url=d.get("url", ""),
                        os=d.get("os", "windows"),
                        arch=d.get("arch", "x64"),
                        archive_type=d.get("archive_type", "zip"),
                        source=d.get("source", "seed"),
                        headers=d.get("headers"),
                    ))
            count += 1
        except Exception as exc:  # noqa: BLE001
            log.error("Seed parse failed for %s: %s", path, exc)
    db.commit()
    log.info("Seeded %d apps from %s", count, data_dir)
    return count
