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


def _invalidate_catalog_cache() -> None:
    """Called after every catalog-mutating commit. Late-import keeps
    ``service.py`` free of a ``_cache`` dependency when catalog-caching
    is disabled in tests."""
    try:
        from ._cache import invalidate_catalog

        invalidate_catalog()
    except Exception:
        pass


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
    _invalidate_catalog_cache()
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
    _invalidate_catalog_cache()
    return app


def delete_app(db: Session, app_id: str) -> bool:
    app = get_app(db, app_id)
    if not app:
        return False
    db.delete(app)
    db.commit()
    _invalidate_catalog_cache()
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
    _invalidate_catalog_cache()
    return rel


def delete_release(db: Session, release_id: int) -> bool:
    rel = db.get(Release, release_id)
    if not rel:
        return False
    db.delete(rel)
    db.commit()
    _invalidate_catalog_cache()
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
    _invalidate_catalog_cache()
    return dl


def delete_download(db: Session, download_id: int) -> bool:
    dl = db.get(Download, download_id)
    if not dl:
        return False
    db.delete(dl)
    db.commit()
    _invalidate_catalog_cache()
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
    """Persist scraped releases. For versions that already exist, merge any
    NEW (os, arch) download entries into the existing release so that a
    later-added platform binary (e.g. macos-arm64 source build in
    webdev-console-binaries) shows up on the next auto-generate without
    requiring the admin to manually delete + re-insert the whole release.
    ``replace=True`` wipes ALL releases first (for a clean regen).

    Returns the number of NEW releases inserted (excluding downloads added
    to pre-existing releases — those don't bump the counter but still
    invalidate the catalog cache so clients see the fresh platform set).
    """
    app = get_app(db, app_id)
    if not app:
        return 0

    if replace:
        db.execute(delete(Release).where(Release.app_id == app.id))
        db.commit()

    existing_by_version = {r.version: r for r in app.releases}
    inserted = 0
    downloads_added = 0
    for gen in releases:
        rel = existing_by_version.get(gen.version)
        if rel is None:
            rel = Release(
                app_id=app.id,
                version=gen.version,
                major_minor=gen.major_minor or _major_minor(gen.version),
                channel=gen.channel,
                released_at=gen.released_at,
            )
            db.add(rel)
            db.flush()  # need rel.id for downloads
            # Dedupe within this single scraper's downloads too — two
            # generator passes (upstream scrape + binaries-repo fallback)
            # can both return the same (os, arch, archive_type) triple
            # and would otherwise trip the UNIQUE constraint.
            seen_triples: set[tuple[str, str, str]] = set()
            for gd in gen.downloads:
                triple = (gd.os, gd.arch, gd.archive_type)
                if triple in seen_triples:
                    continue
                seen_triples.add(triple)
                db.add(
                    Download(
                        release_id=rel.id,
                        url=gd.url,
                        os=gd.os,
                        arch=gd.arch,
                        archive_type=gd.archive_type,
                        source=gd.source,
                        headers=gd.headers,
                    )
                )
            existing_by_version[gen.version] = rel  # subsequent scraper passes hit merge branch
            inserted += 1
            continue

        # Merge: add downloads whose (os, arch, archive_type) triple isn't
        # already on the existing release. Matches the downloads table's
        # UNIQUE constraint so we never try to INSERT a duplicate. URL
        # changes are NOT synced — if the admin has hand-edited a URL we
        # don't want a scrape to silently overwrite it. Only additive.
        existing_triples = {(d.os, d.arch, d.archive_type) for d in rel.downloads}
        for gd in gen.downloads:
            triple = (gd.os, gd.arch, gd.archive_type)
            if triple in existing_triples:
                continue
            existing_triples.add(triple)  # block duplicate within this batch
            db.add(
                Download(
                    release_id=rel.id,
                    url=gd.url,
                    os=gd.os,
                    arch=gd.arch,
                    archive_type=gd.archive_type,
                    source=gd.source,
                    headers=gd.headers,
                )
            )
            downloads_added += 1

    db.commit()
    if inserted or downloads_added or replace:
        _invalidate_catalog_cache()
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
                    major_minor=r.get("major_minor")
                    or _major_minor(r.get("version", "0.0.0")),
                    channel=r.get("channel", "stable"),
                    released_at=r.get("released_at"),
                )
                db.add(rel)
                db.flush()
                for d in r.get("downloads", []):
                    db.add(
                        Download(
                            release_id=rel.id,
                            url=d.get("url", ""),
                            os=d.get("os", "windows"),
                            arch=d.get("arch", "x64"),
                            archive_type=d.get("archive_type", "zip"),
                            source=d.get("source", "seed"),
                            headers=d.get("headers"),
                        )
                    )
            count += 1
        except Exception as exc:  # noqa: BLE001
            log.error("Seed parse failed for %s: %s", path, exc)
    db.commit()
    log.info("Seeded %d apps from %s", count, data_dir)
    return count
