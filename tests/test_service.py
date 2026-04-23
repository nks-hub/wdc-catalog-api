"""Tests for catalog service CRUD operations.

Re-uses the state dir from test_devices.py (set at import-time in conftest
or the first test module). The SQLAlchemy engine is a module-level singleton
so setting NKS_WDC_CATALOG_STATE_DIR again would be ignored anyway.
"""

from __future__ import annotations

from app.db import create_all, session_factory
from app.generators import GenDownload, GenRelease
from app.service import apply_generated_releases, create_app, get_app, list_apps


class TestServiceCRUD:
    def test_create_app_returns_app(self):
        import uuid

        create_all()
        app_id = f"test-crud-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            app = create_app(db, app_id=app_id, display_name="Test CRUD")
            assert app.id == app_id

    def test_list_apps_includes_created(self):
        import uuid

        create_all()
        app_id = f"list-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name="List Test")
            db.commit()
        with session_factory() as db:
            apps = list_apps(db)
            ids = [a.id for a in apps]
            assert app_id in ids

    def test_create_duplicate_raises(self):
        import uuid
        import pytest

        create_all()
        app_id = f"dup-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name="V1")
            db.commit()
        with session_factory() as db:
            with pytest.raises(Exception):
                create_app(db, app_id=app_id, display_name="V2")
                db.flush()

    def test_create_app_normalizes_id_to_lowercase(self):
        import uuid

        create_all()
        app_id = f"UPPER-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            app = create_app(db, app_id=app_id, display_name="Test")
            assert app.id == app_id.strip().lower()

    def test_get_app_returns_none_for_unknown(self):
        from app.service import get_app

        create_all()
        with session_factory() as db:
            assert get_app(db, "totally-nonexistent-app") is None

    def test_create_app_empty_id_raises(self):
        import pytest

        create_all()
        with session_factory() as db:
            with pytest.raises(ValueError):
                create_app(db, app_id="", display_name="Bad")


class TestApplyGeneratedReleases:
    """Regression tests for the 2026-04-23 merge-downloads fix.

    Before the fix, a generator that returned an existing version with a
    NEW (os, arch) download (e.g. adding macos-arm64 after the catalog was
    seeded with windows-only) was fully skipped, so the new platform never
    landed in the DB. The admin saw "1 new release from 1 scraped" but no
    actual new download rows. Post-fix, existing releases get new
    (os, arch) pairs merged in; existing pairs are NOT overwritten.
    """

    def _make_app(self, prefix: str):
        import uuid
        create_all()
        app_id = f"{prefix}-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name=prefix.title())
            db.commit()
        return app_id

    def test_merges_new_platform_download_into_existing_release(self):
        app_id = self._make_app("merge")
        # Seed: release 1.0.0 with Windows download only
        seed = [GenRelease(version="1.0.0", major_minor="1.0", downloads=[
            GenDownload(url="https://example/x.zip", os="windows", arch="x64"),
        ])]
        with session_factory() as db:
            inserted = apply_generated_releases(db, app_id, seed)
            db.commit()
        assert inserted == 1

        # Regen: same version but now also has macos/arm64 download
        regen = [GenRelease(version="1.0.0", major_minor="1.0", downloads=[
            GenDownload(url="https://example/x.zip", os="windows", arch="x64"),
            GenDownload(url="https://example/x.tar.gz", os="macos", arch="arm64", archive_type="tar.gz"),
        ])]
        with session_factory() as db:
            inserted = apply_generated_releases(db, app_id, regen)
            db.commit()
        # Counter stays 0 (no new Release row), but the macos/arm64
        # Download row must have been added to the existing release.
        assert inserted == 0
        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "1.0.0")
            pairs = {(d.os, d.arch) for d in rel.downloads}
            assert ("windows", "x64") in pairs
            assert ("macos", "arm64") in pairs

    def test_does_not_overwrite_existing_download_url(self):
        app_id = self._make_app("nooverwrite")
        seed = [GenRelease(version="2.0.0", major_minor="2.0", downloads=[
            GenDownload(url="https://admin-edited/custom.zip", os="windows", arch="x64"),
        ])]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        # Regen with a *different* URL for the same (windows, x64) pair —
        # should NOT change the admin-edited URL, only add new pairs.
        regen = [GenRelease(version="2.0.0", major_minor="2.0", downloads=[
            GenDownload(url="https://auto-scrape/new.zip", os="windows", arch="x64"),
            GenDownload(url="https://auto-scrape/linux.tar.gz", os="linux", arch="x64", archive_type="tar.gz"),
        ])]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen)
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "2.0.0")
            win_dl = next(d for d in rel.downloads if (d.os, d.arch) == ("windows", "x64"))
            assert win_dl.url == "https://admin-edited/custom.zip"  # preserved
            linux_dl = next(d for d in rel.downloads if (d.os, d.arch) == ("linux", "x64"))
            assert linux_dl.url == "https://auto-scrape/linux.tar.gz"  # added
