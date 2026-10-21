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
        seed = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(url="https://example/x.zip", os="windows", arch="x64"),
                ],
            )
        ]
        with session_factory() as db:
            inserted = apply_generated_releases(db, app_id, seed)
            db.commit()
        assert inserted == 1

        # Regen: same version but now also has macos/arm64 download
        regen = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(url="https://example/x.zip", os="windows", arch="x64"),
                    GenDownload(
                        url="https://example/x.tar.gz",
                        os="macos",
                        arch="arm64",
                        archive_type="tar.gz",
                    ),
                ],
            )
        ]
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
        seed = [
            GenRelease(
                version="2.0.0",
                major_minor="2.0",
                downloads=[
                    GenDownload(
                        url="https://admin-edited/custom.zip", os="windows", arch="x64"
                    ),
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        # Regen with a *different* URL for the same (windows, x64) pair —
        # should NOT change the admin-edited URL, only add new pairs.
        regen = [
            GenRelease(
                version="2.0.0",
                major_minor="2.0",
                downloads=[
                    GenDownload(
                        url="https://auto-scrape/new.zip", os="windows", arch="x64"
                    ),
                    GenDownload(
                        url="https://auto-scrape/linux.tar.gz",
                        os="linux",
                        arch="x64",
                        archive_type="tar.gz",
                    ),
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen)
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "2.0.0")
            win_dl = next(
                d for d in rel.downloads if (d.os, d.arch) == ("windows", "x64")
            )
            assert win_dl.url == "https://admin-edited/custom.zip"  # preserved
            linux_dl = next(
                d for d in rel.downloads if (d.os, d.arch) == ("linux", "x64")
            )
            assert linux_dl.url == "https://auto-scrape/linux.tar.gz"  # added


class TestUrlHealing:
    """Regression for the 2026-05-06 PHP 8.5.5 dead-link incident:
    php.net archived 8.5.5 when 8.5.6 shipped, the catalog kept its
    /downloads/releases/php-8.5.5-...zip URL, and downstream installs
    started 404'ing. ``heal_dead_urls=True`` swaps a stored URL whose
    HEAD probe fails for a freshly-scraped URL whose HEAD probe passes,
    while leaving working URLs (admin overrides, still-canonical links)
    untouched."""

    def _make_app(self, prefix: str):
        import uuid
        from app.db import create_all, session_factory
        from app.service import create_app

        create_all()
        app_id = f"{prefix}-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name=prefix.title())
            db.commit()
        return app_id

    def test_heal_replaces_dead_url_with_alive_one(self, monkeypatch):
        from app.db import session_factory
        from app.generators import GenDownload, GenRelease
        from app.service import apply_generated_releases, get_app

        app_id = self._make_app("heal-dead")

        # Seed: stored URL points at the (now-archived-upstream) location.
        seed = [
            GenRelease(
                version="8.5.5",
                major_minor="8.5",
                downloads=[
                    GenDownload(
                        url="https://upstream/releases/php-8.5.5.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="php.net",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        # Mock HEAD: stored URL dead, scraped URL alive.
        def fake_head(url, **kw):
            class R:
                pass

            r = R()
            r.status_code = 200 if "/archives/" in url else 404
            return r

        monkeypatch.setattr("app.service.httpx.head", fake_head)

        regen = [
            GenRelease(
                version="8.5.5",
                major_minor="8.5",
                downloads=[
                    GenDownload(
                        url="https://upstream/releases/archives/php-8.5.5.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="php.net",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen, heal_dead_urls=True)
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "8.5.5")
            url = next(
                d.url for d in rel.downloads if (d.os, d.arch) == ("windows", "x64")
            )
            assert url == "https://upstream/releases/archives/php-8.5.5.zip"

    def test_heal_preserves_working_url(self, monkeypatch):
        """Admin override (or any working URL) must not be replaced even
        when a different URL is scraped — the existing one HEAD-200s."""
        from app.db import session_factory
        from app.generators import GenDownload, GenRelease
        from app.service import apply_generated_releases, get_app

        app_id = self._make_app("heal-keep")
        seed = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(
                        url="https://admin/custom.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="admin-override",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        # Both URLs reachable — heal must NOT swap.
        def fake_head(url, **kw):
            class R:
                pass

            r = R()
            r.status_code = 200
            return r

        monkeypatch.setattr("app.service.httpx.head", fake_head)

        regen = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(
                        url="https://upstream/different.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="auto",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen, heal_dead_urls=True)
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "1.0.0")
            url = next(
                d.url for d in rel.downloads if (d.os, d.arch) == ("windows", "x64")
            )
            assert url == "https://admin/custom.zip"

    def test_own_build_replaces_php_net_but_not_admin_override(self, monkeypatch):
        """A patched build in nks-hub/webdev-console-binaries supersedes a
        working php.net URL (php.net ships no fixes for EOL Windows branches),
        while an admin-labelled download stays untouched."""
        from app.db import session_factory
        from app.generators import GenDownload, GenRelease
        from app.service import OWN_BUILD_SOURCE, apply_generated_releases, get_app

        app_id = self._make_app("own-build")
        seed = [
            GenRelease(
                version=v,
                major_minor=v.rsplit(".", 1)[0],
                downloads=[
                    GenDownload(
                        url=f"https://{src}/php-{v}.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source=src,
                    )
                ],
            )
            for v, src in (("7.4.33", "php.net"), ("8.0.30", "admin-override"))
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        def fake_head(url, **kw):
            class R:
                pass

            r = R()
            r.status_code = 200
            return r

        monkeypatch.setattr("app.service.httpx.head", fake_head)

        regen = [
            GenRelease(
                version=v,
                major_minor=v.rsplit(".", 1)[0],
                downloads=[
                    GenDownload(
                        url=f"https://github/own/php-{v}-windows-x64.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source=OWN_BUILD_SOURCE,
                    )
                ],
            )
            for v in ("7.4.33", "8.0.30")
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen, heal_dead_urls=True)
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            urls = {r.version: r.downloads[0].url for r in app.releases}
            assert urls["7.4.33"] == "https://github/own/php-7.4.33-windows-x64.zip"
            assert urls["8.0.30"] == "https://admin-override/php-8.0.30.zip"

    def test_heal_disabled_by_default_keeps_invariant(self, monkeypatch):
        """Without ``heal_dead_urls=True`` the legacy invariant holds:
        no URL is ever overwritten regardless of HEAD status. This guards
        the daemon-side admin endpoint that opts out of healing."""
        from app.db import session_factory
        from app.generators import GenDownload, GenRelease
        from app.service import apply_generated_releases, get_app

        app_id = self._make_app("heal-off")
        seed = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(
                        url="https://dead-but-stored.example/x.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="auto",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, seed)
            db.commit()

        # If healing were silently on, this stub would return dead-everywhere.
        def fake_head(url, **kw):
            raise AssertionError(
                "HEAD probe must not run when heal_dead_urls is False"
            )

        monkeypatch.setattr("app.service.httpx.head", fake_head)

        regen = [
            GenRelease(
                version="1.0.0",
                major_minor="1.0",
                downloads=[
                    GenDownload(
                        url="https://alive.example/x.zip",
                        os="windows",
                        arch="x64",
                        archive_type="zip",
                        source="auto",
                    )
                ],
            )
        ]
        with session_factory() as db:
            apply_generated_releases(db, app_id, regen)  # heal_dead_urls=False
            db.commit()

        with session_factory() as db:
            app = get_app(db, app_id)
            rel = next(r for r in app.releases if r.version == "1.0.0")
            url = next(
                d.url for d in rel.downloads if (d.os, d.arch) == ("windows", "x64")
            )
            assert url == "https://dead-but-stored.example/x.zip"
