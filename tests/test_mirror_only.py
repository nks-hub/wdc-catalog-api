"""The catalog never offers a download that is not a mirrored, plausible asset.

Regression for the 2026-10 fresh-install failure: the Windows Apache asset
was ApacheLounge's 2,451-byte "not found" page saved as .zip, the catalog's
older Apache entries pointed at ApacheLounge URLs that return the same page,
and every MySQL Windows entry pointed at dev.mysql.com, which answers 403 to
the daemon.
"""

from __future__ import annotations

import uuid

import pytest
from app.db import create_all, session_factory
from app.generators import GenDownload, GenRelease
from app.service import apply_generated_releases, create_app, get_app_document

MIRROR = "https://github.com/nks-hub/webdev-console-binaries/releases/download"
HTML_ERROR_PAGE_BYTES = 2451


def mirrored(version: str, os_: str, ext: str, size: int | None) -> GenDownload:
    arch = "arm64" if os_ == "macos" else "x64"
    return GenDownload(
        url=f"{MIRROR}/binaries-app-{version}/app-{version}-{os_}-{arch}.{ext}",
        os=os_,
        arch=arch,
        archive_type=ext,
        source="nks-hub/webdev-console-binaries",
        size_bytes=size,
    )


def upstream(version: str) -> GenDownload:
    return GenDownload(
        url=f"https://dev.mysql.com/get/Downloads/app-{version}-winx64.zip",
        os="windows",
        arch="x64",
        archive_type="zip",
        source="dev.mysql.com",
    )


def release(version: str, *downloads: GenDownload) -> GenRelease:
    return GenRelease(version=version, major_minor=version.rsplit(".", 1)[0], downloads=list(downloads))


@pytest.fixture
def mirror_only_app(monkeypatch) -> str:
    """A fresh app id registered as mirror-only (the real ids are seeded by other tests)."""
    create_all()
    app_id = f"mirror-{uuid.uuid4().hex[:6]}"
    with session_factory() as db:
        create_app(db, app_id=app_id)
        db.commit()
    monkeypatch.setattr("app.service.MIRROR_ONLY_APPS", frozenset({app_id}))
    return app_id


def seed(app_id: str, *releases: GenRelease) -> None:
    with session_factory() as db:
        apply_generated_releases(db, app_id, list(releases))
        db.commit()


def offered(app_id: str) -> dict[str, set[tuple[str, str]]]:
    with session_factory() as db:
        doc = get_app_document(db, app_id)
    return {r.version: {(d.os, d.archive_type) for d in r.downloads} for r in doc.releases}


def test_upstream_urls_are_not_offered_and_empty_releases_disappear(mirror_only_app):
    seed(
        mirror_only_app,
        release("9.7.1", upstream("9.7.1")),
        release("9.6.0", mirrored("9.6.0", "windows", "zip", 304_538_543), mirrored("9.6.0", "linux", "tar.xz", 994_530_824)),
        release("9.5.0", upstream("9.5.0"), mirrored("9.5.0", "linux", "tar.xz", 900_000_000)),
    )
    assert offered(mirror_only_app) == {
        "9.6.0": {("windows", "zip"), ("linux", "tar.xz")},
        "9.5.0": {("linux", "tar.xz")},
    }


def test_html_error_page_saved_as_archive_is_not_offered(mirror_only_app):
    seed(
        mirror_only_app,
        release("2.4.66", mirrored("2.4.66", "windows", "zip", HTML_ERROR_PAGE_BYTES), mirrored("2.4.66", "linux", "tar.xz", 5_487_792)),
        release("2.4.65", mirrored("2.4.65", "windows", "zip", HTML_ERROR_PAGE_BYTES)),
    )
    assert offered(mirror_only_app) == {"2.4.66": {("linux", "tar.xz")}}


def test_asset_is_offered_again_once_the_republished_size_is_recorded(mirror_only_app):
    seed(mirror_only_app, release("2.4.66", mirrored("2.4.66", "windows", "zip", HTML_ERROR_PAGE_BYTES)))
    assert offered(mirror_only_app) == {}

    # Next autogen pass sees the fixed asset under the same URL.
    seed(mirror_only_app, release("2.4.66", mirrored("2.4.66", "windows", "zip", 11_527_838)))
    assert offered(mirror_only_app) == {"2.4.66": {("windows", "zip")}}


def test_cron_pass_replaces_a_reachable_upstream_url_with_the_mirror(mirror_only_app, monkeypatch):
    seed(mirror_only_app, release("9.7.1", upstream("9.7.1")))

    class Alive:
        status_code = 200

    # Both URLs answer, which is the case that used to keep the upstream entry.
    monkeypatch.setattr("app.service.httpx.head", lambda url, **kw: Alive())
    with session_factory() as db:
        apply_generated_releases(
            db,
            mirror_only_app,
            [release("9.7.1", mirrored("9.7.1", "windows", "zip", 340_920_144))],
            heal_dead_urls=True,
        )
        db.commit()

    assert offered(mirror_only_app) == {"9.7.1": {("windows", "zip")}}


def test_other_apps_keep_their_upstream_urls():
    create_all()
    app_id = f"upstream-{uuid.uuid4().hex[:6]}"
    with session_factory() as db:
        create_app(db, app_id=app_id)
        db.commit()
    seed(app_id, release("1.0.0", upstream("1.0.0")))
    assert offered(app_id) == {"1.0.0": {("windows", "zip")}}
