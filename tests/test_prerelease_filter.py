"""The public catalog never offers an alpha, beta or release candidate as stable.

Regression: the GitHub-backed generators put every tag on the stable channel,
so pre-releases such as caddy 2.11.0-beta.2 ended up in the catalog the
desktop app installs from. Rows stored by that older behaviour must not be
served either.
"""

from __future__ import annotations

import uuid

from app.db import create_all, session_factory
from app.generators import GenDownload, GenRelease
from app.service import apply_generated_releases, create_app, get_app_document


def release(version: str, channel: str = "stable") -> GenRelease:
    dl = GenDownload(f"https://example/app-{version}.zip", "windows", "x64", "zip", "test")
    return GenRelease(version=version, major_minor=".".join(version.split(".")[:2]), channel=channel, downloads=[dl])


def offered_versions(app_id: str) -> list[str]:
    with session_factory() as db:
        return [r.version for r in get_app_document(db, app_id).releases]


def seed(*releases: GenRelease) -> str:
    create_all()
    app_id = f"prerelease-{uuid.uuid4().hex[:6]}"
    with session_factory() as db:
        create_app(db, app_id=app_id)
        apply_generated_releases(db, app_id, list(releases))
        db.commit()
    return app_id


def test_stored_prereleases_on_the_stable_channel_are_not_served():
    app_id = seed(
        release("2.9.1"),
        release("2.11.0-beta.2"),
        release("2.8.0-rc.1"),
        release("2.8.4"),
        release("2.12.0-alpha3"),
    )
    assert sorted(offered_versions(app_id)) == ["2.8.4", "2.9.1"]


def test_an_admin_curated_beta_channel_release_is_still_served():
    app_id = seed(release("2.9.1"), release("3.0.0-beta.1", channel="beta"))
    assert sorted(offered_versions(app_id)) == ["2.9.1", "3.0.0-beta.1"]


def test_plain_versions_are_untouched():
    app_id = seed(release("8.5.9"), release("2026.9.3"), release("13.1.1"))
    assert sorted(offered_versions(app_id)) == ["13.1.1", "2026.9.3", "8.5.9"]
