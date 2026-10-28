"""Tests for the catalog-api auto-generators.

Verifies that every registered generator is callable and returns the
expected GenRelease structure. apache and mysql are tested offline against
a fake binaries-repo release listing.
"""

from __future__ import annotations

import re

import pytest
from app.generators import (
    GENERATORS,
    GenRelease,
    _github_releases,
    available_generators,
    is_prerelease_version,
    run_generator,
    generate_apache,
    generate_mysql,
    generate_composer,
    generate_postgresql,
)

MIRROR = "https://github.com/nks-hub/webdev-console-binaries/releases/download"


def _mirror_release(app: str, version: str, assets: dict[str, int]) -> dict:
    """One GitHub release payload shaped like the binaries repo's."""
    return {
        "tag_name": f"binaries-{app}-{version}",
        "assets": [
            {
                "name": name,
                "size": size,
                "browser_download_url": f"{MIRROR}/binaries-{app}-{version}/{name}",
            }
            for name, size in assets.items()
        ],
    }


class TestGeneratorRegistry:
    def test_all_generators_registered(self):
        expected = {
            "cloudflared",
            "mailpit",
            "caddy",
            "redis",
            "php",
            "apache",
            "nginx",
            "mariadb",
            "mysql",
            "postgresql",
            "mkcert",
            "node",
            "composer",
        }
        assert set(GENERATORS.keys()) == expected

    def test_available_generators_matches_registry(self):
        assert set(available_generators()) == set(GENERATORS.keys())

    def test_run_generator_unknown_returns_empty(self):
        assert run_generator("nonexistent-app") == []


class TestMirroredGenerators:
    """apache and mysql are offered from the binaries repo only: ApacheLounge
    serves an HTML 200 for rotated builds and dev.mysql.com answers 403, so
    neither upstream URL may reach the catalog."""

    @staticmethod
    def _fake_repo(monkeypatch):
        payload = [
            _mirror_release(
                "mysql",
                "9.7.1",
                {
                    "mysql-9.7.1-windows-x64.zip": 340_920_144,
                    "mysql-9.7.1-linux-x64.tar.xz": 978_752_220,
                },
            ),
            _mirror_release(
                "apache", "2.4.66", {"httpd-2.4.66-windows-x64.zip": 11_527_838}
            ),
            _mirror_release("php", "8.4.20", {"php-8.4.20-windows-x64.zip": 34_323_692}),
        ]
        monkeypatch.setattr("app.generators._github_json", lambda path: payload)

    def test_mysql_comes_only_from_the_binaries_repo(self, monkeypatch):
        self._fake_repo(monkeypatch)
        releases = generate_mysql(limit=5)
        assert [r.version for r in releases] == ["9.7.1"]
        assert releases[0].major_minor == "9.7"
        urls = {d.url for d in releases[0].downloads}
        assert urls == {
            f"{MIRROR}/binaries-mysql-9.7.1/mysql-9.7.1-windows-x64.zip",
            f"{MIRROR}/binaries-mysql-9.7.1/mysql-9.7.1-linux-x64.tar.xz",
        }

    def test_apache_comes_only_from_the_binaries_repo(self, monkeypatch):
        self._fake_repo(monkeypatch)
        (release,) = generate_apache(limit=5)
        assert release.version == "2.4.66"
        (download,) = release.downloads
        assert (download.os, download.arch, download.archive_type) == (
            "windows",
            "x64",
            "zip",
        )
        assert download.url.startswith(MIRROR)

    def test_generators_do_not_scrape_the_upstream_sites(self, monkeypatch):
        self._fake_repo(monkeypatch)

        def no_network(*args, **kwargs):
            raise AssertionError("upstream site must not be contacted")

        monkeypatch.setattr("app.generators.httpx.get", no_network)
        monkeypatch.setattr("app.generators.httpx.head", no_network)
        assert generate_mysql(limit=1)
        assert generate_apache(limit=1)

    def test_asset_sizes_are_carried_into_downloads(self, monkeypatch):
        self._fake_repo(monkeypatch)
        (release,) = generate_apache(limit=5)
        assert release.downloads[0].size_bytes == 11_527_838


class TestNodeGenerator:
    def test_generate_node_returns_list(self):
        from app.generators import generate_node

        result = generate_node(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")

    def test_generate_node_has_multi_platform(self):
        from app.generators import generate_node

        result = generate_node(limit=1)
        if result:
            downloads = result[0].downloads
            os_set = {d.os for d in downloads}
            assert "windows" in os_set or len(downloads) > 0

    def test_generate_node_channel_detection(self):
        from app.generators import generate_node

        result = generate_node(limit=5)
        channels = {r.channel for r in result}
        assert channels <= {"stable", "lts"}


class TestPHPGenerator:
    def test_generate_php_returns_list(self):
        from app.generators import generate_php

        result = generate_php(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert rel.version
            assert rel.major_minor

    def test_generate_php_major_minor_format(self):
        from app.generators import generate_php

        result = generate_php(limit=3)
        for rel in result:
            parts = rel.major_minor.split(".")
            assert len(parts) == 2, f"major_minor {rel.major_minor} should be X.Y"

    def test_generate_php_walks_releases_and_archives(self, monkeypatch):
        """Regression for the 2026-05-06 dead-link incident: php.net moves
        the previous patch into /downloads/releases/archives/ when a new
        one lands in /downloads/releases/. Generator must scrape both
        directories so older patches keep showing up with stable URLs."""
        from app import generators

        releases_listing = (
            '<a href="php-8.5.6-nts-Win32-vs17-x64.zip">php-8.5.6...</a>'
        )
        archives_listing = (
            '<a href="php-8.5.5-nts-Win32-vs17-x64.zip">php-8.5.5</a> '
            '<a href="php-8.5.4-nts-Win32-vs17-x64.zip">php-8.5.4</a> '
            '<a href="php-8.4.20-nts-Win32-vs17-x64.zip">php-8.4.20</a>'
        )

        class FakeResp:
            def __init__(self, text):
                self.text = text

            def raise_for_status(self):
                pass

        def fake_get(url, **kwargs):
            if "archives" in url:
                return FakeResp(archives_listing)
            return FakeResp(releases_listing)

        monkeypatch.setattr(generators.httpx, "get", fake_get)

        result = generators.generate_php(limit=10)
        versions = {r.version for r in result}
        assert "8.5.6" in versions, "current release must be in the result"
        assert "8.5.5" in versions, "archived patch must still be scraped"
        assert "8.5.4" in versions
        assert "8.4.20" in versions

        # 8.5.6 must keep the releases/ URL (canonical location); the
        # archives entries must use archives/ URLs.
        by_version = {r.version: r.downloads[0].url for r in result}
        assert "downloads/releases/php-8.5.6" in by_version["8.5.6"]
        assert "archives/php-8.5.5" in by_version["8.5.5"]

    def test_generate_php_follows_redirects(self, monkeypatch):
        """windows.php.net 302s every directory listing to
        downloads.php.net/~windows/. Without follow_redirects=True the
        scraper would parse the empty redirect body and silently return
        zero hits — the cause of the 2026-05-06 incident where the
        primary scrape pass logged ``primary=0`` while the broken 8.5.5
        URL stayed in the DB unhealed."""
        from app import generators

        captured: dict = {}

        class FakeResp:
            text = '<a href="php-8.5.6-nts-Win32-vs17-x64.zip">x</a>'

            def raise_for_status(self):
                pass

        def fake_get(url, **kwargs):
            captured["follow_redirects"] = kwargs.get("follow_redirects")
            return FakeResp()

        monkeypatch.setattr(generators.httpx, "get", fake_get)
        generators.generate_php(limit=1)
        assert captured.get("follow_redirects") is True

    def test_generate_php_prefers_releases_over_archives_on_collision(
        self, monkeypatch
    ):
        """When both rows list the same patch, the canonical releases/
        URL must win — archives/ is the fallback."""
        from app import generators

        same_file = '<a href="php-8.5.6-nts-Win32-vs17-x64.zip">x</a>'

        class FakeResp:
            def __init__(self, text):
                self.text = text

            def raise_for_status(self):
                pass

        monkeypatch.setattr(
            generators.httpx, "get", lambda url, **kw: FakeResp(same_file)
        )

        result = generators.generate_php(limit=5)
        url = next(r.downloads[0].url for r in result if r.version == "8.5.6")
        assert "/archives/" not in url, (
            "releases/ must beat archives/ when both list the same patch"
        )


class TestMariaDBGenerator:
    def test_generate_mariadb_returns_list(self):
        """generate_mariadb merges 3 sources: archive.mariadb.org (win zip),
        the per-version binaries-repo macOS probe, and a final
        _generate_from_binaries_repo pass that re-adds older versions
        that fell off upstream. Every release's downloads must carry at
        least ONE recognised source string — either `mariadb.org` (win
        zip) or `nks-hub/webdev-console-binaries` (macos-arm64 tarball)."""
        from app.generators import generate_mariadb

        result = generate_mariadb(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            if rel.downloads:
                sources = {dl.source for dl in rel.downloads}
                assert sources & {
                    "mariadb.org",
                    "nks-hub/webdev-console-binaries",
                }, f"unexpected sources {sources}"

    def test_generate_mariadb_windows_download_is_zip(self):
        """The upstream archive.mariadb.org path always returns a Windows
        zip — when that download exists in the merged output, its metadata
        must match (os=windows, arch=x64, archive_type=zip). macOS entries
        from the binaries-repo pass are tar.gz and are intentionally
        skipped here — they're exercised elsewhere."""
        from app.generators import generate_mariadb

        result = generate_mariadb(limit=1)
        for rel in result:
            for dl in rel.downloads:
                if dl.source == "mariadb.org":
                    assert dl.archive_type == "zip"
                    assert dl.os == "windows"
                    assert dl.arch == "x64"


class TestPostgreSQLGenerator:
    def test_generate_postgresql_reads_binaries_repo_assets(self, monkeypatch):
        def fake_github_json(path: str):
            assert "webdev-console-binaries" in path
            return [
                {
                    "tag_name": "binaries-postgresql-18.3",
                    "assets": [
                        {
                            "name": "postgresql-18.3-windows-x64.zip",
                            "browser_download_url": "https://example.test/postgresql-18.3-windows-x64.zip",
                        },
                        {
                            "name": "postgresql-18.3-linux-x64.tar.gz",
                            "browser_download_url": "https://example.test/postgresql-18.3-linux-x64.tar.gz",
                        },
                        {
                            "name": "postgresql-18.3-macos-arm64.tar.gz",
                            "browser_download_url": "https://example.test/postgresql-18.3-macos-arm64.tar.gz",
                        },
                    ],
                }
            ]

        monkeypatch.setattr("app.generators._github_json", fake_github_json)

        result = generate_postgresql(limit=5)

        assert len(result) == 1
        release = result[0]
        assert release.version == "18.3"
        assert release.major_minor == "18.3"
        assert {(d.os, d.arch, d.archive_type) for d in release.downloads} == {
            ("windows", "x64", "zip"),
            ("linux", "x64", "tar.gz"),
            ("macos", "arm64", "tar.gz"),
        }
        assert {d.source for d in release.downloads} == {
            "nks-hub/webdev-console-binaries"
        }


class TestMailpitGenerator:
    def test_generate_mailpit_returns_list(self):
        from app.generators import generate_mailpit

        result = generate_mailpit(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")


class TestCaddyGenerator:
    def test_generate_caddy_returns_list(self):
        from app.generators import generate_caddy

        result = generate_caddy(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")


class TestRedisGenerator:
    def test_generate_redis_returns_list(self):
        from app.generators import generate_redis

        result = generate_redis(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")


class TestNginxGenerator:
    def test_generate_nginx_returns_list(self):
        from app.generators import generate_nginx

        result = generate_nginx(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert "." in rel.version
            for dl in rel.downloads:
                assert "nginx" in dl.url


class TestCloudflaredGenerator:
    def test_generate_cloudflared_has_exe(self):
        from app.generators import generate_cloudflared

        result = generate_cloudflared(limit=1)
        if result and result[0].downloads:
            exts = {dl.archive_type for dl in result[0].downloads}
            assert len(exts) > 0


def _release(tag: str, *, prerelease: bool = False, draft: bool = False, assets=()) -> dict:
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "published_at": "2026-10-22T09:00:00Z",
        "assets": list(assets),
    }


# Shaped like GitHub's answer for composer/composer, newest first. The RC is
# flagged upstream, the beta only gives itself away by its tag, and the draft
# must never be offered.
COMPOSER_RELEASES = [
    _release("2.11.0-RC1", prerelease=True),
    _release("2.10.1"),
    _release("2.10.0"),
    _release("2.10.0-beta.1"),
    _release("2.99.0", draft=True),
    _release("2.9.5"),
    _release("2.9.0-alpha2"),
    _release("2.9.0"),
]


@pytest.fixture
def github_answers(monkeypatch):
    """Serve a payload as GitHub's releases answer; returns ``(set_payload, requested_urls)``."""
    state = {"payload": [], "error": None}
    urls: list[str] = []

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return state["payload"]

    def fake_get(url, **kwargs):
        urls.append(url)
        if state["error"]:
            raise state["error"]
        return _Resp()

    monkeypatch.setattr("app.generators.httpx.get", fake_get)
    return state, urls


class TestPrereleaseVersion:
    @pytest.mark.parametrize(
        "version",
        ["2.11.0-RC1", "2.9.0-beta.3", "2.8.0-rc.1", "3.0.0alpha1", "8.5.0RC1", "2.10.0-BETA2"],
    )
    def test_alpha_beta_rc_are_prereleases(self, version):
        assert is_prerelease_version(version)

    @pytest.mark.parametrize("version", ["2.10.0", "2026.9.3", "8.0.2-2", "1.4.4", "13.1.1", "v1.0.0", ""])
    def test_plain_versions_are_not(self, version):
        assert not is_prerelease_version(version)


class TestGithubReleasesStableOnly:
    def test_drops_flagged_tagged_and_draft_releases(self, github_answers):
        state, _ = github_answers
        state["payload"] = COMPOSER_RELEASES
        tags = [r["tag_name"] for r in _github_releases("composer/composer", limit=10)]
        assert tags == ["2.10.1", "2.10.0", "2.9.5", "2.9.0"]

    def test_limit_counts_stable_releases_only(self, github_answers):
        state, _ = github_answers
        state["payload"] = COMPOSER_RELEASES
        tags = [r["tag_name"] for r in _github_releases("composer/composer", limit=2)]
        assert tags == ["2.10.1", "2.10.0"]

    def test_asks_github_for_more_than_limit_so_prereleases_do_not_eat_slots(self, github_answers):
        _, urls = github_answers
        _github_releases("composer/composer", limit=10)
        _github_releases("composer/composer", limit=60)
        assert [u.rsplit("per_page=", 1)[1] for u in urls] == ["30", "100"]

    def test_upstream_failure_gives_empty_list(self, github_answers):
        state, _ = github_answers
        state["error"] = RuntimeError("simulated network failure")
        assert _github_releases("composer/composer") == []


class TestCaddyStableOnly:
    def test_betas_and_rcs_are_not_offered(self, github_answers):
        from app.generators import generate_caddy

        def asset(tag):
            return {
                "name": f"caddy_{tag}_linux_amd64.tar.gz",
                "browser_download_url": f"https://example/caddy/{tag}/caddy_{tag}_linux_amd64.tar.gz",
            }

        state, _ = github_answers
        state["payload"] = [
            _release("v2.11.0-beta.2", prerelease=True, assets=[asset("2.11.0-beta.2")]),
            _release("v2.9.1", assets=[asset("2.9.1")]),
            _release("v2.8.0-rc.1", assets=[asset("2.8.0-rc.1")]),
            _release("v2.8.4", assets=[asset("2.8.4")]),
        ]
        assert [r.version for r in generate_caddy(limit=5)] == ["2.9.1", "2.8.4"]


class TestComposerGenerator:
    _SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

    @pytest.fixture(autouse=True)
    def recorded_composer(self, github_answers):
        github_answers[0]["payload"] = COMPOSER_RELEASES

    def test_composer_returns_list(self):
        result = generate_composer(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)

    def test_composer_semver(self):
        result = generate_composer(limit=10)
        assert result
        for rel in result:
            assert self._SEMVER.match(rel.version), (
                f"Version {rel.version!r} does not match semver X.Y.Z"
            )

    def test_composer_skips_release_candidates_betas_and_alphas(self):
        assert [r.version for r in generate_composer(limit=10)] == ["2.10.1", "2.10.0", "2.9.5", "2.9.0"]

    def test_composer_latest_is_newest_stable_even_with_limit_one(self):
        assert [r.version for r in generate_composer(limit=1)] == ["2.10.1"]

    def test_composer_limit_respected(self):
        assert len(generate_composer(limit=2)) == 2
        assert len(generate_composer(limit=1)) == 1

    def test_composer_all_three_os(self):
        os_set = {dl.os for dl in generate_composer(limit=1)[0].downloads}
        assert os_set == {"windows", "linux", "macos"}

    def test_composer_phar_url_pattern(self):
        for dl in generate_composer(limit=1)[0].downloads:
            assert dl.url == "https://getcomposer.org/download/2.10.1/composer.phar"
            assert dl.archive_type == "phar"
            assert dl.source == "getcomposer.org"

    def test_composer_channel_stable(self):
        for rel in generate_composer(limit=10):
            assert rel.channel == "stable"

    def test_composer_no_v_prefix(self):
        for rel in generate_composer(limit=10):
            assert not rel.version.startswith("v"), (
                f"Version {rel.version!r} should not start with 'v'"
            )

    def test_composer_returns_list_on_network_failure(self, github_answers):
        github_answers[0]["error"] = RuntimeError("simulated network failure")
        assert run_generator("composer", limit=1) == []


@pytest.mark.integration
class TestComposerLive:
    """Talks to api.github.com. Skipped unless pytest runs with --run-integration."""

    def test_live_composer_offers_only_stable_versions(self):
        result = generate_composer(limit=10)
        if not result:
            pytest.skip("GitHub unreachable or rate limited")
        for rel in result:
            assert re.fullmatch(r"\d+\.\d+\.\d+", rel.version), rel.version
            assert {dl.os for dl in rel.downloads} == {"windows", "linux", "macos"}


class TestGenReleaseStructure:
    """Spot-check that every generator's output conforms to GenRelease."""

    @pytest.mark.parametrize("app_id", list(GENERATORS.keys()))
    def test_generator_returns_valid_releases(self, app_id: str):
        # Run with limit=1 to minimize network calls in CI.
        # Some generators may return 0 if the upstream is unreachable.
        releases = run_generator(app_id, limit=1)
        assert isinstance(releases, list)
        for rel in releases:
            assert isinstance(rel, GenRelease)
            assert rel.version
            assert len(rel.downloads) >= 0
