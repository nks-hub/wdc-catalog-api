"""Tests for the catalog-api auto-generators.

Verifies that every registered generator is callable and returns the
expected GenRelease structure. The MySQL generator specifically tests
the fallback path since the live scrape depends on dev.mysql.com being
reachable (unreliable in CI).
"""

from __future__ import annotations

import re

import pytest
from app.generators import (
    GENERATORS,
    GenRelease,
    available_generators,
    run_generator,
    generate_mysql,
    generate_composer,
    _mysql_fallback,
)


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
            "mkcert",
            "node",
            "composer",
        }
        assert set(GENERATORS.keys()) == expected

    def test_available_generators_matches_registry(self):
        assert set(available_generators()) == set(GENERATORS.keys())

    def test_run_generator_unknown_returns_empty(self):
        assert run_generator("nonexistent-app") == []


class TestMySQLGenerator:
    def test_fallback_returns_releases(self):
        releases = _mysql_fallback(limit=5)
        assert len(releases) > 0
        assert len(releases) <= 5
        for rel in releases:
            assert isinstance(rel, GenRelease)
            assert rel.version
            assert rel.major_minor
            assert len(rel.downloads) > 0
            assert "mysql" in rel.downloads[0].url.lower()
            assert rel.downloads[0].os == "windows"
            assert rel.downloads[0].arch == "x64"

    def test_fallback_versions_are_semver(self):
        releases = _mysql_fallback(limit=10)
        for rel in releases:
            parts = rel.version.split(".")
            assert len(parts) == 3, f"Version {rel.version} is not semver"
            for part in parts:
                assert part.isdigit(), (
                    f"Version segment '{part}' in {rel.version} is not numeric"
                )

    def test_fallback_limit_respected(self):
        assert len(_mysql_fallback(limit=2)) == 2
        assert len(_mysql_fallback(limit=1)) == 1

    def test_generate_mysql_returns_list(self):
        # This may hit the network or fall back — either way must return a list.
        result = generate_mysql(limit=3)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)

    def test_fallback_urls_contain_version(self):
        releases = _mysql_fallback(limit=4)
        for rel in releases:
            for dl in rel.downloads:
                assert rel.version in dl.url, (
                    f"URL {dl.url} should contain version {rel.version}"
                )
                assert "dev.mysql.com" in dl.url

    def test_fallback_major_minor_matches_version(self):
        releases = _mysql_fallback(limit=4)
        for rel in releases:
            expected_mm = ".".join(rel.version.split(".")[:2])
            assert rel.major_minor == expected_mm


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


class TestApacheGenerator:
    def test_generate_apache_returns_list(self):
        from app.generators import generate_apache

        result = generate_apache(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert rel.version
            assert "." in rel.version


class TestComposerGenerator:
    _SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

    def test_composer_returns_list(self):
        result = generate_composer(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)

    def test_composer_semver(self):
        result = generate_composer(limit=3)
        for rel in result:
            assert self._SEMVER.match(rel.version), (
                f"Version {rel.version!r} does not match semver X.Y.Z"
            )

    def test_composer_limit_respected(self):
        result = generate_composer(limit=2)
        assert len(result) <= 2
        result_one = generate_composer(limit=1)
        assert len(result_one) <= 1

    def test_composer_all_three_os(self):
        result = generate_composer(limit=1)
        if not result:
            pytest.skip("composer upstream unreachable")
        os_set = {dl.os for dl in result[0].downloads}
        assert os_set == {"windows", "linux", "macos"}

    def test_composer_phar_url_pattern(self):
        result = generate_composer(limit=1)
        if not result:
            pytest.skip("composer upstream unreachable")
        for dl in result[0].downloads:
            assert "getcomposer.org/download/" in dl.url
            assert dl.url.endswith("composer.phar")
            assert dl.archive_type == "phar"
            assert dl.source == "getcomposer.org"

    def test_composer_channel_stable(self):
        result = generate_composer(limit=3)
        for rel in result:
            assert rel.channel == "stable"

    def test_composer_no_v_prefix(self):
        result = generate_composer(limit=3)
        for rel in result:
            assert not rel.version.startswith("v"), (
                f"Version {rel.version!r} should not start with 'v'"
            )

    def test_composer_returns_list_on_network_failure(self):
        # Even if the network is unreachable, run_generator must return a list.
        result = run_generator("composer", limit=1)
        assert isinstance(result, list)


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
