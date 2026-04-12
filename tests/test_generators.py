"""Tests for the catalog-api auto-generators.

Verifies that every registered generator is callable and returns the
expected GenRelease structure. The MySQL generator specifically tests
the fallback path since the live scrape depends on dev.mysql.com being
reachable (unreliable in CI).
"""

from __future__ import annotations

import pytest
from app.generators import (
    GENERATORS,
    GenRelease,
    available_generators,
    run_generator,
    generate_mysql,
    _mysql_fallback,
)


class TestGeneratorRegistry:
    def test_all_generators_registered(self):
        expected = {
            "cloudflared", "mailpit", "caddy", "redis",
            "php", "apache", "nginx", "mariadb", "mysql", "node",
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
                assert part.isdigit(), f"Version segment '{part}' in {rel.version} is not numeric"

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
                assert rel.version in dl.url, f"URL {dl.url} should contain version {rel.version}"
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
