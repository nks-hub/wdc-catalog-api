"""Tests for the plugins-catalog endpoint (``/api/v1/plugins/catalog``).

The F94 landing shipped the ``plugins_catalog`` module without
coverage — the full pytest suite passed only because nothing imported
the new router in test paths. This file locks in:

- asset-filename parsing (``_asset_plugin_id``) — handles the
  canonical naming convention plus edge-cases that should not match.
- ``generate_plugins`` grouping behaviour with a stubbed GitHub
  ``_github_releases`` response.
- ``GET /api/v1/plugins/catalog`` and
  ``GET /api/v1/plugins/catalog/{plugin_id}`` — happy path + 404
  branch, using the same stub pattern.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import plugins_catalog
from app.main import app


# --- asset filename parsing ---------------------------------------------


class TestAssetPluginId:
    def test_canonical_filename_maps_to_lowercase_id(self):
        assert (
            plugins_catalog._asset_plugin_id("NKS.WebDevConsole.Plugin.Apache.zip")
            == "nks.wdc.apache"
        )

    def test_camelcase_name_lowercased(self):
        assert (
            plugins_catalog._asset_plugin_id("NKS.WebDevConsole.Plugin.MariaDB.zip")
            == "nks.wdc.mariadb"
        )

    def test_missing_extension_rejected(self):
        assert (
            plugins_catalog._asset_plugin_id("NKS.WebDevConsole.Plugin.Apache") is None
        )

    def test_wrong_prefix_rejected(self):
        assert plugins_catalog._asset_plugin_id("Plugin.Apache.zip") is None

    def test_non_alnum_name_rejected(self):
        # Dots / dashes inside the name would collide with the prefix
        # boundary — the regex requires [A-Za-z0-9]+.
        assert (
            plugins_catalog._asset_plugin_id("NKS.WebDevConsole.Plugin.Foo-Bar.zip")
            is None
        )

    def test_empty_string_rejected(self):
        assert plugins_catalog._asset_plugin_id("") is None


# --- generate_plugins grouping ------------------------------------------

_FAKE_RELEASES = [
    {
        "tag_name": "v0.1.0",
        "published_at": "2026-04-20T15:34:02Z",
        "assets": [
            {
                "name": "NKS.WebDevConsole.Plugin.Apache.zip",
                "browser_download_url": "https://example/apache-0.1.0.zip",
            },
            {
                "name": "NKS.WebDevConsole.Plugin.Nginx.zip",
                "browser_download_url": "https://example/nginx-0.1.0.zip",
            },
            # Non-matching asset (e.g. source tarball) should be skipped.
            {
                "name": "Source code.zip",
                "browser_download_url": "https://example/src.zip",
            },
        ],
    },
    {
        "tag_name": "v0.0.9",
        "published_at": "2026-04-10T09:00:00Z",
        "assets": [
            {
                "name": "NKS.WebDevConsole.Plugin.Apache.zip",
                "browser_download_url": "https://example/apache-0.0.9.zip",
            },
        ],
    },
]


@pytest.fixture()
def stub_releases(monkeypatch):
    monkeypatch.setattr(
        plugins_catalog,
        "_github_releases",
        lambda repo, limit=20: _FAKE_RELEASES,
    )


class TestGeneratePlugins:
    def test_groups_by_plugin_id(self, stub_releases):
        grouped = plugins_catalog.generate_plugins()
        assert set(grouped.keys()) == {"nks.wdc.apache", "nks.wdc.nginx"}

    def test_apache_has_both_versions(self, stub_releases):
        grouped = plugins_catalog.generate_plugins()
        versions = [r.version for r in grouped["nks.wdc.apache"]]
        assert versions == ["0.1.0", "0.0.9"]

    def test_download_os_arch_always_any(self, stub_releases):
        grouped = plugins_catalog.generate_plugins()
        for releases in grouped.values():
            for rel in releases:
                for dl in rel.downloads:
                    assert dl.os == "any"
                    assert dl.arch == "any"
                    assert dl.archive_type == "zip"

    def test_released_at_is_date_prefix(self, stub_releases):
        grouped = plugins_catalog.generate_plugins()
        # GitHub returns full ISO; module should slice to YYYY-MM-DD.
        assert grouped["nks.wdc.apache"][0].released_at == "2026-04-20"


# --- HTTP endpoints -----------------------------------------------------


class TestPluginsCatalogEndpoints:
    def test_full_catalog_returns_plugins(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog")
        assert r.status_code == 200
        body = r.json()
        assert body["schema"] == "wdc-plugins/v1"
        assert body["plugin_count"] == 2
        ids = {p["id"] for p in body["plugins"]}
        assert ids == {"nks.wdc.apache", "nks.wdc.nginx"}

    def test_single_plugin_happy_path(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog/nks.wdc.apache")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == "nks.wdc.apache"
        assert len(body["releases"]) == 2

    def test_single_plugin_case_insensitive(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog/NKS.WDC.Apache")
        assert r.status_code == 200
        assert r.json()["id"] == "nks.wdc.apache"

    def test_single_plugin_unknown_id_404(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog/nks.wdc.doesnotexist")
        assert r.status_code == 404

    def test_cache_control_header_set(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog")
        assert "public" in r.headers.get("cache-control", "")


# --- in-process TTL cache -----------------------------------------------


class TestGithubReleasesCache:
    def test_within_ttl_hits_upstream_once(self, monkeypatch):
        # Clear any leftover entry from other tests, then count httpx.get
        # invocations. The second call with identical args should be
        # served from the cache.
        plugins_catalog._cache.clear()
        calls = {"n": 0}

        class _FakeResp:
            def raise_for_status(self):  # noqa: D401
                pass

            def json(self):
                return [{"tag_name": "v1.0.0", "assets": []}]

        def _fake_get(url, headers=None, timeout=None):  # noqa: ARG001
            calls["n"] += 1
            return _FakeResp()

        monkeypatch.setattr(plugins_catalog.httpx, "get", _fake_get)
        monkeypatch.setattr(plugins_catalog, "CACHE_TTL_SECONDS", 60.0)

        plugins_catalog._github_releases("fake/repo", limit=5)
        plugins_catalog._github_releases("fake/repo", limit=5)
        plugins_catalog._github_releases("fake/repo", limit=5)
        assert calls["n"] == 1

    def test_ttl_zero_disables_cache(self, monkeypatch):
        plugins_catalog._cache.clear()
        calls = {"n": 0}

        class _FakeResp:
            def raise_for_status(self):  # noqa: D401
                pass

            def json(self):
                return []

        def _fake_get(url, headers=None, timeout=None):  # noqa: ARG001
            calls["n"] += 1
            return _FakeResp()

        monkeypatch.setattr(plugins_catalog.httpx, "get", _fake_get)
        monkeypatch.setattr(plugins_catalog, "CACHE_TTL_SECONDS", 0.0)

        plugins_catalog._github_releases("fake/repo")
        plugins_catalog._github_releases("fake/repo")
        assert calls["n"] == 2

    def test_upstream_failure_not_cached(self, monkeypatch):
        # A transient 500/network error should NOT occupy the cache for
        # a full TTL — otherwise one flaky fetch silently blinds the
        # endpoint for a minute even though GitHub is back.
        plugins_catalog._cache.clear()

        def _fake_get(url, headers=None, timeout=None):  # noqa: ARG001
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(plugins_catalog.httpx, "get", _fake_get)
        monkeypatch.setattr(plugins_catalog, "CACHE_TTL_SECONDS", 60.0)

        result = plugins_catalog._github_releases("fake/repo")
        assert result == []
        assert plugins_catalog._cache == {}
