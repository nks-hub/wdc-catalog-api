"""Tests for the plugins-catalog endpoint (``/api/v1/plugins/catalog``).

The F94 landing shipped the ``plugins_catalog`` module without
coverage — the full pytest suite passed only because nothing imported
the new router in test paths. This file locks in:

- asset-filename parsing (``_asset_plugin_id``) — handles the
  canonical naming convention plus edge-cases that should not match.
- ``generate_plugins`` against recorded-shape GitHub release JSON: plugin
  id from the tag prefix, semver ``version``, ``sha256`` per download,
  ``name`` / ``description`` from ``plugin.json``.
- ``_asset_sha256`` / ``_plugin_manifest`` upstream lookups and their caches.
- ``GET /api/v1/plugins/catalog`` and
  ``GET /api/v1/plugins/catalog/{plugin_id}`` — happy path + 404
  branch, using the same stub pattern.
"""

from __future__ import annotations

import hashlib
import json

import httpx
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


# --- generate_plugins ---------------------------------------------------

_SHA = {n: hashlib.sha256(n.encode()).hexdigest() for n in "abcdefg"}
_DL = "https://example/download"


def _asset(name: str, tag: str, sha: str | None = None, **extra) -> dict:
    asset = {"name": name, "browser_download_url": f"{_DL}/{tag}/{name}", **extra}
    if sha:
        asset["digest"] = f"sha256:{sha}"
    return asset


# Newest-first like the GitHub API, except that apache 1.0.9 is deliberately
# listed before 1.0.17 to prove the catalog orders by version, not by position.
_FAKE_RELEASES = [
    {
        "tag_name": "nks.wdc.apache-v1.0.9",
        "published_at": "2026-04-23T18:06:01Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.Apache.zip", "nks.wdc.apache-v1.0.9", _SHA["a"])],
    },
    {
        "tag_name": "nks.wdc.apache-v1.0.17",
        "published_at": "2026-10-28T00:06:35Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.Apache.zip", "nks.wdc.apache-v1.0.17", _SHA["b"])],
    },
    {
        "tag_name": "nks.wdc.nginx-v1.0.2",
        "published_at": "2026-04-23T18:06:24Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.Nginx.zip", "nks.wdc.nginx-v1.0.2", _SHA["c"])],
    },
    {
        # Tag prefix differs from the asset name (NksDeploy -> deploy); the
        # bundled phar is not a plugin zip and must be ignored.
        "tag_name": "nks.wdc.deploy-v0.1.0",
        "published_at": "2026-05-04T00:02:59Z",
        "assets": [
            _asset("NKS.WebDevConsole.Plugin.NksDeploy.zip", "nks.wdc.deploy-v0.1.0", _SHA["d"]),
            _asset("nksdeploy.phar", "nks.wdc.deploy-v0.1.0", _SHA["g"]),
        ],
    },
    {
        "tag_name": "nks.wdc.deploy.localrsync-v0.1.0",
        "published_at": "2026-05-04T00:02:52Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.LocalRsync.zip", "nks.wdc.deploy.localrsync-v0.1.0", _SHA["e"])],
    },
    {
        # Legacy tag without the nks.wdc. prefix: id falls back to the asset name.
        "tag_name": "redis-v1.0.3",
        "published_at": "2026-04-23T16:13:49Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.Redis.zip", "redis-v1.0.3", _SHA["f"])],
    },
    {
        # Legacy bundle release: every zip becomes its own plugin release.
        "tag_name": "v0.1.0",
        "published_at": "2026-04-20T16:35:40Z",
        "assets": [
            _asset("NKS.WebDevConsole.Plugin.Apache.zip", "v0.1.0", _SHA["a"]),
            _asset("NKS.WebDevConsole.Plugin.Nginx.zip", "v0.1.0", _SHA["c"]),
            # Non-matching asset (e.g. source tarball) should be skipped.
            {"name": "Source code.zip", "browser_download_url": "https://example/src.zip"},
        ],
    },
    {
        # Not a plain major.minor.patch tag: not offered.
        "tag_name": "nks.wdc.node-v1.0.0-rc.1",
        "published_at": "2026-04-23T16:13:49Z",
        "assets": [_asset("NKS.WebDevConsole.Plugin.Node.zip", "nks.wdc.node-v1.0.0-rc.1", _SHA["a"])],
    },
]

_FAKE_MANIFESTS = {
    ("nks.wdc.apache-v1.0.17", "NKS.WebDevConsole.Plugin.Apache"): {
        "id": "nks.wdc.apache",
        "displayName": "Apache HTTP Server",
        "description": "Apache 2.4 service module.",
    },
    ("nks.wdc.deploy.localrsync-v0.1.0", "NKS.WebDevConsole.Plugin.LocalRsync"): {
        "id": "nks.wdc.deploy.localrsync",
        "displayName": "Local rsync deploy",
        "description": "IDeployBackend that publishes via rsync.",
    },
}


_FAKE_GENERATED_AT = "2026-10-28T10:00:00Z"


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    """Keep every test off the shared state dir and the module-level releases cache."""
    monkeypatch.setattr(plugins_catalog, "_state_file", lambda: tmp_path / plugins_catalog.STATE_FILENAME)
    monkeypatch.setattr(plugins_catalog, "GITHUB_TOKEN", "")
    plugins_catalog._cache.clear()
    yield
    plugins_catalog._cache.clear()


@pytest.fixture()
def stub_releases(monkeypatch):
    """Stub the GitHub releases and plugin.json lookups; returns the plugin.json calls."""
    manifest_calls: list[tuple[str, str]] = []

    def _fake_manifest(repo, tag, plugin_dir):
        manifest_calls.append((tag, plugin_dir))
        return _FAKE_MANIFESTS.get((tag, plugin_dir), {})

    monkeypatch.setattr(
        plugins_catalog,
        "_github_releases",
        lambda repo, limit=20: plugins_catalog.ReleasesSnapshot(_FAKE_RELEASES, _FAKE_GENERATED_AT, stale=False),
    )
    monkeypatch.setattr(plugins_catalog, "_plugin_manifest", _fake_manifest)
    return manifest_calls


class TestGeneratePlugins:
    def test_id_comes_from_tag_prefix_not_asset_name(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        assert set(grouped.keys()) == {
            "nks.wdc.apache",
            "nks.wdc.nginx",
            "nks.wdc.deploy",
            "nks.wdc.deploy.localrsync",
            "nks.wdc.redis",
        }

    def test_version_is_semver_not_whole_tag(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        assert grouped["nks.wdc.deploy.localrsync"].releases[0].version == "0.1.0"
        for entry in grouped.values():
            for rel in entry.releases:
                assert plugins_catalog._TAG_RE.match(f"v{rel.version}")

    def test_major_minor_is_numeric(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        assert grouped["nks.wdc.apache"].releases[0].major_minor == "1.0"

    def test_releases_sorted_newest_version_first(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        versions = [r.version for r in grouped["nks.wdc.apache"].releases]
        assert versions == ["1.0.17", "1.0.9", "0.1.0"]

    def test_legacy_tags_fall_back_to_asset_name(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        assert [r.version for r in grouped["nks.wdc.redis"].releases] == ["1.0.3"]
        assert [r.version for r in grouped["nks.wdc.nginx"].releases] == ["1.0.2", "0.1.0"]

    def test_tagged_release_takes_only_the_plugin_zip(self, stub_releases):
        deploy = plugins_catalog.generate_plugins().plugins["nks.wdc.deploy"]
        assert len(deploy.releases) == 1
        (dl,) = deploy.releases[0].downloads
        assert dl.url.endswith("NKS.WebDevConsole.Plugin.NksDeploy.zip")

    def test_prerelease_tag_not_offered(self, stub_releases):
        assert "nks.wdc.node" not in plugins_catalog.generate_plugins().plugins

    def test_download_carries_sha256_of_its_own_asset(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        assert grouped["nks.wdc.apache"].releases[0].downloads[0].sha256 == _SHA["b"]
        assert grouped["nks.wdc.apache"].releases[1].downloads[0].sha256 == _SHA["a"]
        assert grouped["nks.wdc.deploy"].releases[0].downloads[0].sha256 == _SHA["d"]

    def test_name_and_description_from_plugin_json(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        apache = grouped["nks.wdc.apache"]
        assert apache.name == "Apache HTTP Server"
        assert apache.description == "Apache 2.4 service module."
        rsync = grouped["nks.wdc.deploy.localrsync"]
        assert rsync.name == "Local rsync deploy"

    def test_plugin_json_read_once_per_plugin_at_newest_tag(self, stub_releases):
        plugins_catalog.generate_plugins()
        assert ("nks.wdc.apache-v1.0.17", "NKS.WebDevConsole.Plugin.Apache") in stub_releases
        assert sum(1 for _, d in stub_releases if d.endswith(".Apache")) == 1
        assert len(stub_releases) == 5

    def test_missing_plugin_json_falls_back_to_directory_name(self, stub_releases):
        nginx = plugins_catalog.generate_plugins().plugins["nks.wdc.nginx"]
        assert nginx.name == "Nginx"
        assert nginx.description is None

    def test_download_os_arch_always_any(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        for entry in grouped.values():
            for rel in entry.releases:
                for dl in rel.downloads:
                    assert dl.os == "any"
                    assert dl.arch == "any"
                    assert dl.archive_type == "zip"

    def test_released_at_is_date_prefix(self, stub_releases):
        grouped = plugins_catalog.generate_plugins().plugins
        # GitHub returns full ISO; module should slice to YYYY-MM-DD.
        assert grouped["nks.wdc.apache"].releases[0].released_at == "2026-10-28"


# --- sha256 lookup ------------------------------------------------------


class _FakeStream:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        pass

    def iter_bytes(self):
        yield self._payload[:3]
        yield self._payload[3:]


class TestAssetSha256:
    def test_digest_field_wins_without_download(self, monkeypatch):
        def _no_network(*a, **kw):
            raise AssertionError("must not download when digest is present")

        monkeypatch.setattr(plugins_catalog.httpx, "stream", _no_network)
        asset = {"digest": "sha256:" + "AB" * 32, "browser_download_url": "https://x/a.zip"}
        assert plugins_catalog._asset_sha256(asset) == "ab" * 32

    def test_download_hash_cached_per_asset_id_and_updated_at(self, monkeypatch):
        plugins_catalog._sha256_cache.clear()
        calls = {"n": 0}
        payload = b"plugin-zip-bytes"

        def _fake_stream(method, url, **kw):  # noqa: ARG001
            calls["n"] += 1
            return _FakeStream(payload)

        monkeypatch.setattr(plugins_catalog.httpx, "stream", _fake_stream)
        asset = {
            "id": 42,
            "updated_at": "2026-10-28T00:00:00Z",
            "browser_download_url": "https://x/a.zip",
            "digest": None,
        }
        expected = hashlib.sha256(payload).hexdigest()

        assert plugins_catalog._asset_sha256(asset) == expected
        assert plugins_catalog._asset_sha256(asset) == expected
        assert calls["n"] == 1

        plugins_catalog._asset_sha256({**asset, "updated_at": "2026-10-29T00:00:00Z"})
        assert calls["n"] == 2

    def test_failed_download_returns_none_and_is_not_cached(self, monkeypatch):
        plugins_catalog._sha256_cache.clear()

        def _boom(*a, **kw):
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(plugins_catalog.httpx, "stream", _boom)
        asset = {"id": 7, "updated_at": "t", "browser_download_url": "https://x/a.zip"}
        assert plugins_catalog._asset_sha256(asset) is None
        assert plugins_catalog._sha256_cache == {}


# --- plugin.json lookup -------------------------------------------------


class TestPluginManifest:
    def test_fetched_from_raw_url_at_tag_and_cached(self, monkeypatch):
        plugins_catalog._manifest_cache.clear()
        urls: list[str] = []

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"displayName": "Apache HTTP Server"}

        def _fake_get(url, **kw):  # noqa: ARG001
            urls.append(url)
            return _Resp()

        monkeypatch.setattr(plugins_catalog.httpx, "get", _fake_get)
        args = ("nks-hub/plugins", "nks.wdc.apache-v1.0.17", "NKS.WebDevConsole.Plugin.Apache")

        assert plugins_catalog._plugin_manifest(*args)["displayName"] == "Apache HTTP Server"
        assert plugins_catalog._plugin_manifest(*args)["displayName"] == "Apache HTTP Server"
        assert urls == [
            "https://raw.githubusercontent.com/nks-hub/plugins/nks.wdc.apache-v1.0.17"
            "/NKS.WebDevConsole.Plugin.Apache/plugin.json"
        ]

    def test_failure_returns_empty_and_is_not_cached(self, monkeypatch):
        plugins_catalog._manifest_cache.clear()

        def _boom(*a, **kw):
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(plugins_catalog.httpx, "get", _boom)
        assert plugins_catalog._plugin_manifest("r/r", "t", "d") == {}
        assert plugins_catalog._manifest_cache == {}


# --- HTTP endpoints -----------------------------------------------------


class TestPluginsCatalogEndpoints:
    def test_full_catalog_returns_plugins(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog")
        assert r.status_code == 200
        body = r.json()
        assert body["schema"] == "wdc-plugins/v1"
        assert body["plugin_count"] == 5
        ids = {p["id"] for p in body["plugins"]}
        assert ids == {
            "nks.wdc.apache",
            "nks.wdc.nginx",
            "nks.wdc.deploy",
            "nks.wdc.deploy.localrsync",
            "nks.wdc.redis",
        }

    def test_full_catalog_exposes_name_description_version_sha256(self, stub_releases):
        with TestClient(app) as c:
            body = c.get("/api/v1/plugins/catalog").json()
        apache = next(p for p in body["plugins"] if p["id"] == "nks.wdc.apache")
        assert apache["name"] == "Apache HTTP Server"
        assert apache["description"] == "Apache 2.4 service module."
        assert apache["releases"][0]["version"] == "1.0.17"
        assert apache["releases"][0]["downloads"][0]["sha256"] == _SHA["b"]

    def test_single_plugin_happy_path(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog/nks.wdc.apache")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == "nks.wdc.apache"
        assert body["name"] == "Apache HTTP Server"
        assert len(body["releases"]) == 3

    def test_single_plugin_dotted_id(self, stub_releases):
        with TestClient(app) as c:
            r = c.get("/api/v1/plugins/catalog/nks.wdc.deploy.localrsync")
        assert r.status_code == 200
        assert r.json()["releases"][0]["version"] == "0.1.0"

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
        assert result is None
        assert plugins_catalog._cache == {}


# --- stale fallback and GitHub token ------------------------------------

_REPO = "fake/repo"
_LIMIT = 100


class _Resp:
    def __init__(self, body=None, status: int = 200):
        self._body = body
        self._status = status

    def raise_for_status(self):
        if self._status >= 400:
            req = httpx.Request("GET", "https://api.github.com/x")
            raise httpx.HTTPStatusError(
                f"{self._status}", request=req, response=httpx.Response(self._status, request=req)
            )

    def json(self):
        return self._body


@pytest.fixture()
def github(monkeypatch):
    """Queue GitHub answers; each call takes the next one.

    A list or dict is a 200 body, an int is an HTTP error status and an
    Exception is raised by ``httpx.get`` itself (network failure).
    """
    monkeypatch.setattr(plugins_catalog, "CACHE_TTL_SECONDS", 0.0)
    queue: list = []
    sent_headers: list[dict] = []

    def _fake_get(url, headers=None, timeout=None, **kw):  # noqa: ARG001
        sent_headers.append(headers)
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _Resp(status=outcome) if isinstance(outcome, int) else _Resp(outcome)

    monkeypatch.setattr(plugins_catalog.httpx, "get", _fake_get)
    return queue, sent_headers


_FAILURES = [
    pytest.param(403, id="rate-limit-403"),
    pytest.param(429, id="too-many-429"),
    pytest.param(502, id="bad-gateway-5xx"),
    pytest.param(httpx.ConnectError("no route"), id="network"),
    pytest.param({"message": "API rate limit exceeded"}, id="non-list-body"),
]


class TestStaleFallback:
    @pytest.mark.parametrize("failure", _FAILURES)
    def test_memory_copy_served_stale_when_github_fails(self, github, failure):
        queue, _ = github
        queue += [_FAKE_RELEASES, failure]

        fresh = plugins_catalog._github_releases(_REPO, _LIMIT)
        stale = plugins_catalog._github_releases(_REPO, _LIMIT)

        assert fresh.stale is False
        assert stale.stale is True
        assert stale.releases == _FAKE_RELEASES
        assert stale.generated_at == fresh.generated_at

    @pytest.mark.parametrize("failure", _FAILURES)
    def test_disk_copy_survives_restart(self, github, failure):
        queue, _ = github
        queue += [_FAKE_RELEASES, failure]
        fresh = plugins_catalog._github_releases(_REPO, _LIMIT)

        plugins_catalog._cache.clear()  # what a process restart does to memory
        stale = plugins_catalog._github_releases(_REPO, _LIMIT)

        assert stale.stale is True
        assert stale.releases == _FAKE_RELEASES
        assert stale.generated_at == fresh.generated_at

    @pytest.mark.parametrize("failure", _FAILURES)
    def test_no_copy_at_all_returns_none(self, github, failure):
        queue, _ = github
        queue.append(failure)
        assert plugins_catalog._github_releases(_REPO, _LIMIT) is None
        assert plugins_catalog._cache == {}
        assert not plugins_catalog._state_file().exists()

    def test_failure_does_not_overwrite_memory_or_disk(self, github):
        queue, _ = github
        queue += [_FAKE_RELEASES, 403, 403]
        plugins_catalog._github_releases(_REPO, _LIMIT)
        entry = plugins_catalog._cache[(_REPO, _LIMIT)]
        on_disk = plugins_catalog._state_file().read_text(encoding="utf-8")

        plugins_catalog._github_releases(_REPO, _LIMIT)
        assert plugins_catalog._cache[(_REPO, _LIMIT)] == entry
        plugins_catalog._cache.clear()
        plugins_catalog._github_releases(_REPO, _LIMIT)

        assert plugins_catalog._cache == {}
        assert plugins_catalog._state_file().read_text(encoding="utf-8") == on_disk

    def test_recovery_after_failure_is_fresh_again(self, github):
        queue, _ = github
        queue += [_FAKE_RELEASES, 403, _FAKE_RELEASES[:1]]
        plugins_catalog._github_releases(_REPO, _LIMIT)
        plugins_catalog._github_releases(_REPO, _LIMIT)

        recovered = plugins_catalog._github_releases(_REPO, _LIMIT)

        assert recovered.stale is False
        assert recovered.releases == _FAKE_RELEASES[:1]

    def test_empty_success_is_never_persisted_or_served_stale(self, github):
        queue, _ = github
        queue += [[], 403]
        assert plugins_catalog._github_releases(_REPO, _LIMIT).releases == []
        assert not plugins_catalog._state_file().exists()

        assert plugins_catalog._github_releases(_REPO, _LIMIT) is None

    def test_empty_file_on_disk_is_ignored(self, github):
        queue, _ = github
        queue.append(403)
        plugins_catalog._state_file().write_text(
            json.dumps({"repo": _REPO, "limit": _LIMIT, "generated_at": "t", "releases": []}),
            encoding="utf-8",
        )
        assert plugins_catalog._github_releases(_REPO, _LIMIT) is None

    @pytest.mark.parametrize(
        "content",
        [
            "{not json",
            json.dumps({"repo": "other/repo", "limit": _LIMIT, "generated_at": "t", "releases": [{"tag_name": "v1.0.0"}]}),
            json.dumps({"repo": _REPO, "limit": 5, "generated_at": "t", "releases": [{"tag_name": "v1.0.0"}]}),
            json.dumps([]),
        ],
        ids=["corrupt", "other-repo", "other-limit", "wrong-shape"],
    )
    def test_unusable_file_on_disk_is_ignored(self, github, content):
        queue, _ = github
        queue.append(403)
        plugins_catalog._state_file().write_text(content, encoding="utf-8")
        assert plugins_catalog._github_releases(_REPO, _LIMIT) is None

    def test_unwritable_state_dir_does_not_break_fetch(self, github, monkeypatch, tmp_path):
        queue, _ = github
        queue.append(_FAKE_RELEASES)
        blocker = tmp_path / "file-not-a-dir"
        blocker.write_text("x")
        monkeypatch.setattr(plugins_catalog, "_state_file", lambda: blocker / plugins_catalog.STATE_FILENAME)

        snapshot = plugins_catalog._github_releases(_REPO, _LIMIT)

        assert snapshot.stale is False
        assert snapshot.releases == _FAKE_RELEASES


class TestGithubToken:
    def test_token_sent_as_bearer_to_releases_api(self, github, monkeypatch):
        queue, sent = github
        queue.append(_FAKE_RELEASES)
        monkeypatch.setattr(plugins_catalog, "GITHUB_TOKEN", "test-token")

        plugins_catalog._github_releases(_REPO, _LIMIT)

        assert sent[0]["Authorization"] == "Bearer test-token"

    def test_no_authorization_header_without_token(self, github):
        queue, sent = github
        queue.append(_FAKE_RELEASES)

        plugins_catalog._github_releases(_REPO, _LIMIT)

        assert "Authorization" not in sent[0]

    def test_token_not_sent_to_raw_plugin_json_host(self, github, monkeypatch):
        queue, sent = github
        queue.append({"displayName": "Apache"})
        monkeypatch.setattr(plugins_catalog, "GITHUB_TOKEN", "test-token")
        plugins_catalog._manifest_cache.clear()

        plugins_catalog._plugin_manifest(_REPO, "tag", "Dir")

        assert "Authorization" not in (sent[0] or {})

    def test_token_not_in_failure_log(self, github, monkeypatch, caplog):
        queue, _ = github
        queue.append(403)
        monkeypatch.setattr(plugins_catalog, "GITHUB_TOKEN", "test-token")

        with caplog.at_level("WARNING"):
            plugins_catalog._github_releases(_REPO, _LIMIT)

        assert "test-token" not in caplog.text


class TestEndpointsWhenGithubFails:
    def test_full_catalog_stays_complete_and_is_marked_stale(self, github, monkeypatch):
        queue, _ = github
        queue += [_FAKE_RELEASES, 403]
        monkeypatch.setattr(plugins_catalog, "_plugin_manifest", lambda *a: {})
        with TestClient(app) as c:
            fresh = c.get("/api/v1/plugins/catalog").json()
            stale = c.get("/api/v1/plugins/catalog")

        assert stale.status_code == 200
        body = stale.json()
        assert fresh["stale"] is False
        assert body["stale"] is True
        assert body["generated_at"] == fresh["generated_at"]
        assert body["plugin_count"] == fresh["plugin_count"] == 5
        assert body["plugins"] == fresh["plugins"]

    def test_fresh_catalog_carries_generated_at(self, stub_releases):
        with TestClient(app) as c:
            body = c.get("/api/v1/plugins/catalog").json()
        assert body["stale"] is False
        assert body["generated_at"] == _FAKE_GENERATED_AT

    def test_single_plugin_marked_stale(self, github, monkeypatch):
        queue, _ = github
        queue += [_FAKE_RELEASES, 502]
        monkeypatch.setattr(plugins_catalog, "_plugin_manifest", lambda *a: {})
        with TestClient(app) as c:
            c.get("/api/v1/plugins/catalog/nks.wdc.apache")
            r = c.get("/api/v1/plugins/catalog/nks.wdc.apache")

        assert r.status_code == 200
        assert r.json()["stale"] is True
        assert r.json()["id"] == "nks.wdc.apache"

    def test_no_copy_means_503_not_an_empty_catalog(self, github):
        queue, _ = github
        queue += [403, 403]
        with TestClient(app) as c:
            full = c.get("/api/v1/plugins/catalog")
            single = c.get("/api/v1/plugins/catalog/nks.wdc.apache")

        for r in (full, single):
            assert r.status_code == 503
            assert r.headers["retry-after"] == "60"
            assert "plugin_count" not in r.text
