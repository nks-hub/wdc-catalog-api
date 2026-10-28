"""Tests for the catalog-api auto-generators.

Verifies that every registered generator is callable and returns the
expected GenRelease structure. apache and mysql are tested offline against
a fake binaries-repo release listing.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import httpx
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


class Upstream:
    """Offline stand-in for every host the generators talk to.

    A test registers a recorded answer under a URL fragment; the longest
    matching fragment wins. Anything unrecorded fails like a dead network.
    """

    def __init__(self) -> None:
        self.pages: dict[str, object] = {}
        self.head_ok: set[str] = set()
        self.requested: list[str] = []
        self.error: Exception | None = None

    def serve(self, fragment: str, body: object) -> None:
        self.pages[fragment] = body

    def github(self, repo: str, releases: list[dict]) -> None:
        self.serve(f"/repos/{repo}/releases", releases)

    def body(self, url: str) -> object:
        if self.error:
            raise self.error
        self.requested.append(url)
        for fragment in sorted(self.pages, key=len, reverse=True):
            if fragment in url:
                return self.pages[fragment]
        raise httpx.ConnectError(f"no recorded answer for {url}")


class _Page:
    def __init__(self, body: object) -> None:
        self._body = body

    @property
    def text(self) -> str:
        return self._body if isinstance(self._body, str) else json.dumps(self._body)

    def json(self) -> object:
        return self._body

    def raise_for_status(self) -> None:
        pass


def _release(tag: str, *, prerelease: bool = False, draft: bool = False, assets=()) -> dict:
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "published_at": "2026-10-22T09:00:00Z",
        "assets": list(assets),
    }


def _assets(repo: str, tag: str, *names: str) -> list[dict]:
    base = f"https://github.com/{repo}/releases/download/{tag}"
    return [{"name": n, "browser_download_url": f"{base}/{n}"} for n in names]


def _mailpit(tag: str) -> dict:
    names = [f"mailpit-{os_}.{ext}" for os_, ext in [
        ("darwin-amd64", "tar.gz"), ("darwin-arm64", "tar.gz"), ("linux-386", "tar.gz"),
        ("linux-amd64", "tar.gz"), ("linux-arm", "tar.gz"), ("linux-arm64", "tar.gz"),
        ("windows-amd64", "zip"), ("windows-arm64", "zip"),
    ]]
    return _release(tag, assets=_assets("axllent/mailpit", tag, *names))


def _caddy(tag: str, **flags) -> dict:
    v = tag.lstrip("v")
    names = [
        f"caddy_{v}_windows_amd64.zip", f"caddy_{v}_linux_amd64.tar.gz", f"caddy_{v}_linux_arm64.tar.gz",
        f"caddy_{v}_mac_arm64.tar.gz", f"caddy_{v}_mac_amd64.tar.gz", f"caddy_{v}_checksums.txt",
    ]
    return _release(tag, assets=_assets("caddyserver/caddy", tag, *names), **flags)


def _redis(tag: str) -> dict:
    names = [f"Redis-{tag}-Windows-x64-{flavour}.zip" for flavour in (
        "cygwin-with-Service", "cygwin", "msys2-with-Service", "msys2",
    )]
    return _release(tag, assets=_assets("redis-windows/redis-windows", tag, *names))


def _cloudflared(tag: str) -> dict:
    names = [
        "cloudflared-darwin-amd64.tgz", "cloudflared-darwin-arm64.tgz", "cloudflared-linux-386",
        "cloudflared-linux-amd64", "cloudflared-linux-arm64", "cloudflared-windows-386.exe",
        "cloudflared-windows-amd64.exe", "cloudflared-windows-amd64.msi", f"cloudflared_{tag}_amd64.deb",
    ]
    return _release(tag, assets=_assets("cloudflare/cloudflared", tag, *names))


def _mkcert(tag: str) -> dict:
    names = [f"mkcert-{tag}-{suffix}" for suffix in (
        "darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64.exe", "windows-arm64.exe",
    )]
    return _release(tag, assets=_assets("FiloSottile/mkcert", tag, *names))


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

NGINX_DOWNLOAD_PAGE = """
<table>
<tr><td>Mainline version</td></tr>
<tr><td><a href="/download/nginx-1.31.8.tar.gz">nginx-1.31.8</a></td>
    <td><a href="/download/nginx-1.31.8.tar.gz.asc">pgp</a></td>
    <td><a href="/download/nginx-1.31.8.zip">nginx/Windows-1.31.8</a></td>
    <td><a href="/download/nginx-1.31.8.zip.asc">pgp</a></td></tr>
<tr><td>Stable version</td></tr>
<tr><td><a href="/download/nginx-1.30.6.zip">nginx/Windows-1.30.6</a></td></tr>
<tr><td><a href="/download/nginx-1.30.6.zip">nginx/Windows-1.30.6</a></td></tr>
<tr><td>Legacy versions</td></tr>
<tr><td><a href="/download/nginx-1.28.3.zip">nginx/Windows-1.28.3</a></td></tr>
</table>
"""

_NODE_FILES = ["linux-x64", "osx-arm64-tar", "osx-x64-tar", "src", "win-x64-zip"]
NODE_INDEX = [
    {"version": "v26.12.1", "date": "2026-10-21", "files": _NODE_FILES, "lts": False},
    {"version": "v24.11.0", "date": "2026-10-08", "files": _NODE_FILES, "lts": "Krypton"},
    {"version": "v0.1.0", "date": "2011-08-26", "files": ["src"], "lts": False},
    {"version": "v22.15.0", "date": "2026-04-23", "files": _NODE_FILES, "lts": "Jod"},
]

MARIADB_ARCHIVE_PAGE = "".join(
    f'<a href="mariadb-{v}/">mariadb-{v}/</a>\n'
    for v in ("10.0", "10.0.0", "11.8.3", "12.0.2", "13.1.1", "13.1.1")
)

PHP_RELEASES_PAGE = '<a href="php-8.5.9-nts-Win32-vs17-x64.zip">php-8.5.9</a><a href="php-8.4.19-nts-Win32-vs17-x64.zip">php-8.4.19</a>'
PHP_ARCHIVES_PAGE = (
    '<a href="php-8.5.8-nts-Win32-vs17-x64.zip">php-8.5.8</a>'
    '<a href="php-8.4.9-nts-Win32-vs17-x64.zip">php-8.4.9</a>'
    '<a href="php-8.4.19-nts-Win32-vs17-x64.zip">php-8.4.19</a>'
)

BINARIES_REPO = [
    _mirror_release("apache", "2.4.66", {"apache-2.4.66-windows-x64.zip": 12_000_000}),
    _mirror_release("mysql", "9.7.1", {"mysql-9.7.1-windows-x64.zip": 250_000_000}),
    _mirror_release(
        "postgresql",
        "18.3",
        {
            "postgresql-18.3-windows-x64.zip": 300_000_000,
            "postgresql-18.3-linux-x64.tar.gz": 60_000_000,
            "postgresql-18.3-macos-arm64.tar.gz": 55_000_000,
        },
    ),
    _mirror_release(
        "mariadb",
        "11.4.4",
        {"mariadb-11.4.4-linux-x64.tar.gz": 90_000_000, "mariadb-11.4.4-macos-arm64.tar.gz": 85_000_000},
    ),
]


@pytest.fixture
def upstream(monkeypatch) -> Upstream:
    """Every upstream the generators use, preloaded with recorded answers."""
    up = Upstream()
    up.github("axllent/mailpit", [_mailpit("v1.32.0"), _mailpit("v1.31.6"), _mailpit("v1.31.5")])
    up.github(
        "caddyserver/caddy",
        [_caddy("v2.11.7"), _caddy("v2.11.0-beta.2", prerelease=True), _caddy("v2.10.2"), _caddy("v2.8.0-rc.1")],
    )
    up.github("redis-windows/redis-windows", [_redis("8.10.3"), _redis("8.10.2"), _redis("8.8.3")])
    up.github("cloudflare/cloudflared", [_cloudflared("2026.10.5"), _cloudflared("2026.10.4")])
    up.github("FiloSottile/mkcert", [_mkcert("v1.4.4"), _mkcert("v1.4.3")])
    up.github("composer/composer", COMPOSER_RELEASES)
    up.github("nks-hub/webdev-console-binaries", BINARIES_REPO)
    up.serve("nginx.org/en/download.html", NGINX_DOWNLOAD_PAGE)
    up.serve("nodejs.org/dist/index.json", NODE_INDEX)
    up.serve("archive.mariadb.org/", MARIADB_ARCHIVE_PAGE)
    up.serve("windows.php.net/downloads/releases/", PHP_RELEASES_PAGE)
    up.serve("windows.php.net/downloads/releases/archives/", PHP_ARCHIVES_PAGE)
    up.head_ok.update(
        {
            "mariadb-13.1.1-winx64.zip",
            "mariadb-11.8.3-winx64.zip",
            "binaries-mariadb-13.1.1/mariadb-13.1.1-macos-arm64.tar.gz",
        }
    )

    monkeypatch.setattr("app.generators.httpx.get", lambda url, **kw: _Page(up.body(url)))
    monkeypatch.setattr("app.generators._github_json", lambda path: up.body(path))
    monkeypatch.setattr(
        "app.generators.httpx.head",
        lambda url, **kw: SimpleNamespace(status_code=200 if any(f in url for f in up.head_ok) else 404),
    )
    return up


class TestNodeGenerator:
    def test_generate_node_returns_list(self, upstream):
        from app.generators import generate_node

        result = generate_node(limit=3)
        assert [r.version for r in result] == ["26.12.1", "24.11.0", "22.15.0"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")

    def test_generate_node_has_multi_platform(self, upstream):
        from app.generators import generate_node

        downloads = generate_node(limit=1)[0].downloads
        assert {(d.os, d.arch, d.archive_type) for d in downloads} == {
            ("windows", "x64", "zip"),
            ("linux", "x64", "tar.xz"),
            ("macos", "arm64", "tar.gz"),
            ("macos", "x64", "tar.gz"),
        }
        assert downloads[0].url == "https://nodejs.org/dist/v26.12.1/node-v26.12.1-win-x64.zip"

    def test_generate_node_channel_detection(self, upstream):
        from app.generators import generate_node

        channels = {r.version: r.channel for r in generate_node(limit=5)}
        assert channels == {"26.12.1": "stable", "24.11.0": "lts", "22.15.0": "lts"}

    def test_generate_node_skips_releases_without_a_download(self, upstream):
        from app.generators import generate_node

        assert "0.1.0" not in {r.version for r in generate_node(limit=5)}


class TestPHPGenerator:
    def test_generate_php_returns_list(self, upstream):
        from app.generators import generate_php

        result = generate_php(limit=3)
        assert [r.version for r in result] == ["8.5.9", "8.5.8", "8.4.19"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert rel.version
            assert rel.major_minor

    def test_generate_php_major_minor_format(self, upstream):
        from app.generators import generate_php

        for rel in generate_php(limit=5):
            parts = rel.major_minor.split(".")
            assert len(parts) == 2, f"major_minor {rel.major_minor} should be X.Y"

    def test_generate_php_orders_patches_numerically(self, upstream):
        from app.generators import generate_php

        versions = [r.version for r in generate_php(limit=10)]
        assert versions.index("8.4.19") < versions.index("8.4.9")

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
    def test_generate_mariadb_returns_list(self, upstream):
        """generate_mariadb merges 3 sources: archive.mariadb.org (win zip),
        the per-version binaries-repo macOS probe, and a final
        _generate_from_binaries_repo pass that re-adds older versions
        that fell off upstream. Every release's downloads must carry at
        least ONE recognised source string — either `mariadb.org` (win
        zip) or `nks-hub/webdev-console-binaries` (macos-arm64 tarball)."""
        from app.generators import generate_mariadb

        result = generate_mariadb(limit=3)
        assert [r.version for r in result] == ["13.1.1", "11.8.3", "11.4.4"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            sources = {dl.source for dl in rel.downloads}
            assert sources & {"mariadb.org", "nks-hub/webdev-console-binaries"}, f"unexpected sources {sources}"

    def test_generate_mariadb_windows_download_is_zip(self, upstream):
        """The upstream archive.mariadb.org path always returns a Windows
        zip — when that download exists in the merged output, its metadata
        must match (os=windows, arch=x64, archive_type=zip). macOS entries
        from the binaries-repo pass are tar.gz and are intentionally
        skipped here — they're exercised elsewhere."""
        from app.generators import generate_mariadb

        upstream_downloads = [
            dl for rel in generate_mariadb(limit=3) for dl in rel.downloads if dl.source == "mariadb.org"
        ]
        assert len(upstream_downloads) == 2
        for dl in upstream_downloads:
            assert dl.archive_type == "zip"
            assert dl.os == "windows"
            assert dl.arch == "x64"

    def test_generate_mariadb_skips_versions_without_a_windows_build(self, upstream):
        from app.generators import generate_mariadb

        assert "12.0.2" not in {r.version for r in generate_mariadb(limit=10)}

    def test_generate_mariadb_adds_the_macos_arm64_build_when_it_exists(self, upstream):
        from app.generators import generate_mariadb

        by_version = {r.version: {(d.os, d.arch) for d in r.downloads} for r in generate_mariadb(limit=3)}
        assert ("macos", "arm64") in by_version["13.1.1"]
        assert ("macos", "arm64") not in by_version["11.8.3"]


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
    def test_generate_mailpit_returns_list(self, upstream):
        from app.generators import generate_mailpit

        result = generate_mailpit(limit=2)
        assert [r.version for r in result] == ["1.32.0", "1.31.6"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")

    def test_generate_mailpit_picks_the_three_supported_platforms(self, upstream):
        from app.generators import generate_mailpit

        assert {(d.os, d.arch, d.archive_type) for d in generate_mailpit(limit=1)[0].downloads} == {
            ("windows", "x64", "zip"),
            ("linux", "x64", "tar.gz"),
            ("macos", "arm64", "tar.gz"),
        }


class TestCaddyGenerator:
    def test_generate_caddy_returns_list(self, upstream):
        from app.generators import generate_caddy

        result = generate_caddy(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")

    def test_betas_and_rcs_are_not_offered(self, upstream):
        from app.generators import generate_caddy

        assert [r.version for r in generate_caddy(limit=5)] == ["2.11.7", "2.10.2"]

    def test_generate_caddy_picks_the_three_supported_platforms(self, upstream):
        from app.generators import generate_caddy

        assert {(d.os, d.arch, d.archive_type) for d in generate_caddy(limit=1)[0].downloads} == {
            ("windows", "x64", "zip"),
            ("linux", "x64", "tar.gz"),
            ("macos", "arm64", "tar.gz"),
        }


class TestRedisGenerator:
    def test_generate_redis_returns_list(self, upstream):
        from app.generators import generate_redis

        result = generate_redis(limit=2)
        assert [r.version for r in result] == ["8.10.3", "8.10.2"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert not rel.version.startswith("v")

    def test_generate_redis_offers_one_windows_zip_per_release(self, upstream):
        from app.generators import generate_redis

        (dl,) = generate_redis(limit=1)[0].downloads
        assert (dl.os, dl.arch, dl.archive_type) == ("windows", "x64", "zip")
        assert "Windows" in dl.url


class TestNginxGenerator:
    def test_generate_nginx_returns_list(self, upstream):
        from app.generators import generate_nginx

        result = generate_nginx(limit=2)
        assert [r.version for r in result] == ["1.31.8", "1.30.6"]
        for rel in result:
            assert isinstance(rel, GenRelease)
            assert "." in rel.version
            for dl in rel.downloads:
                assert "nginx" in dl.url

    def test_download_links_on_the_page_are_absolute_paths(self, upstream):
        """nginx.org writes ``href="/download/nginx-X.zip"``; a pattern that
        only accepts ``href="nginx-X.zip"`` finds nothing and the scraper
        silently offers no new nginx at all."""
        from app.generators import generate_nginx

        (dl,) = generate_nginx(limit=1)[0].downloads
        assert dl.url == "https://nginx.org/download/nginx-1.31.8.zip"
        assert (dl.os, dl.arch, dl.archive_type) == ("windows", "x64", "zip")

    def test_a_version_listed_twice_is_offered_once(self, upstream):
        from app.generators import generate_nginx

        versions = [r.version for r in generate_nginx(limit=10)]
        assert versions == ["1.31.8", "1.30.6", "1.28.3"]


class TestCloudflaredGenerator:
    def test_generate_cloudflared_has_exe(self, upstream):
        from app.generators import generate_cloudflared

        result = generate_cloudflared(limit=1)
        assert result[0].version == "2026.10.5"
        assert "exe" in {dl.archive_type for dl in result[0].downloads}

    def test_generate_cloudflared_covers_every_supported_platform(self, upstream):
        from app.generators import generate_cloudflared

        assert {(d.os, d.arch, d.archive_type) for d in generate_cloudflared(limit=1)[0].downloads} == {
            ("windows", "x64", "exe"),
            ("windows", "x86", "exe"),
            ("linux", "x64", "bin"),
            ("linux", "arm64", "bin"),
            ("macos", "x64", "tgz"),
            ("macos", "arm64", "tgz"),
        }


class TestMkcertGenerator:
    def test_generate_mkcert_covers_every_platform(self, upstream):
        from app.generators import generate_mkcert

        result = generate_mkcert(limit=2)
        assert [r.version for r in result] == ["1.4.4", "1.4.3"]
        assert {(d.os, d.arch, d.archive_type) for d in result[0].downloads} == {
            ("macos", "x64", "bin"),
            ("macos", "arm64", "bin"),
            ("linux", "x64", "bin"),
            ("linux", "arm64", "bin"),
            ("windows", "x64", "exe"),
            ("windows", "arm64", "exe"),
        }


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
    def test_drops_flagged_tagged_and_draft_releases(self, upstream):
        tags = [r["tag_name"] for r in _github_releases("composer/composer", limit=10)]
        assert tags == ["2.10.1", "2.10.0", "2.9.5", "2.9.0"]

    def test_limit_counts_stable_releases_only(self, upstream):
        tags = [r["tag_name"] for r in _github_releases("composer/composer", limit=2)]
        assert tags == ["2.10.1", "2.10.0"]

    def test_asks_github_for_more_than_limit_so_prereleases_do_not_eat_slots(self, upstream):
        _github_releases("composer/composer", limit=10)
        _github_releases("composer/composer", limit=60)
        assert [u.rsplit("per_page=", 1)[1] for u in upstream.requested] == ["30", "100"]

    def test_upstream_failure_gives_empty_list(self, upstream):
        upstream.error = RuntimeError("simulated network failure")
        assert _github_releases("composer/composer") == []


class TestComposerGenerator:
    _SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

    def test_composer_returns_list(self, upstream):
        result = generate_composer(limit=2)
        assert isinstance(result, list)
        for rel in result:
            assert isinstance(rel, GenRelease)

    def test_composer_semver(self, upstream):
        result = generate_composer(limit=10)
        assert result
        for rel in result:
            assert self._SEMVER.match(rel.version), (
                f"Version {rel.version!r} does not match semver X.Y.Z"
            )

    def test_composer_skips_release_candidates_betas_and_alphas(self, upstream):
        assert [r.version for r in generate_composer(limit=10)] == ["2.10.1", "2.10.0", "2.9.5", "2.9.0"]

    def test_composer_latest_is_newest_stable_even_with_limit_one(self, upstream):
        assert [r.version for r in generate_composer(limit=1)] == ["2.10.1"]

    def test_composer_limit_respected(self, upstream):
        assert len(generate_composer(limit=2)) == 2
        assert len(generate_composer(limit=1)) == 1

    def test_composer_all_three_os(self, upstream):
        os_set = {dl.os for dl in generate_composer(limit=1)[0].downloads}
        assert os_set == {"windows", "linux", "macos"}

    def test_composer_phar_url_pattern(self, upstream):
        for dl in generate_composer(limit=1)[0].downloads:
            assert dl.url == "https://getcomposer.org/download/2.10.1/composer.phar"
            assert dl.archive_type == "phar"
            assert dl.source == "getcomposer.org"

    def test_composer_channel_stable(self, upstream):
        for rel in generate_composer(limit=10):
            assert rel.channel == "stable"

    def test_composer_no_v_prefix(self, upstream):
        for rel in generate_composer(limit=10):
            assert not rel.version.startswith("v"), (
                f"Version {rel.version!r} should not start with 'v'"
            )

    def test_composer_returns_list_on_network_failure(self, upstream):
        upstream.error = RuntimeError("simulated network failure")
        assert run_generator("composer", limit=1) == []


class TestGenReleaseStructure:
    """Every registered generator turns its recorded upstream into valid releases."""

    @pytest.mark.parametrize("app_id", list(GENERATORS.keys()))
    def test_generator_returns_valid_releases(self, upstream, app_id: str):
        releases = run_generator(app_id, limit=2)
        assert releases, f"{app_id}: recorded upstream produced no release"
        for rel in releases:
            assert isinstance(rel, GenRelease)
            assert rel.version and not rel.version.startswith("v")
            assert not is_prerelease_version(rel.version)
            assert rel.downloads, f"{app_id} {rel.version}: no downloads"
            for dl in rel.downloads:
                assert dl.url.startswith("https://")
                assert dl.os in {"windows", "linux", "macos"}
                assert dl.arch in {"x64", "x86", "arm64"}
                assert dl.archive_type and dl.source

    @pytest.mark.parametrize("app_id", list(GENERATORS.keys()))
    def test_generator_survives_a_dead_network(self, upstream, app_id: str):
        upstream.error = RuntimeError("simulated network failure")
        assert isinstance(run_generator(app_id, limit=2), list)


@pytest.mark.integration
class TestGeneratorsLive:
    """Talks to the real upstreams. Skipped unless pytest runs with --run-integration."""

    @pytest.mark.parametrize("app_id", list(GENERATORS.keys()))
    def test_live_generator_offers_only_stable_versions(self, app_id: str):
        releases = run_generator(app_id, limit=2)
        if not releases:
            pytest.skip(f"{app_id}: upstream unreachable or rate limited")
        for rel in releases:
            assert rel.version and not rel.version.startswith("v")
            assert not is_prerelease_version(rel.version), rel.version
            assert rel.downloads
