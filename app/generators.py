"""Upstream URL auto-generators.

Each generator fetches the canonical release listing for one upstream
source and produces a list of `AppDoc` releases ready to import into the
catalog DB. No JSON editing required — click "Auto-generate" in the
admin UI for an app and the service calls the right generator to pull
the latest versions + platform downloads directly from the vendor.

Sources
-------
php           → https://windows.php.net/downloads/releases/   (HTML listing)
apache        → https://www.apachelounge.com/download/        (HTML listing)
mysql         → https://dev.mysql.com/downloads/mysql/        (static versions)
mariadb       → https://archive.mariadb.org                   (static versions)
redis         → github.com/redis-windows/redis-windows        (GitHub releases API)
mailpit       → github.com/axllent/mailpit                    (GitHub releases API)
caddy         → github.com/caddyserver/caddy                  (GitHub releases API)
nginx         → https://nginx.org/en/download.html            (HTML listing)
cloudflared   → github.com/cloudflare/cloudflared             (GitHub releases API)

Every generator is best-effort: upstream changes will break scraping.
Failures log a warning and return an empty list so the UI surfaces
"0 releases found" instead of a 500.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Iterable

import httpx

log = logging.getLogger(__name__)

HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
DEFAULT_UA = (
    "NKS-WebDevConsole-Catalog/0.1 (+https://github.com/nks-hub/webdev-console)"
)


@dataclass
class GenDownload:
    url: str
    os: str = "windows"
    arch: str = "x64"
    archive_type: str = "zip"
    source: str = "auto"
    headers: dict[str, str] | None = None


@dataclass
class GenRelease:
    version: str
    major_minor: str = ""
    channel: str = "stable"
    released_at: str | None = None
    downloads: list[GenDownload] = field(default_factory=list)


# ── GitHub helper ───────────────────────────────────────────────────────


def _github_releases(repo: str, limit: int = 10) -> list[dict]:
    """Fetch the last `limit` releases from a public GitHub repo."""
    url = f"https://api.github.com/repos/{repo}/releases?per_page={limit}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_UA,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        r = httpx.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("GitHub fetch failed for %s: %s", repo, exc)
        return []


def _github_json(path: str) -> list[dict]:
    """Raw GET against api.github.com returning parsed JSON.

    Thin wrapper for endpoints ``_github_releases`` doesn't cover (custom
    query strings, pagination). Raises on non-2xx so callers can
    distinguish "empty list" from "GitHub errored"; use ``try/except`` on
    the call site if a best-effort fallback is acceptable.
    """
    url = f"https://api.github.com{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_UA,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    r = httpx.get(url, headers=headers, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _probe_wdc_binaries_asset(
    app: str, version: str, platform: str, ext: str
) -> str | None:
    """Return a download URL for a platform-specific asset we built in
    nks-hub/webdev-console-binaries, or None if the release/asset is missing.

    MariaDB + MySQL upstream don't publish macOS/arm64 tarballs. Our
    binaries repo has dedicated workflows that build from source on a
    macos-14 runner and attach the tarball to the matching release tag
    (e.g. `binaries-mariadb-11.4.10/mariadb-11.4.10-macos-arm64.tar.gz`).
    Use a HEAD probe so absent assets silently drop out of the catalog —
    matches how _MYSQL_CDN and the MariaDB winx64 probes behave.
    """
    asset = f"{app}-{version}-{platform}.{ext}"
    url = (
        "https://github.com/nks-hub/webdev-console-binaries/"
        f"releases/download/binaries-{app}-{version}/{asset}"
    )
    try:
        head = httpx.head(
            url, timeout=httpx.Timeout(5.0, connect=5.0), follow_redirects=True
        )
        if head.status_code < 400:
            return url
    except Exception:  # noqa: BLE001
        pass
    return None


# Platform triple parser for `<app>-<version>-<os>-<arch>.<ext>` asset names
# in the binaries repo. Recognises every (os, arch) pair our build
# workflows produce plus the archive formats consumed by the daemon's
# BinaryDownloader. Unknown patterns → None so we silently skip anything
# non-canonical (source zips, checksums, sig files).
_BINARIES_ASSET_PATTERN = re.compile(
    r"^[a-z]+-(?P<version>[^-]+)-(?P<os>windows|linux|macos)-(?P<arch>x64|x86|arm64|arm)\.(?P<ext>zip|tar\.gz|tar\.xz|msi|bin|exe)$"
)


def _extract_triple_from_asset_name(name: str) -> tuple[str, str, str] | None:
    m = _BINARIES_ASSET_PATTERN.match(name)
    if not m:
        return None
    return m.group("os"), m.group("arch"), m.group("ext")


def _generate_from_binaries_repo(app: str, limit: int = 100) -> list[GenRelease]:
    """Enumerate every ``binaries-<app>-<version>`` release in
    nks-hub/webdev-console-binaries and convert each matching asset into
    a GenDownload.

    Used as an additive fallback source for apps whose upstream scraper
    misses versions we've built ourselves (e.g. MySQL 9.6.0 landed in
    the binaries repo before Oracle's 9.7 bumped the scraped page, so
    the catalog never saw it). The caller is expected to merge the
    returned releases into whatever the primary scraper already
    produced; ``apply_generated_releases`` handles the merge.
    """
    releases: list[GenRelease] = []
    # /releases returns 30 per page; pagination is optional because each
    # app has fewer than 30 release tags today. Walk pages until exhausted
    # anyway so this keeps working when MariaDB/MySQL get more builds.
    page = 1
    tag_prefix = f"binaries-{app}-"
    while len(releases) < limit:
        try:
            data = _github_json(
                f"/repos/nks-hub/webdev-console-binaries/releases?per_page=100&page={page}"
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("binaries repo scrape failed for %s: %s", app, exc)
            break
        if not isinstance(data, list) or not data:
            break
        for rel in data:
            tag: str = rel.get("tag_name", "")
            if not tag.startswith(tag_prefix):
                continue
            version = tag[len(tag_prefix):]
            downloads: list[GenDownload] = []
            for asset in rel.get("assets", []):
                triple = _extract_triple_from_asset_name(asset.get("name", ""))
                if triple is None:
                    continue
                os_tag, arch_tag, ext = triple
                downloads.append(
                    GenDownload(
                        url=asset.get("browser_download_url", ""),
                        os=os_tag,
                        arch=arch_tag,
                        archive_type=ext,
                        source="nks-hub/webdev-console-binaries",
                    )
                )
            if downloads:
                releases.append(
                    GenRelease(
                        version=version,
                        major_minor=_major_minor(version),
                        downloads=downloads,
                    )
                )
        if len(data) < 100:
            break
        page += 1
    return releases


def _major_minor(version: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


# ── cloudflared ─────────────────────────────────────────────────────────


def generate_cloudflared(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("cloudflare/cloudflared", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        downloads: list[GenDownload] = []
        for asset in rel.get("assets", []):
            name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not url:
                continue
            if name.endswith("-windows-amd64.exe"):
                downloads.append(GenDownload(url, "windows", "x64", "exe", "github"))
            elif name.endswith("-windows-386.exe"):
                downloads.append(GenDownload(url, "windows", "x86", "exe", "github"))
            elif name == "cloudflared-linux-amd64":
                downloads.append(GenDownload(url, "linux", "x64", "bin", "github"))
            elif name == "cloudflared-linux-arm64":
                downloads.append(GenDownload(url, "linux", "arm64", "bin", "github"))
            elif name.endswith("-darwin-amd64.tgz"):
                downloads.append(GenDownload(url, "macos", "x64", "tgz", "github"))
            elif name.endswith("-darwin-arm64.tgz"):
                downloads.append(GenDownload(url, "macos", "arm64", "tgz", "github"))
        if downloads:
            releases.append(
                GenRelease(
                    version=tag,
                    major_minor=_major_minor(tag),
                    released_at=(rel.get("published_at") or "")[:10] or None,
                    downloads=downloads,
                )
            )
    return releases


# ── mailpit ────────────────────────────────────────────────────────────


def generate_mailpit(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("axllent/mailpit", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        downloads: list[GenDownload] = []
        for asset in rel.get("assets", []):
            name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not url:
                continue
            if name == "mailpit-windows-amd64.zip":
                downloads.append(GenDownload(url, "windows", "x64", "zip", "github"))
            elif name == "mailpit-linux-amd64.tar.gz":
                downloads.append(GenDownload(url, "linux", "x64", "tar.gz", "github"))
            elif name == "mailpit-darwin-arm64.tar.gz":
                downloads.append(GenDownload(url, "macos", "arm64", "tar.gz", "github"))
        if downloads:
            releases.append(
                GenRelease(
                    version=tag,
                    major_minor=_major_minor(tag),
                    released_at=(rel.get("published_at") or "")[:10] or None,
                    downloads=downloads,
                )
            )
    return releases


# ── caddy ──────────────────────────────────────────────────────────────


def generate_caddy(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("caddyserver/caddy", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        downloads: list[GenDownload] = []
        for asset in rel.get("assets", []):
            name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not url:
                continue
            if name.endswith("_windows_amd64.zip"):
                downloads.append(GenDownload(url, "windows", "x64", "zip", "github"))
            elif name.endswith("_linux_amd64.tar.gz"):
                downloads.append(GenDownload(url, "linux", "x64", "tar.gz", "github"))
            elif name.endswith("_mac_arm64.tar.gz"):
                downloads.append(GenDownload(url, "macos", "arm64", "tar.gz", "github"))
        if downloads:
            releases.append(
                GenRelease(
                    version=tag,
                    major_minor=_major_minor(tag),
                    released_at=(rel.get("published_at") or "")[:10] or None,
                    downloads=downloads,
                )
            )
    return releases


# ── redis (redis-windows fork) ─────────────────────────────────────────


def generate_redis(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("redis-windows/redis-windows", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        downloads: list[GenDownload] = []
        for asset in rel.get("assets", []):
            name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not name or not url:
                continue
            if "Windows" in name and name.endswith(".zip"):
                downloads.append(
                    GenDownload(url, "windows", "x64", "zip", "github/redis-windows")
                )
                break
        if downloads:
            releases.append(
                GenRelease(
                    version=tag,
                    major_minor=_major_minor(tag),
                    released_at=(rel.get("published_at") or "")[:10] or None,
                    downloads=downloads,
                )
            )
    return releases


# ── PHP (windows.php.net) ───────────────────────────────────────────────

_PHP_ROWS = (
    # (list URL, archive suffix pattern, regex for version extraction)
    (
        "https://windows.php.net/downloads/releases/",
        re.compile(r'href="(php-(\d+\.\d+\.\d+)-nts-Win32-vs\d+-x64\.zip)"'),
    ),
)


def generate_php(limit: int = 10) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for list_url, pattern in _PHP_ROWS:
        try:
            r = httpx.get(
                list_url, timeout=HTTP_TIMEOUT, headers={"User-Agent": DEFAULT_UA}
            )
            r.raise_for_status()
            seen: set[str] = set()
            for m in pattern.finditer(r.text):
                filename, version = m.group(1), m.group(2)
                if version in seen:
                    continue
                seen.add(version)
                download_url = list_url + filename
                releases.append(
                    GenRelease(
                        version=version,
                        major_minor=_major_minor(version),
                        downloads=[
                            GenDownload(
                                download_url, "windows", "x64", "zip", "php.net"
                            )
                        ],
                    )
                )
                if len(releases) >= limit:
                    break
        except Exception as exc:  # noqa: BLE001
            log.warning("PHP scrape failed for %s: %s", list_url, exc)
    # Sort descending by semver-ish key
    releases.sort(
        key=lambda r: tuple(int(x) for x in r.version.split(".")), reverse=True
    )
    return releases[:limit]


# ── Apache (apachelounge.com) ──────────────────────────────────────────

_APACHE_PATTERN = re.compile(
    r'href="(binaries/(httpd-(\d+\.\d+\.\d+)-[\d-]+-win64-VS\d+\.zip))"',
    re.IGNORECASE,
)


def generate_apache(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    try:
        r = httpx.get(
            "https://www.apachelounge.com/download/",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": DEFAULT_UA},
        )
        r.raise_for_status()
        for m in _APACHE_PATTERN.finditer(r.text):
            rel_path, _filename, version = m.group(1), m.group(2), m.group(3)
            url = "https://www.apachelounge.com/download/" + rel_path
            releases.append(
                GenRelease(
                    version=version,
                    major_minor=_major_minor(version),
                    downloads=[
                        GenDownload(
                            url,
                            "windows",
                            "x64",
                            "zip",
                            "apachelounge",
                            {"User-Agent": DEFAULT_UA},
                        )
                    ],
                )
            )
            if len(releases) >= limit:
                break
    except Exception as exc:  # noqa: BLE001
        log.warning("Apache scrape failed: %s", exc)
    return releases


# ── MariaDB (archive.mariadb.org) ──────────────────────────────────────
#
# The archive host serves an Apache-style open directory listing at /.
# We scrape release directories matching `mariadb-X.Y.Z/`, filter to the
# latest `limit` by semver-descending sort, then derive the direct
# Windows zip URL from the known `winx64-packages/{name}.zip` pattern.
# HEAD probe before adding so we never register a release whose
# Windows build is missing upstream.

_MARIADB_RELEASE_PATTERN = re.compile(
    r'href="mariadb-(\d+)\.(\d+)\.(\d+)/"',
    re.IGNORECASE,
)


def generate_mariadb(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    try:
        r = httpx.get(
            "https://archive.mariadb.org/",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": DEFAULT_UA},
        )
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        log.warning("MariaDB scrape failed: %s", exc)
        return releases

    seen: set[tuple[int, int, int]] = set()
    parsed: list[tuple[int, int, int]] = []
    for m in _MARIADB_RELEASE_PATTERN.finditer(r.text):
        triple = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if triple in seen:
            continue
        seen.add(triple)
        parsed.append(triple)

    # Sort descending so we hand the UI the freshest stable builds first.
    parsed.sort(reverse=True)

    for major, minor, patch in parsed:
        if len(releases) >= limit:
            break
        version = f"{major}.{minor}.{patch}"
        url = (
            f"https://archive.mariadb.org/mariadb-{version}/"
            f"winx64-packages/mariadb-{version}-winx64.zip"
        )
        # HEAD probe so we don't register a directory that exists but whose
        # Windows zip wasn't built (pre-10.x alpha betas, arch-only drops).
        try:
            head = httpx.head(url, timeout=httpx.Timeout(5.0, connect=5.0))
            if head.status_code >= 400:
                continue
        except Exception:  # noqa: BLE001
            continue

        downloads = [GenDownload(url, "windows", "x64", "zip", "mariadb.org")]
        # nks-hub/webdev-console-binaries publishes a macOS arm64 source-
        # build when upstream doesn't (archive.mariadb.org has no
        # bintar-osx_arm64 for 11.x+). Probe it so Apple Silicon users
        # get a binary in the catalog.
        macos_url = _probe_wdc_binaries_asset(
            "mariadb", version, "macos-arm64", "tar.gz"
        )
        if macos_url:
            downloads.append(
                GenDownload(
                    macos_url,
                    "macos",
                    "arm64",
                    "tar.gz",
                    "nks-hub/webdev-console-binaries",
                )
            )

        releases.append(
            GenRelease(
                version=version,
                major_minor=_major_minor(version),
                downloads=downloads,
            )
        )

    # Additive: older MariaDB versions still in nks-hub/webdev-console-binaries
    # (e.g. 11.4.4, 11.8.3) drop out of archive.mariadb.org's top-N listing
    # as newer patch releases land, so the primary scrape misses them.
    # Merge the binaries-repo tarballs back in so existing DB entries get
    # their macos-arm64 asset even after they fall off upstream.
    releases.extend(_generate_from_binaries_repo("mariadb", limit=limit))
    return releases


# ── Nginx (nginx.org) ──────────────────────────────────────────────────

_NGINX_PATTERN = re.compile(r'href="(nginx-(\d+\.\d+\.\d+)\.zip)"')


def generate_nginx(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    try:
        r = httpx.get(
            "https://nginx.org/en/download.html",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": DEFAULT_UA},
        )
        r.raise_for_status()
        seen: set[str] = set()
        for m in _NGINX_PATTERN.finditer(r.text):
            filename, version = m.group(1), m.group(2)
            if version in seen:
                continue
            seen.add(version)
            url = f"https://nginx.org/download/{filename}"
            releases.append(
                GenRelease(
                    version=version,
                    major_minor=_major_minor(version),
                    downloads=[GenDownload(url, "windows", "x64", "zip", "nginx.org")],
                )
            )
            if len(releases) >= limit:
                break
    except Exception as exc:  # noqa: BLE001
        log.warning("Nginx scrape failed: %s", exc)
    return releases


# ── MySQL Community Server (dev.mysql.com) ────────────────────────────

_MYSQL_VERSIONS_URL = "https://dev.mysql.com/downloads/mysql/"
_MYSQL_CDN = "https://dev.mysql.com/get/Downloads/MySQL-{mm}/mysql-{ver}-winx64.zip"
_MYSQL_VERSION_PATTERN = re.compile(
    r"MySQL Community Server (\d+)\.(\d+)\.(\d+)"
    r"|mysql-(\d+)\.(\d+)\.(\d+)-winx64\.zip"
)


def generate_mysql(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []

    # Strategy: scrape the downloads page for advertised versions, then
    # construct CDN URLs. MySQL doesn't publish a simple API or GitHub
    # releases, so we parse the human-readable download page.
    try:
        r = httpx.get(
            _MYSQL_VERSIONS_URL,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": DEFAULT_UA},
            follow_redirects=True,
        )
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        log.warning("MySQL scrape failed: %s", exc)
        # Fall back to well-known recent stable versions.
        return _mysql_fallback(limit)

    seen: set[tuple[int, int, int]] = set()
    parsed: list[tuple[int, int, int]] = []
    for m in _MYSQL_VERSION_PATTERN.finditer(r.text):
        groups = m.groups()
        # The regex has two alternatives — pick whichever matched.
        if groups[0] is not None:
            triple = (int(groups[0]), int(groups[1]), int(groups[2]))
        else:
            triple = (int(groups[3]), int(groups[4]), int(groups[5]))
        if triple in seen:
            continue
        seen.add(triple)
        parsed.append(triple)

    parsed.sort(reverse=True)

    for major, minor, patch in parsed:
        if len(releases) >= limit:
            break
        version = f"{major}.{minor}.{patch}"
        mm = f"{major}.{minor}"
        url = _MYSQL_CDN.format(mm=mm, ver=version)

        # HEAD probe to confirm the archive exists (some point releases
        # skip the Windows zip or use a different naming scheme).
        try:
            head = httpx.head(
                url, timeout=httpx.Timeout(5.0, connect=5.0), follow_redirects=True
            )
            if head.status_code >= 400:
                continue
        except Exception:  # noqa: BLE001
            continue

        downloads = [GenDownload(url, "windows", "x64", "zip", "dev.mysql.com")]
        # nks-hub/webdev-console-binaries source-builds MySQL for macOS
        # arm64 (Oracle ships DMG only, no arm64 zip consumable by the
        # daemon's binary downloader). Probe for the tarball so Apple
        # Silicon users see MySQL in the catalog.
        macos_url = _probe_wdc_binaries_asset("mysql", version, "macos-arm64", "tar.gz")
        if macos_url:
            downloads.append(
                GenDownload(
                    macos_url,
                    "macos",
                    "arm64",
                    "tar.gz",
                    "nks-hub/webdev-console-binaries",
                )
            )

        releases.append(
            GenRelease(
                version=version,
                major_minor=mm,
                downloads=downloads,
            )
        )

    if not releases:
        releases = _mysql_fallback(limit)

    # Additive: versions we've source-built in nks-hub/webdev-console-binaries
    # that the upstream scraper didn't surface (e.g. 9.6.0 when dev.mysql.com
    # has already moved on to 9.7). apply_generated_releases merges these
    # by (os, arch) so there's no clash with already-present downloads.
    releases.extend(_generate_from_binaries_repo("mysql", limit=limit))
    return releases


def _mysql_fallback(limit: int) -> list[GenRelease]:
    """Hardcoded recent MySQL versions as a safety net when scraping fails."""
    fallback = [
        ("9.3.0", "9.3"),
        ("9.2.0", "9.2"),
        ("8.4.5", "8.4"),
        ("8.0.42", "8.0"),
    ]
    releases: list[GenRelease] = []
    for ver, mm in fallback[:limit]:
        releases.append(
            GenRelease(
                version=ver,
                major_minor=mm,
                downloads=[
                    GenDownload(
                        _MYSQL_CDN.format(mm=mm, ver=ver),
                        "windows",
                        "x64",
                        "zip",
                        "dev.mysql.com (fallback)",
                    )
                ],
            )
        )
    return releases


# ── Node.js (nodejs.org) ──────────────────────────────────────────────

_NODE_INDEX_URL = "https://nodejs.org/dist/index.json"


def generate_node(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    try:
        r = httpx.get(
            _NODE_INDEX_URL,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": DEFAULT_UA},
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("Node.js fetch failed: %s", exc)
        return releases

    # index.json is sorted newest-first. Each entry has:
    # {"version":"v22.15.0","date":"...","files":["win-x64-zip","linux-x64",...], ...}
    for entry in data:
        if len(releases) >= limit:
            break
        version_raw = entry.get("version", "")
        if not version_raw.startswith("v"):
            continue
        version = version_raw[1:]  # strip leading 'v'
        files = entry.get("files", [])

        downloads: list[GenDownload] = []
        # Windows x64 zip
        if "win-x64-zip" in files:
            downloads.append(
                GenDownload(
                    url=f"https://nodejs.org/dist/{version_raw}/node-{version_raw}-win-x64.zip",
                    os="windows",
                    arch="x64",
                    archive_type="zip",
                    source="nodejs.org",
                )
            )
        # Linux x64 tar.xz
        if "linux-x64" in files:
            downloads.append(
                GenDownload(
                    url=f"https://nodejs.org/dist/{version_raw}/node-{version_raw}-linux-x64.tar.xz",
                    os="linux",
                    arch="x64",
                    archive_type="tar.xz",
                    source="nodejs.org",
                )
            )
        # macOS arm64
        if "osx-arm64-tar" in files:
            downloads.append(
                GenDownload(
                    url=f"https://nodejs.org/dist/{version_raw}/node-{version_raw}-darwin-arm64.tar.gz",
                    os="macos",
                    arch="arm64",
                    archive_type="tar.gz",
                    source="nodejs.org",
                )
            )
        # macOS x64
        if "osx-x64-tar" in files:
            downloads.append(
                GenDownload(
                    url=f"https://nodejs.org/dist/{version_raw}/node-{version_raw}-darwin-x64.tar.gz",
                    os="macos",
                    arch="x64",
                    archive_type="tar.gz",
                    source="nodejs.org",
                )
            )

        if not downloads:
            continue

        # Determine channel: even major = LTS (once it reaches LTS status)
        lts = entry.get("lts")
        channel = "lts" if lts else "stable"

        releases.append(
            GenRelease(
                version=version,
                major_minor=_major_minor(version),
                channel=channel,
                downloads=downloads,
            )
        )

    return releases


# ── composer (getcomposer.org / GitHub) ────────────────────────────────
#
# composer.phar is a PHP archive that runs on every platform identically —
# there are no per-OS or per-arch builds.  We use the GitHub releases API
# (composer/composer) to enumerate tagged versions and derive the canonical
# download URL from getcomposer.org.  A SHA-256 sidecar is available at
# <url>.sha256sum but is not fetched here (the catalog stores the URL, not
# the checksum).  We emit three GenDownload entries per release — one for
# each supported OS — all pointing to the same .phar URL, so the catalog
# can surface the tool regardless of which OS filter the UI applies.


def generate_composer(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("composer/composer", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        phar_url = f"https://getcomposer.org/download/{tag}/composer.phar"
        downloads: list[GenDownload] = [
            GenDownload(phar_url, "windows", "x64", "phar", "getcomposer.org"),
            GenDownload(phar_url, "linux", "x64", "phar", "getcomposer.org"),
            GenDownload(phar_url, "macos", "x64", "phar", "getcomposer.org"),
        ]
        releases.append(
            GenRelease(
                version=tag,
                major_minor=_major_minor(tag),
                channel="stable",
                released_at=(rel.get("published_at") or "")[:10] or None,
                downloads=downloads,
            )
        )
    return releases


# ── mkcert ─────────────────────────────────────────────────────────────
#
# FiloSottile/mkcert publishes its releases on GitHub with one single
# statically-linked binary per OS/arch triplet (no tarball, no archive).
# As of v1.4.4 the asset naming pattern is:
#   mkcert-v1.4.4-linux-amd64
#   mkcert-v1.4.4-linux-arm64
#   mkcert-v1.4.4-darwin-amd64
#   mkcert-v1.4.4-darwin-arm64
#   mkcert-v1.4.4-windows-amd64.exe
#   mkcert-v1.4.4-windows-arm64.exe
#
# WDC's ssl plugin wraps mkcert transparently; adding a generator here
# lets `refresh` pull upstream tags so the catalog can surface newer
# v1.5.x releases once FiloSottile cuts them (binaries-repo mirror via
# build-mkcert.yml PR #17 already covers the same 5 triplets).


def generate_mkcert(limit: int = 5) -> list[GenRelease]:
    releases: list[GenRelease] = []
    for rel in _github_releases("FiloSottile/mkcert", limit=limit):
        tag = rel.get("tag_name", "").lstrip("v")
        if not tag:
            continue
        downloads: list[GenDownload] = []
        for asset in rel.get("assets", []):
            name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not url:
                continue
            # mkcert ships bare binaries — no archive, no extension on
            # Unix. archive_type "bin" mirrors how generate_cloudflared
            # tags its own bare cloudflared binaries.
            if name.endswith("-linux-amd64"):
                downloads.append(GenDownload(url, "linux", "x64", "bin", "github"))
            elif name.endswith("-linux-arm64"):
                downloads.append(GenDownload(url, "linux", "arm64", "bin", "github"))
            elif name.endswith("-darwin-amd64"):
                downloads.append(GenDownload(url, "macos", "x64", "bin", "github"))
            elif name.endswith("-darwin-arm64"):
                downloads.append(GenDownload(url, "macos", "arm64", "bin", "github"))
            elif name.endswith("-windows-amd64.exe"):
                downloads.append(GenDownload(url, "windows", "x64", "exe", "github"))
            elif name.endswith("-windows-arm64.exe"):
                downloads.append(GenDownload(url, "windows", "arm64", "exe", "github"))
        if downloads:
            releases.append(
                GenRelease(
                    version=tag,
                    major_minor=_major_minor(tag),
                    released_at=(rel.get("published_at") or "")[:10] or None,
                    downloads=downloads,
                )
            )
    return releases


# ── Registry ────────────────────────────────────────────────────────────

GENERATORS = {
    "cloudflared": generate_cloudflared,
    "mailpit": generate_mailpit,
    "caddy": generate_caddy,
    "redis": generate_redis,
    "php": generate_php,
    "apache": generate_apache,
    "nginx": generate_nginx,
    "mariadb": generate_mariadb,
    "mysql": generate_mysql,
    "mkcert": generate_mkcert,
    "node": generate_node,
    "composer": generate_composer,
}


def available_generators() -> Iterable[str]:
    return GENERATORS.keys()


def run_generator(app_id: str, limit: int = 5) -> list[GenRelease]:
    gen = GENERATORS.get(app_id.lower())
    if gen is None:
        return []
    try:
        return gen(limit)
    except Exception as exc:  # noqa: BLE001
        log.warning("Generator for %s threw: %s", app_id, exc)
        return []
