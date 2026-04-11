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
DEFAULT_UA = "NKS-WebDevConsole-Catalog/0.1 (+https://github.com/nks-hub/webdev-console)"


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
            releases.append(GenRelease(
                version=tag,
                major_minor=_major_minor(tag),
                released_at=(rel.get("published_at") or "")[:10] or None,
                downloads=downloads,
            ))
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
            releases.append(GenRelease(
                version=tag,
                major_minor=_major_minor(tag),
                released_at=(rel.get("published_at") or "")[:10] or None,
                downloads=downloads,
            ))
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
            releases.append(GenRelease(
                version=tag,
                major_minor=_major_minor(tag),
                released_at=(rel.get("published_at") or "")[:10] or None,
                downloads=downloads,
            ))
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
                downloads.append(GenDownload(url, "windows", "x64", "zip", "github/redis-windows"))
                break
        if downloads:
            releases.append(GenRelease(
                version=tag,
                major_minor=_major_minor(tag),
                released_at=(rel.get("published_at") or "")[:10] or None,
                downloads=downloads,
            ))
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
            r = httpx.get(list_url, timeout=HTTP_TIMEOUT, headers={"User-Agent": DEFAULT_UA})
            r.raise_for_status()
            seen: set[str] = set()
            for m in pattern.finditer(r.text):
                filename, version = m.group(1), m.group(2)
                if version in seen:
                    continue
                seen.add(version)
                download_url = list_url + filename
                releases.append(GenRelease(
                    version=version,
                    major_minor=_major_minor(version),
                    downloads=[GenDownload(download_url, "windows", "x64", "zip", "php.net")],
                ))
                if len(releases) >= limit:
                    break
        except Exception as exc:  # noqa: BLE001
            log.warning("PHP scrape failed for %s: %s", list_url, exc)
    # Sort descending by semver-ish key
    releases.sort(key=lambda r: tuple(int(x) for x in r.version.split(".")), reverse=True)
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
            rel_path, filename, version = m.group(1), m.group(2), m.group(3)
            url = "https://www.apachelounge.com/download/" + rel_path
            releases.append(GenRelease(
                version=version,
                major_minor=_major_minor(version),
                downloads=[GenDownload(url, "windows", "x64", "zip", "apachelounge", {"User-Agent": DEFAULT_UA})],
            ))
            if len(releases) >= limit:
                break
    except Exception as exc:  # noqa: BLE001
        log.warning("Apache scrape failed: %s", exc)
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
            releases.append(GenRelease(
                version=version,
                major_minor=_major_minor(version),
                downloads=[GenDownload(url, "windows", "x64", "zip", "nginx.org")],
            ))
            if len(releases) >= limit:
                break
    except Exception as exc:  # noqa: BLE001
        log.warning("Nginx scrape failed: %s", exc)
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
