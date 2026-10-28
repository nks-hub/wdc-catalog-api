"""Plugins catalog — mirror of the binaries catalog (``api_catalog.py``) but
for WDC plugin artifacts published on
https://github.com/nks-hub/webdev-console-plugins.

The JSON contract deliberately parallels the binaries catalog (``app_id``,
``releases[]``, ``downloads[]``) so the C# daemon can reuse the same
``CatalogClient`` fetching / sha256-verification machinery. The key shape
difference: plugin release assets are NOT partitioned by OS/arch (managed
.NET libraries are cross-platform) so every download entry uses
``os="any" arch="any"``. Releases are tagged per plugin
(``<plugin id>-v<semver>``, e.g. ``nks.wdc.deploy.localrsync-v0.1.0``), so
the plugin id comes from the tag prefix; legacy tags without the
``nks.wdc.`` prefix fall back to the asset filename. Every download carries
the sha256 of its zip, and each plugin carries the ``displayName`` and
``description`` from its ``plugin.json`` at the newest tag. When GitHub
fails, the last good response is served with ``"stale": true`` and its
``generated_at`` time instead of an empty catalog.

Endpoint:
    GET /api/v1/plugins/catalog           — full plugins catalog
    GET /api/v1/plugins/catalog/{plugin}  — single plugin detail
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status

from .generators import DEFAULT_UA, GenDownload, GenRelease
from .settings import get_settings

log = logging.getLogger(__name__)

HTTP_TIMEOUT = float(os.environ.get("NKS_WDC_PLUGINS_HTTP_TIMEOUT", "10"))
PLUGINS_REPO = os.environ.get("NKS_WDC_PLUGINS_REPO", "nks-hub/webdev-console-plugins")
# Optional GitHub token for the releases API call (raises the limit from
# 60 to 5000 requests/h). Sent only to api.github.com, never logged.
GITHUB_TOKEN = os.environ.get("NKS_WDC_PLUGINS_GITHUB_TOKEN", "").strip()
# File in the state dir that keeps the last good releases response across restarts.
STATE_FILENAME = "plugins-releases.json"
# In-process TTL for the GitHub releases fetch. Without this every HTTP
# hit to /api/v1/plugins/catalog (and the per-plugin variant) re-queried
# GitHub, which burns the 60-req/h anonymous rate limit on a single
# uvicorn worker under any real load. The Cache-Control header on the
# HTTP response only helps CDN/browser layers, not internal re-fetches.
CACHE_TTL_SECONDS = float(os.environ.get("NKS_WDC_PLUGINS_CACHE_TTL", "60"))
# GitHub's per_page maximum. The repo holds one release per plugin version,
# so anything lower silently drops the plugins that were released least recently.
RELEASES_LIMIT = 100
_IO_WORKERS = 8

_cache_lock = Lock()
# Successful fetches only: (monotonic time, releases, ISO-8601 UTC wall time).
# Entries are kept after the TTL expires so they can be served stale.
_cache: dict[tuple[str, int], tuple[float, list[dict[str, Any]], str]] = {}
# Release assets and tagged plugin.json files never change once published, so
# successful lookups live for the whole process; failures are never stored.
_sha256_cache: dict[tuple[Any, str], str] = {}
_manifest_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins-catalog"])

# Release tag convention: `<plugin id>-v<semver>`, e.g. `nks.wdc.apache-v1.0.17`.
# Pre-release tags are not matched, so they are never offered as "stable".
_TAG_RE = re.compile(r"^(?:(?P<prefix>.+)-)?v(?P<version>\d+\.\d+\.\d+)$")
_TAG_ID_PREFIX = "nks.wdc."

# Plugin asset file-name convention: `NKS.WebDevConsole.Plugin.<Name>.zip`
# (created by the release.yml workflow). The trailing `.zip` plus the
# `NKS.WebDevConsole.Plugin.` prefix are stripped to yield the plugin id
# in canonical lowercase form, e.g. `nks.wdc.apache` ← `...Plugin.Apache.zip`.
_ASSET_RE = re.compile(r"^NKS\.WebDevConsole\.Plugin\.(?P<name>[A-Za-z0-9]+)\.zip$")


@dataclass(frozen=True)
class ReleasesSnapshot:
    releases: list[dict[str, Any]]
    generated_at: str
    stale: bool


def _state_file() -> Path:
    return get_settings().resolved_state_dir / STATE_FILENAME


def _save_snapshot(repo: str, limit: int, generated_at: str, releases: list[dict[str, Any]]) -> None:
    """Persist the last good releases response; best effort, never raises."""
    path = _state_file()
    tmp = path.with_suffix(".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps({"repo": repo, "limit": limit, "generated_at": generated_at, "releases": releases}),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist plugins releases to %s: %s", path, exc)


def _load_snapshot(repo: str, limit: int) -> tuple[str, list[dict[str, Any]]] | None:
    """Read the persisted releases for ``(repo, limit)``; None when absent, foreign or empty."""
    path = _state_file()
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        if saved["repo"] == repo and saved["limit"] == limit and saved["releases"]:
            return saved["generated_at"], saved["releases"]
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        log.warning("ignoring unreadable plugins releases file %s: %s", path, exc)
    return None


def _github_releases(repo: str, limit: int = RELEASES_LIMIT) -> ReleasesSnapshot | None:
    """Fetch the last `limit` releases from a public GitHub repo.

    Shares the DEFAULT_UA + timeout conventions with generators._github_releases
    but is duplicated here to avoid circular imports and to keep plugin
    catalog concerns independent of the binaries generator module.

    Results are memoised in-process for ``CACHE_TTL_SECONDS`` (default 60s)
    keyed by ``(repo, limit)`` so the endpoint does not re-hit GitHub on
    every single request. Set ``CACHE_TTL_SECONDS=0`` to disable.

    When GitHub fails (rate limit, 5xx, network), the last good response is
    returned with ``stale=True``: from memory, else from the state dir file
    that survives restarts. A failure never overwrites either copy, and
    None means GitHub failed and no earlier non-empty copy exists.
    """
    key = (repo, limit)
    now = time.monotonic()
    with _cache_lock:
        entry = _cache.get(key)
    if CACHE_TTL_SECONDS > 0 and entry is not None and (now - entry[0]) < CACHE_TTL_SECONDS:
        return ReleasesSnapshot(entry[1], entry[2], stale=False)

    url = f"https://api.github.com/repos/{repo}/releases?per_page={limit}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_UA,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        r = httpx.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            raise ValueError("releases response is not a list")
    except Exception as exc:  # noqa: BLE001
        log.warning("GitHub plugins-repo fetch failed for %s: %s", repo, exc)
        if entry is not None and entry[1]:
            return ReleasesSnapshot(entry[1], entry[2], stale=True)
        saved = _load_snapshot(repo, limit)
        return ReleasesSnapshot(saved[1], saved[0], stale=True) if saved else None

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _cache_lock:
        _cache[key] = (now, data, generated_at)
    if data:
        _save_snapshot(repo, limit, generated_at, data)
    return ReleasesSnapshot(data, generated_at, stale=False)


def _asset_plugin_id(filename: str) -> str | None:
    """Extract canonical plugin id from a release asset filename.

    ``NKS.WebDevConsole.Plugin.Apache.zip`` → ``nks.wdc.apache``
    Returns None for anything that doesn't match the naming convention.
    """
    m = _ASSET_RE.match(filename)
    if not m:
        return None
    return f"nks.wdc.{m.group('name').lower()}"


@dataclass
class PluginEntry:
    id: str
    name: str
    description: str | None
    releases: list[GenRelease]


def _plugin_assets(rel: dict[str, Any]):
    """Yield ``(plugin_id, version, asset)`` for the plugin zips of one release.

    A ``nks.wdc.*`` tag names exactly one plugin, so only its first zip is
    taken. Any other tag (legacy ``redis-v1.0.3``, bundle ``v0.1.0``) takes
    the id of every zip from its filename. Tags without a plain
    ``major.minor.patch`` version yield nothing.
    """
    m = _TAG_RE.match(rel.get("tag_name") or "")
    if not m:
        return
    prefix = m.group("prefix") or ""
    for asset in rel.get("assets") or []:
        asset_plugin_id = _asset_plugin_id(asset.get("name") or "")
        if asset_plugin_id is None or not asset.get("browser_download_url"):
            continue
        if prefix.startswith(_TAG_ID_PREFIX):
            yield prefix, m.group("version"), asset
            return
        yield asset_plugin_id, m.group("version"), asset


def _asset_sha256(asset: dict[str, Any]) -> str | None:
    """Return the sha256 of a release asset, or None when it cannot be determined.

    Uses the ``digest`` field of the GitHub API when present; otherwise
    downloads the asset and hashes it, remembering the result per asset id
    and ``updated_at`` so a refresh does not download it again.
    """
    digest = asset.get("digest") or ""
    if digest.startswith("sha256:"):
        return digest.removeprefix("sha256:").lower()

    url = asset.get("browser_download_url") or ""
    key = (asset.get("id") or url, asset.get("updated_at") or "")
    with _cache_lock:
        cached = _sha256_cache.get(key)
    if cached:
        return cached

    hasher = hashlib.sha256()
    try:
        with httpx.stream(
            "GET",
            url,
            headers={"User-Agent": DEFAULT_UA},
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
        ) as r:
            r.raise_for_status()
            for chunk in r.iter_bytes():
                hasher.update(chunk)
    except Exception as exc:  # noqa: BLE001
        log.warning("sha256 download failed for %s: %s", url, exc)
        return None

    sha256 = hasher.hexdigest()
    with _cache_lock:
        _sha256_cache[key] = sha256
    return sha256


def _plugin_manifest(repo: str, tag: str, plugin_dir: str) -> dict[str, Any]:
    """Return ``plugin.json`` of ``plugin_dir`` at ``tag``, or ``{}`` when unavailable."""
    key = (repo, tag, plugin_dir)
    with _cache_lock:
        cached = _manifest_cache.get(key)
    if cached is not None:
        return cached

    url = f"https://raw.githubusercontent.com/{repo}/{tag}/{plugin_dir}/plugin.json"
    try:
        r = httpx.get(
            url,
            headers={"User-Agent": DEFAULT_UA},
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
        )
        r.raise_for_status()
        manifest = r.json()
        if not isinstance(manifest, dict):
            raise ValueError("plugin.json is not an object")
    except Exception as exc:  # noqa: BLE001
        log.warning("plugin.json fetch failed for %s: %s", url, exc)
        return {}

    with _cache_lock:
        _manifest_cache[key] = manifest
    return manifest


def _build_release(version: str, rel: dict[str, Any], asset: dict[str, Any]) -> GenRelease:
    return GenRelease(
        version=version,
        major_minor=".".join(version.split(".")[:2]),
        released_at=(rel.get("published_at") or "")[:10] or None,
        downloads=[
            GenDownload(
                url=asset["browser_download_url"],
                os="any",
                arch="any",
                archive_type="zip",
                source="nks-hub-plugins",
                sha256=_asset_sha256(asset),
            )
        ],
    )


@dataclass
class PluginsCatalog:
    plugins: dict[str, PluginEntry]
    generated_at: str
    stale: bool


def generate_plugins(limit: int = RELEASES_LIMIT) -> PluginsCatalog | None:
    """Fetch plugin releases from the plugins repo and group by plugin id.

    ``plugins`` maps ``plugin_id`` to a ``PluginEntry`` where each release has
    exactly one download entry (the .zip for that plugin at that version).
    Releases are ordered newest version first, so ``releases[0]`` is the
    latest. ``name`` and ``description`` come from ``plugin.json`` at the
    newest tag; ``name`` falls back to the plugin directory name and
    ``description`` to None when that file cannot be fetched.

    ``stale`` is True when GitHub failed and the catalog was built from the
    last good response, taken at ``generated_at``. Returns None when GitHub
    failed and there is no earlier response at all.
    """
    snapshot = _github_releases(PLUGINS_REPO, limit=limit)
    if snapshot is None:
        return None
    found: dict[str, list[tuple[str, dict[str, Any], dict[str, Any]]]] = {}
    for rel in snapshot.releases:
        for plugin_id, version, asset in _plugin_assets(rel):
            found.setdefault(plugin_id, []).append((version, rel, asset))
    for items in found.values():
        items.sort(key=lambda it: tuple(map(int, it[0].split("."))), reverse=True)

    def describe(items: list[tuple[str, dict[str, Any], dict[str, Any]]]) -> tuple[str, str | None]:
        _, rel, asset = items[0]
        plugin_dir = asset["name"].removesuffix(".zip")
        manifest = _plugin_manifest(PLUGINS_REPO, rel["tag_name"], plugin_dir)
        return manifest.get("displayName") or plugin_dir.rsplit(".", 1)[-1], manifest.get("description")

    flat = [(plugin_id, *item) for plugin_id, items in found.items() for item in items]
    grouped: dict[str, list[GenRelease]] = {}
    with ThreadPoolExecutor(max_workers=_IO_WORKERS) as pool:
        described = pool.map(describe, found.values())
        built = pool.map(lambda f: _build_release(*f[1:]), flat)
        for (plugin_id, *_), release in zip(flat, built):
            grouped.setdefault(plugin_id, []).append(release)
        plugins = {
            plugin_id: PluginEntry(plugin_id, name, description, grouped[plugin_id])
            for plugin_id, (name, description) in zip(found, described)
        }
    return PluginsCatalog(plugins, snapshot.generated_at, snapshot.stale)


def _current_catalog() -> PluginsCatalog:
    catalog = generate_plugins()
    if catalog is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "plugin catalog unavailable: GitHub did not answer and no earlier copy exists",
            headers={"Retry-After": "60"},
        )
    return catalog


def _plugins_catalog_payload(catalog: PluginsCatalog) -> dict[str, Any]:
    plugins = [asdict(entry) for _, entry in sorted(catalog.plugins.items())]
    return {
        "schema": "wdc-plugins/v1",
        "source": PLUGINS_REPO,
        "generated_at": catalog.generated_at,
        "stale": catalog.stale,
        "plugin_count": len(plugins),
        "plugins": plugins,
    }


@router.get("/catalog")
def api_get_plugins_catalog(request: Request) -> Response:
    payload = _plugins_catalog_payload(_current_catalog())
    return Response(
        content=_json_dumps(payload),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


@router.get("/catalog/{plugin_id}")
def api_get_single_plugin(plugin_id: str, request: Request) -> Response:
    plugin_id = plugin_id.lower()
    catalog = _current_catalog()
    if plugin_id not in catalog.plugins:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "plugin not found")
    payload = {
        **asdict(catalog.plugins[plugin_id]),
        "generated_at": catalog.generated_at,
        "stale": catalog.stale,
    }
    return Response(
        content=_json_dumps(payload),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
