"""Plugins catalog — mirror of the binaries catalog (``api_catalog.py``) but
for WDC plugin artifacts published on
https://github.com/nks-hub/webdev-console-plugins.

The JSON contract deliberately parallels the binaries catalog (``app_id``,
``releases[]``, ``downloads[]``) so the C# daemon can reuse the same
``CatalogClient`` fetching / sha256-verification machinery. The key shape
difference: plugin release assets are NOT partitioned by OS/arch (managed
.NET libraries are cross-platform) so every download entry uses
``os="any" arch="any"``. Each release on the plugins repo bundles ALL
plugins together (one ``.zip`` per plugin), so this generator GROUPS assets
by plugin id derived from the asset filename and emits a per-plugin
release stream.

Endpoint:
    GET /api/v1/plugins/catalog           — full plugins catalog
    GET /api/v1/plugins/catalog/{plugin}  — single plugin detail
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import asdict
from threading import Lock
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status

from .generators import DEFAULT_UA, GenDownload, GenRelease

log = logging.getLogger(__name__)

HTTP_TIMEOUT = float(os.environ.get("NKS_WDC_PLUGINS_HTTP_TIMEOUT", "10"))
PLUGINS_REPO = os.environ.get("NKS_WDC_PLUGINS_REPO", "nks-hub/webdev-console-plugins")
# In-process TTL for the GitHub releases fetch. Without this every HTTP
# hit to /api/v1/plugins/catalog (and the per-plugin variant) re-queried
# GitHub, which burns the 60-req/h anonymous rate limit on a single
# uvicorn worker under any real load. The Cache-Control header on the
# HTTP response only helps CDN/browser layers, not internal re-fetches.
CACHE_TTL_SECONDS = float(os.environ.get("NKS_WDC_PLUGINS_CACHE_TTL", "60"))

_cache_lock = Lock()
_cache: dict[tuple[str, int], tuple[float, list[dict[str, Any]]]] = {}

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins-catalog"])

# Plugin asset file-name convention: `NKS.WebDevConsole.Plugin.<Name>.zip`
# (created by the release.yml workflow). The trailing `.zip` plus the
# `NKS.WebDevConsole.Plugin.` prefix are stripped to yield the plugin id
# in canonical lowercase form, e.g. `nks.wdc.apache` ← `...Plugin.Apache.zip`.
_ASSET_RE = re.compile(r"^NKS\.WebDevConsole\.Plugin\.(?P<name>[A-Za-z0-9]+)\.zip$")


def _github_releases(repo: str, limit: int = 20) -> list[dict[str, Any]]:
    """Fetch the last `limit` releases from a public GitHub repo.

    Shares the DEFAULT_UA + timeout conventions with generators._github_releases
    but is duplicated here to avoid circular imports and to keep plugin
    catalog concerns independent of the binaries generator module.

    Results are memoised in-process for ``CACHE_TTL_SECONDS`` (default 60s)
    keyed by ``(repo, limit)`` so the endpoint does not re-hit GitHub on
    every single request. Set ``CACHE_TTL_SECONDS=0`` to disable.
    """
    key = (repo, limit)
    now = time.monotonic()
    if CACHE_TTL_SECONDS > 0:
        with _cache_lock:
            entry = _cache.get(key)
            if entry is not None and (now - entry[0]) < CACHE_TTL_SECONDS:
                return entry[1]

    url = f"https://api.github.com/repos/{repo}/releases?per_page={limit}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": DEFAULT_UA,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        r = httpx.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("GitHub plugins-repo fetch failed for %s: %s", repo, exc)
        # Don't poison the cache with empty lists — upstream transient
        # failures would otherwise paper over real data for a full TTL.
        return []

    if CACHE_TTL_SECONDS > 0:
        with _cache_lock:
            _cache[key] = (now, data)
    return data


def _asset_plugin_id(filename: str) -> str | None:
    """Extract canonical plugin id from a release asset filename.

    ``NKS.WebDevConsole.Plugin.Apache.zip`` → ``nks.wdc.apache``
    Returns None for anything that doesn't match the naming convention.
    """
    m = _ASSET_RE.match(filename)
    if not m:
        return None
    return f"nks.wdc.{m.group('name').lower()}"


def generate_plugins(limit: int = 20) -> dict[str, list[GenRelease]]:
    """Fetch plugin releases from the plugins repo and group by plugin id.

    Returns a mapping ``{plugin_id: [GenRelease, ...]}`` where each release
    has exactly one download entry (the .zip for that plugin at that
    version). Releases are ordered newest-first as returned by GitHub.
    """
    out: dict[str, list[GenRelease]] = {}
    for rel in _github_releases(PLUGINS_REPO, limit=limit):
        tag = (rel.get("tag_name") or "").lstrip("v")
        if not tag:
            continue
        released_at = (rel.get("published_at") or "")[:10] or None
        for asset in rel.get("assets", []) or []:
            fname = asset.get("name") or ""
            url = asset.get("browser_download_url") or ""
            if not url:
                continue
            plugin_id = _asset_plugin_id(fname)
            if plugin_id is None:
                continue
            dl = GenDownload(
                url=url,
                os="any",
                arch="any",
                archive_type="zip",
                source="nks-hub-plugins",
            )
            out.setdefault(plugin_id, []).append(
                GenRelease(
                    version=tag,
                    major_minor=".".join(tag.split(".")[:2]),
                    released_at=released_at,
                    downloads=[dl],
                )
            )
    return out


def _plugins_catalog_payload() -> dict[str, Any]:
    grouped = generate_plugins()
    plugins = [
        {
            "id": plugin_id,
            "releases": [asdict(r) for r in releases],
        }
        for plugin_id, releases in sorted(grouped.items())
    ]
    return {
        "schema": "wdc-plugins/v1",
        "source": PLUGINS_REPO,
        "plugin_count": len(plugins),
        "plugins": plugins,
    }


@router.get("/catalog")
def api_get_plugins_catalog(request: Request) -> Response:
    payload = _plugins_catalog_payload()
    return Response(
        content=_json_dumps(payload),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


@router.get("/catalog/{plugin_id}")
def api_get_single_plugin(plugin_id: str, request: Request) -> Response:
    plugin_id = plugin_id.lower()
    grouped = generate_plugins()
    if plugin_id not in grouped:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "plugin not found")
    payload = {
        "id": plugin_id,
        "releases": [asdict(r) for r in grouped[plugin_id]],
    }
    return Response(
        content=_json_dumps(payload),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=60"},
    )


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
