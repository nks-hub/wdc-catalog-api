"""Pydantic models for the NKS WDC catalog + config sync API.

The catalog shape is consumed by the C# daemon's `CatalogClient` (see
`src/daemon/NKS.WebDevConsole.Daemon/Binaries/CatalogClient.cs`). DO NOT
change field names here without updating the `CatalogDocument` DTOs in
that file — the daemon serializes with `JsonNamingPolicy.SnakeCaseLower`
so keys must stay snake_case in the wire format. Pydantic handles that
via `alias_generator=to_snake` below.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_snake


class CamelModel(BaseModel):
    """Base with aliases so both snake_case and camelCase are accepted
    on input, while output is always snake_case (matches CatalogClient)."""

    model_config = ConfigDict(
        alias_generator=to_snake,
        populate_by_name=True,
        extra="ignore",
    )


class DownloadDoc(CamelModel):
    """A single binary download: an OS/arch-specific URL + metadata."""

    url: str
    os: str = "windows"
    arch: str = "x64"
    archive_type: str = "zip"
    source: str = "unknown"
    # Optional HTTP headers the downloader must send. Typically only
    # `User-Agent` when the upstream mirror rejects the .NET default.
    headers: Optional[dict[str, str]] = None
    # SHA-256 of the downloaded archive, lowercase hex. Verifier will
    # compare after download; empty string means "skip verification".
    sha256: Optional[str] = None
    # Human-readable file size for UI progress planning (optional).
    size_bytes: Optional[int] = None


class ReleaseDoc(CamelModel):
    """A versioned release with one or more per-platform downloads."""

    version: str
    major_minor: str = ""
    channel: str = "stable"
    released_at: Optional[str] = None
    downloads: list[DownloadDoc] = Field(default_factory=list)


class AppDoc(CamelModel):
    """One application bucket: name, metadata, list of releases."""

    name: str
    display_name: str = ""
    category: str = "other"
    description: str = ""
    homepage: Optional[str] = None
    license: Optional[str] = None
    releases: list[ReleaseDoc] = Field(default_factory=list)


class CatalogDocument(CamelModel):
    """Top-level catalog envelope returned by GET /api/v1/catalog."""

    schema_version: str = "1"
    generated_at: Optional[str] = None
    apps: dict[str, AppDoc] = Field(default_factory=dict)


# ── Config sync ─────────────────────────────────────────────────────────
# Devices push their local configuration snapshots so a fresh WDC install
# can hydrate from the last known good state. Keep it deliberately thin:
# free-form JSON body, server just timestamps + returns it.


class ConfigSyncEntry(CamelModel):
    device_id: str
    updated_at: str
    payload: dict


class ConfigSyncUploadRequest(CamelModel):
    device_id: str
    payload: dict


class ConfigSyncListResponse(CamelModel):
    device_id: str
    updated_at: Optional[str] = None
    has_config: bool = False
