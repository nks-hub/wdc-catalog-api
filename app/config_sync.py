"""Per-device config sync storage.

Devices POST their current NKS WDC config snapshot (sites, service
settings, plugin toggles, etc.) keyed by an opaque device id — a random
UUID the Electron client generates on first run and persists in
`~/.wdc/device.id`. The server holds the latest snapshot per device and
returns it verbatim on GET so a fresh install can hydrate state after
re-auth.

Intentionally flat storage: one JSON file per device under
`{state_dir}/configs/{device_id}.json`. That is enough for a personal
sync service — a real multi-tenant deployment would back this with
Postgres or Redis, but that is out of scope here.

Security: there is NO authentication built into this service — it's
designed to sit behind an API gateway / Cloudflare Access that adds
bearer tokens OR to run on localhost. Never expose the bare endpoint to
the internet without a reverse-proxy auth layer.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .schemas import ConfigSyncEntry

log = logging.getLogger(__name__)

# Device IDs must be safe for use as a filename component. Accept UUIDs
# and lowercased alphanumerics + dashes only — enough for real clients,
# small enough to reject `..` traversal without path joining gymnastics.
_DEVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


def _validate_device_id(device_id: str) -> str:
    normalized = device_id.strip().lower()
    if not _DEVICE_ID_RE.match(normalized):
        raise ValueError(
            "device_id must be 3–64 chars, lowercase alphanumeric + dashes",
        )
    return normalized


class ConfigSyncStore:
    def __init__(self, state_dir: Path) -> None:
        self._dir = state_dir / "configs"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _path(self, device_id: str) -> Path:
        return self._dir / f"{_validate_device_id(device_id)}.json"

    def upsert(self, device_id: str, payload: dict) -> ConfigSyncEntry:
        now = datetime.now(timezone.utc).isoformat()
        entry = ConfigSyncEntry(
            device_id=_validate_device_id(device_id),
            updated_at=now,
            payload=payload,
        )
        path = self._path(device_id)
        # Atomic write: tmp + rename so a crash mid-write leaves the
        # previous snapshot intact instead of a truncated JSON file.
        tmp = path.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(
                entry.model_dump_json(indent=2), encoding="utf-8"
            )
            tmp.replace(path)
        log.info("Config sync upsert for %s (%d bytes)", device_id, len(entry.model_dump_json()))
        return entry

    def get(self, device_id: str) -> ConfigSyncEntry | None:
        path = self._path(device_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ConfigSyncEntry.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            log.error("Corrupt config snapshot for %s: %s", device_id, exc)
            return None

    def list_device_ids(self) -> list[str]:
        with self._lock:
            return sorted(p.stem for p in self._dir.glob("*.json"))

    def delete(self, device_id: str) -> bool:
        path = self._path(device_id)
        with self._lock:
            if path.is_file():
                path.unlink()
                return True
            return False
