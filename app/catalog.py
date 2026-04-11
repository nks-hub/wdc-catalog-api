"""In-memory catalog loader backed by a directory of per-app JSON files.

Each file under `app/data/apps/*.json` is parsed into an `AppDoc`. The
filename (without extension) is the canonical app id and doubles as the
dictionary key in the served `CatalogDocument`. No database — editing a
JSON file and reloading the process is all that's needed to publish a
new release, which keeps this service deploy-friendly on tiny VPS boxes.

Thread-safety: the loader uses a single mutable dict under a re-entrant
lock. `reload()` swaps the dict atomically after parsing so readers
either see the old catalog or the new one, never a partial merge.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from .schemas import AppDoc, CatalogDocument

log = logging.getLogger(__name__)


class CatalogStore:
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._lock = threading.RLock()
        self._doc = CatalogDocument(schema_version="1", apps={})
        self._last_loaded: datetime | None = None

    @property
    def last_loaded(self) -> datetime | None:
        return self._last_loaded

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    def reload(self) -> int:
        """Rescan `data/apps/*.json` and replace the in-memory catalog.

        Returns the number of apps successfully loaded. Bad files are
        logged and skipped — one broken JSON never kills the whole
        catalog, so a typo in one file doesn't take the service down.
        """
        apps: dict[str, AppDoc] = {}
        if not self._data_dir.is_dir():
            log.warning("Catalog data dir does not exist: %s", self._data_dir)
            with self._lock:
                self._doc = CatalogDocument(schema_version="1", apps=apps)
                self._last_loaded = datetime.now(timezone.utc)
            return 0

        for path in sorted(self._data_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                app = AppDoc.model_validate(raw)
                if not app.name:
                    app.name = path.stem
                apps[app.name] = app
            except Exception as exc:  # noqa: BLE001 — log + continue
                log.error("Failed to parse %s: %s", path, exc)

        with self._lock:
            self._doc = CatalogDocument(
                schema_version="1",
                generated_at=datetime.now(timezone.utc).isoformat(),
                apps=apps,
            )
            self._last_loaded = datetime.now(timezone.utc)
        log.info("Catalog reloaded: %d apps from %s", len(apps), self._data_dir)
        return len(apps)

    def document(self) -> CatalogDocument:
        with self._lock:
            return self._doc

    def app(self, name: str) -> AppDoc | None:
        with self._lock:
            return self._doc.apps.get(name.lower()) or self._doc.apps.get(name)
