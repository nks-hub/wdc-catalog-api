"""Daily catalog auto-regenerator.

Runs every generator in ``GENERATORS`` once a day and feeds the output
through ``apply_generated_releases`` so freshly built binaries (e.g. a
new macos-arm64 tarball landed on ``nks-hub/webdev-console-binaries``)
show up in the served catalog without the admin having to click
"Auto-generate" for each app manually.

The job is additive — existing release rows are preserved and only new
``(os, arch)`` pairs are merged in (see ``service.apply_generated_releases``
behavior as of the 2026-04-23 fix). Admin hand-edits to URLs are not
overwritten by the scrape.

Disable by setting ``NKS_WDC_DISABLE_CATALOG_AUTOGEN=1`` in the
container env. The cron is wired into the same APScheduler loop used
by the retention + backup jobs (``app.retention.start_scheduler``).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from .db import session_factory
from .generators import GENERATORS, _generate_from_binaries_repo, run_generator
from .service import apply_generated_releases

log = logging.getLogger(__name__)


@dataclass
class AutogenOutcome:
    app_id: str
    scraped: int
    inserted: int
    error: str | None = None


def run_catalog_autogen(limit_per_app: int = 10) -> list[AutogenOutcome]:
    """Regenerate every app with a registered generator, then layer in
    everything we've built ourselves in ``nks-hub/webdev-console-binaries``.

    Two-pass strategy:
      1. Primary upstream scraper (GENERATORS[app_id]) — fresh versions
         from the canonical source (archive.mariadb.org, apachelounge,
         php.net, etc.).
      2. Binaries-repo fallback — every ``binaries-<app>-<version>`` tag
         we've published, so versions we've source-built but that fell
         off the upstream top-N listing still land in the catalog with
         all their platform assets (macos-arm64, linux-x64, windows-x64).

    ``apply_generated_releases`` merges by ``(os, arch, archive_type)`` so
    the second pass never duplicates existing downloads.

    ``limit_per_app`` caps how many releases each generator walks — higher
    catches older versions that gained a macos/arm64 source-build after
    the fact, lower keeps runtime bounded for rate-limited upstreams.
    Tune via ``NKS_WDC_CATALOG_AUTOGEN_LIMIT``.
    """
    outcomes: list[AutogenOutcome] = []
    # Union of GENERATORS + any app already present in the DB — covers
    # apps like redis/apache that have a binaries-repo release but whose
    # primary generator we skip, plus apps the admin added manually.
    all_apps = set(GENERATORS.keys())
    for app_id in sorted(all_apps):
        try:
            primary: list = []
            try:
                primary = run_generator(app_id, limit=limit_per_app)
            except Exception as exc:  # noqa: BLE001
                log.warning("catalog autogen primary %s failed: %s", app_id, exc)
            # Fallback is always consulted so a broken upstream (rate
            # limit, DNS flap, HTML layout change) can't hide our own
            # published binaries from the catalog.
            fallback = _generate_from_binaries_repo(app_id, limit=100)
            combined = primary + fallback
            with session_factory() as db:
                inserted = apply_generated_releases(db, app_id, combined)
                db.commit()
            outcomes.append(
                AutogenOutcome(app_id=app_id, scraped=len(combined), inserted=inserted)
            )
            log.info(
                "catalog autogen: %s primary=%d binaries-repo=%d inserted=%d",
                app_id,
                len(primary),
                len(fallback),
                inserted,
            )
        except Exception as exc:  # noqa: BLE001 — log + continue, one bad upstream shouldn't halt others
            outcomes.append(
                AutogenOutcome(app_id=app_id, scraped=0, inserted=0, error=str(exc))
            )
            log.warning("catalog autogen: %s failed: %s", app_id, exc)
    return outcomes


def _scheduled_catalog_autogen() -> dict:
    """APScheduler entry-point. Mirrors ``_scheduled_retention`` pattern so
    every log line from the sweep inherits a per-run request ID."""
    import uuid

    try:
        from .observability import request_id_var
    except Exception:
        outcomes = run_catalog_autogen(_limit_from_env())
        return {"runs": [o.__dict__ for o in outcomes]}

    token = request_id_var.set(f"autogen-{uuid.uuid4().hex[:8]}")
    try:
        outcomes = run_catalog_autogen(_limit_from_env())
        return {"runs": [o.__dict__ for o in outcomes]}
    except Exception:
        log.exception("scheduled catalog autogen failed")
        raise
    finally:
        request_id_var.reset(token)


def _limit_from_env() -> int:
    raw = os.environ.get("NKS_WDC_CATALOG_AUTOGEN_LIMIT", "10").strip()
    try:
        val = int(raw)
    except ValueError:
        return 10
    return max(1, min(val, 100))


__all__ = [
    "AutogenOutcome",
    "run_catalog_autogen",
    "_scheduled_catalog_autogen",
]
