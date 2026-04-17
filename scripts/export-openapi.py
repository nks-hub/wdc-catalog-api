"""Dump the FastAPI OpenAPI schema to disk.

Used by CI (release workflow) to publish ``openapi.json`` as a release
asset — downstream consumers (the C# daemon's CatalogClient) pin a
specific version and diff-check against it on every build.

Run directly::

    NKS_WDC_CATALOG_DEV=1 python scripts/export-openapi.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("openapi.json"),
        help="Destination file (default: openapi.json in current dir)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON with 2-space indent",
    )
    args = parser.parse_args()

    # Ensure app imports cleanly — the DEV flag unlocks ephemeral
    # secrets so importing doesn't require production env vars.
    os.environ.setdefault("NKS_WDC_CATALOG_DEV", "1")
    os.environ.setdefault("NKS_WDC_DISABLE_SCHEDULER", "1")
    os.environ.setdefault("NKS_WDC_DISABLE_RATE_LIMITS", "1")

    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    from app.main import app

    schema = app.openapi()
    kwargs = {"indent": 2, "sort_keys": True} if args.pretty else {"sort_keys": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(schema, **kwargs) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes, "
          f"{len(schema.get('paths', {}))} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
