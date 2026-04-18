#!/usr/bin/env python3
"""Backfill sha_256 for GitHub-hosted downloads in app/data/apps/*.json.

GitHub's REST API exposes a per-asset `digest: sha256:<hex>` field computed
at upload time and immutable thereafter. The WDC binaries repo already
publishes these hashes for every release asset, but the catalog JSON files
emit `sha_256: null` for them. This one-shot script walks all releases in
`nks-hub/webdev-console-binaries`, pairs each asset URL with matching
download entries across all `app/data/apps/*.json` files, and populates the
`sha_256` field in place.

Usage:
    python scripts/backfill-sha256-from-github.py [--dry-run]

Flags:
    --dry-run   Do not modify files. Report what would change.
    --repo      Override the GitHub repo (default: nks-hub/webdev-console-binaries).
    --apps-dir  Override the apps data directory.
    --limit     Max releases to enumerate (default: 100).

The script is idempotent: downloads whose `sha_256` already matches are
skipped. Non-GitHub URLs (e.g. windows.php.net, archive.mariadb.org) are
left alone.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable

DEFAULT_REPO = "nks-hub/webdev-console-binaries"
GITHUB_RELEASE_PREFIX = f"https://github.com/{DEFAULT_REPO}/releases/download/"


def run_gh(args: list[str]) -> str:
    """Invoke `gh` and return stdout, raising on non-zero exit."""
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed (exit {proc.returncode}):\n{proc.stderr}"
        )
    return proc.stdout


def list_release_tags(repo: str, limit: int) -> list[str]:
    """Return the tag names of every release in the repo."""
    out = run_gh(
        [
            "release",
            "list",
            "-R",
            repo,
            "-L",
            str(limit),
            "--json",
            "tagName",
            "--jq",
            ".[].tagName",
        ]
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def fetch_release_assets(repo: str, tag: str) -> list[dict]:
    """Return list of {name, digest, size} for each asset of a release."""
    out = run_gh(
        [
            "release",
            "view",
            tag,
            "-R",
            repo,
            "--json",
            "assets",
            "--jq",
            ".assets[] | {name, digest, size}",
        ]
    )
    assets: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        assets.append(json.loads(line))
    return assets


def build_digest_map(repo: str, limit: int) -> dict[str, dict]:
    """Map `https://github.com/<repo>/releases/download/<tag>/<name>` -> asset info."""
    tags = list_release_tags(repo, limit)
    print(f"[info] found {len(tags)} releases in {repo}", file=sys.stderr)
    url_to_asset: dict[str, dict] = {}
    for tag in tags:
        try:
            assets = fetch_release_assets(repo, tag)
        except RuntimeError as exc:
            print(f"[warn] skipping {tag}: {exc}", file=sys.stderr)
            continue
        for asset in assets:
            name = asset.get("name")
            digest = asset.get("digest") or ""
            if not name or not digest.startswith("sha256:"):
                continue
            url = f"https://github.com/{repo}/releases/download/{tag}/{name}"
            url_to_asset[url] = {
                "sha_256": digest.removeprefix("sha256:"),
                "size": asset.get("size"),
                "tag": tag,
                "name": name,
            }
    print(
        f"[info] collected {len(url_to_asset)} asset hashes from GitHub",
        file=sys.stderr,
    )
    return url_to_asset


def iter_downloads(doc: dict) -> Iterable[tuple[dict, str]]:
    """Yield (download-dict, url) for each download in the app document."""
    for release in doc.get("releases", []) or []:
        for dl in release.get("downloads", []) or []:
            url = dl.get("url")
            if url:
                yield dl, url


def process_file(
    path: Path, digest_map: dict[str, dict], dry_run: bool
) -> tuple[int, int, int, list[str]]:
    """Return (matched_backfilled, skipped, unmatched, notes) for this file."""
    raw = path.read_text(encoding="utf-8")
    doc = json.loads(raw)

    matched = 0
    skipped = 0
    unmatched = 0
    notes: list[str] = []
    changed = False

    for dl, url in iter_downloads(doc):
        if not url.startswith("https://github.com/"):
            skipped += 1
            continue
        asset = digest_map.get(url)
        if asset is None:
            unmatched += 1
            notes.append(f"  UNMATCHED: {url}")
            continue
        current = dl.get("sha_256")
        expected = asset["sha_256"]
        if current == expected:
            skipped += 1
            continue
        if current and current != expected:
            notes.append(
                f"  OVERWRITE: {url}\n    old={current}\n    new={expected}"
            )
        dl["sha_256"] = expected
        # Backfill size_bytes too if missing — it's essentially free.
        if asset.get("size") and not dl.get("size_bytes"):
            dl["size_bytes"] = asset["size"]
        matched += 1
        changed = True

    if changed and not dry_run:
        # Preserve 2-space indent + trailing newline (matches existing files).
        new_raw = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        path.write_text(new_raw, encoding="utf-8")

    return matched, skipped, unmatched, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not modify files; just print the plan.",
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help=f"GitHub repo (default: {DEFAULT_REPO})",
    )
    parser.add_argument(
        "--apps-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "app" / "data" / "apps",
        help="Directory containing app JSON files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max releases to list from the repo.",
    )
    args = parser.parse_args()

    if not args.apps_dir.is_dir():
        print(f"[error] apps-dir not found: {args.apps_dir}", file=sys.stderr)
        return 2

    print(f"[info] apps-dir: {args.apps_dir}", file=sys.stderr)
    print(f"[info] mode:     {'DRY-RUN' if args.dry_run else 'WRITE'}", file=sys.stderr)

    digest_map = build_digest_map(args.repo, args.limit)
    if not digest_map:
        print("[error] no GitHub asset hashes retrieved; aborting", file=sys.stderr)
        return 1

    total_matched = 0
    total_skipped = 0
    total_unmatched = 0
    per_file: list[tuple[Path, int, int, int, list[str]]] = []

    for path in sorted(args.apps_dir.glob("*.json")):
        matched, skipped, unmatched, notes = process_file(
            path, digest_map, args.dry_run
        )
        total_matched += matched
        total_skipped += skipped
        total_unmatched += unmatched
        per_file.append((path, matched, skipped, unmatched, notes))

    print("")
    print("=== Per-file summary ===")
    for path, matched, skipped, unmatched, notes in per_file:
        print(
            f"  {path.name:<20}  matched={matched:>3}  skipped={skipped:>3}  "
            f"unmatched={unmatched:>3}"
        )
        for note in notes:
            print(note)

    print("")
    print("=== Totals ===")
    print(f"  matched+backfilled : {total_matched}")
    print(f"  skipped            : {total_skipped}  (non-github URL or already set)")
    print(f"  unmatched          : {total_unmatched}  (github URL not found in any release)")
    print(f"  github assets seen : {len(digest_map)}")
    print(f"  mode               : {'DRY-RUN' if args.dry_run else 'WROTE FILES'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
