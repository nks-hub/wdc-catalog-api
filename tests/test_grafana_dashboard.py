"""Regression tests for `ops/grafana/dashboard.json`.

A corrupt dashboard JSON breaks the Grafana import silently; this
sanity check makes sure the file parses and carries the expected
security panels we ship alongside the metric.
"""

from __future__ import annotations

import json
from pathlib import Path


DASHBOARD_PATH = Path(__file__).parent.parent / "ops" / "grafana" / "dashboard.json"


def test_dashboard_json_parses():
    """File is valid JSON."""
    with DASHBOARD_PATH.open(encoding="utf-8") as fh:
        dashboard = json.load(fh)
    assert isinstance(dashboard, dict)
    assert "panels" in dashboard


def test_dashboard_has_security_section():
    """v0.42.0 panels for nks_wdc_security_events_total are present."""
    with DASHBOARD_PATH.open(encoding="utf-8") as fh:
        dashboard = json.load(fh)

    panels = dashboard["panels"]

    # The row separator with title "Security signals" must exist.
    rows = [p for p in panels if p.get("type") == "row"]
    security_rows = [r for r in rows if r.get("title") == "Security signals"]
    assert security_rows, "missing 'Security signals' row"

    # At least one panel references the security counter.
    security_panel_found = False
    for p in panels:
        for target in p.get("targets", []):
            if "nks_wdc_security_events_total" in target.get("expr", ""):
                security_panel_found = True
                break
        if security_panel_found:
            break
    assert security_panel_found, "no panel references nks_wdc_security_events_total"


def test_every_panel_has_gridpos_and_targets():
    """Every non-row panel has a gridPos + targets list — sanity that
    the Grafana import won't reject the payload."""
    with DASHBOARD_PATH.open(encoding="utf-8") as fh:
        dashboard = json.load(fh)

    for p in dashboard["panels"]:
        assert "gridPos" in p, f"panel {p.get('title')!r} missing gridPos"
        if p.get("type") == "row":
            continue
        assert "targets" in p, f"panel {p.get('title')!r} missing targets"
        assert len(p["targets"]) > 0, f"panel {p.get('title')!r} has empty targets"


def test_grid_positions_are_non_overlapping_within_rows():
    """Simple grid sanity — panels at the same y don't overlap in x."""
    with DASHBOARD_PATH.open(encoding="utf-8") as fh:
        dashboard = json.load(fh)

    # Group panels by y coordinate, skip rows (which span full width).
    by_y: dict[int, list] = {}
    for p in dashboard["panels"]:
        if p.get("type") == "row":
            continue
        y = p["gridPos"]["y"]
        by_y.setdefault(y, []).append(p)

    for y, group in by_y.items():
        spans = sorted(
            (p["gridPos"]["x"], p["gridPos"]["x"] + p["gridPos"]["w"], p["title"])
            for p in group
        )
        for i in range(len(spans) - 1):
            assert spans[i][1] <= spans[i + 1][0], (
                f"panels overlap at y={y}: {spans[i][2]!r} ends at "
                f"{spans[i][1]} but {spans[i + 1][2]!r} starts at "
                f"{spans[i + 1][0]}"
            )
