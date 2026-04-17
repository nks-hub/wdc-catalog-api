"""Smoke test that the OpenAPI export script round-trips cleanly."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_export_script_runs_and_produces_valid_json(tmp_path):
    out = tmp_path / "openapi.json"
    result = subprocess.run(
        [sys.executable, "scripts/export-openapi.py", "-o", str(out), "--pretty"],
        cwd=REPO_ROOT,
        env={
            **__import__("os").environ,
            "NKS_WDC_CATALOG_DEV": "1",
            "NKS_WDC_DISABLE_SCHEDULER": "1",
            "NKS_WDC_DISABLE_RATE_LIMITS": "1",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    spec = json.loads(out.read_text(encoding="utf-8"))
    # Sanity-check a few endpoints that must appear in the contract.
    paths = spec.get("paths", {})
    assert "/api/v1/catalog" in paths
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/devices/{device_id}/backups" in paths
    # A few Pydantic DTOs must show up so client generators have types.
    schemas = spec.get("components", {}).get("schemas", {})
    for name in ("TokenResponse", "ConfigSyncEntry", "AdminUserRow"):
        assert name in schemas, f"Missing schema: {name}"
