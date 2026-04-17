"""Shared test configuration — ensures isolated DB state."""

import os
import tempfile

# Set ONCE before any app module imports. All test files share this
# same temp directory so the SQLAlchemy engine singleton connects to
# the same SQLite file across the entire test session.
if "NKS_WDC_CATALOG_STATE_DIR" not in os.environ:
    os.environ["NKS_WDC_CATALOG_STATE_DIR"] = tempfile.mkdtemp(prefix="nks-wdc-test-")
    os.environ["NKS_WDC_CATALOG_DEV"] = "1"
    # Rate limits make per-IP tests flaky; opt out by default and re-enable
    # selectively via monkeypatch in dedicated rate-limit regression tests.
    os.environ.setdefault("NKS_WDC_DISABLE_RATE_LIMITS", "1")
