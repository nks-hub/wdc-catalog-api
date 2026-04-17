"""Shared slowapi Limiter instance — imported by main.py and devices.py.

Keeping the limiter in its own module avoids a circular import between
main.py (which mounts devices_router) and devices.py (which needs
@limiter.limit decorators on /auth endpoints).

Tests set NKS_WDC_DISABLE_RATE_LIMITS=1 so assertions aren't flaky from
per-IP counters bleeding between test functions.

Set NKS_WDC_RATELIMIT_REDIS=redis://host:6379/0 to share counters across
workers/instances. Without it slowapi uses an in-memory store scoped to a
single process — safe for single-worker deploys, incorrect once you run
multiple workers or replicas.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_DISABLED = os.environ.get("NKS_WDC_DISABLE_RATE_LIMITS") == "1"
_STORAGE_URI = os.environ.get("NKS_WDC_RATELIMIT_REDIS") or "memory://"

limiter = Limiter(
    key_func=get_remote_address,
    enabled=not _DISABLED,
    default_limits=[],
    storage_uri=_STORAGE_URI,
)
