"""Shared slowapi Limiter instance — imported by main.py and devices.py.

Keeping the limiter in its own module avoids a circular import between
main.py (which mounts devices_router) and devices.py (which needs
@limiter.limit decorators on /auth endpoints).

Tests set NKS_WDC_DISABLE_RATE_LIMITS=1 so assertions aren't flaky from
per-IP counters bleeding between test functions.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_DISABLED = os.environ.get("NKS_WDC_DISABLE_RATE_LIMITS") == "1"

limiter = Limiter(
    key_func=get_remote_address,
    enabled=not _DISABLED,
    default_limits=[],
)
