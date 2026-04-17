"""Device-ID normalization + validation.

Extracted into its own module so every route that touches a
``device_id`` path param can share the same regex + error shape without
importing through ``main.py`` (which creates circular-import risks
between main and the JSON-API routers).
"""

from __future__ import annotations

import re

from fastapi import HTTPException, status


# Lowercase alphanumeric + dashes, 3–64 chars starting with
# alphanumeric. Strict shape keeps log-noise + filesystem-traversal
# vectors contained; SQLAlchemy parameterizes the query so the risk is
# cosmetic storage pollution, not injection.
_DEVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")


def normalize_device_id(raw: str) -> str:
    """Lowercase + strip + validate a client-supplied device id.

    Raises HTTP 400 on any format violation so clients see a clear
    error instead of the request silently succeeding with a mangled id.
    """
    normalized = raw.strip().lower()
    if not normalized:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "device_id is required")
    if not _DEVICE_ID_RE.match(normalized):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "device_id must be 3–64 chars, lowercase alphanumeric + dashes",
        )
    return normalized


__all__ = ["normalize_device_id"]
