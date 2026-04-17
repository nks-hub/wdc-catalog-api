"""Cookie security helpers — shared by ``auth``, ``csrf`` and ``main``.

Extracted from ``main.py`` so cross-cutting modules (CSRF middleware,
session signer) don't need a late-import into the FastAPI entrypoint to
decide if the ``Secure`` flag should be set.
"""

from __future__ import annotations

import os


def cookie_secure() -> bool:
    """Production cookies MUST carry the Secure flag; DEV over http
    would drop them silently."""
    return os.environ.get("NKS_WDC_CATALOG_DEV") != "1"


__all__ = ["cookie_secure"]
